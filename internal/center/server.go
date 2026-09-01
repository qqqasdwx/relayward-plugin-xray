package center

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
	"github.com/Relayward/relayward-sdk/contract"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/subscription"
)

var requiredPermissions = []string{
	centerpluginv1.PermissionPortDiagnose,
	centerpluginv1.PermissionNodeConfigure,
	centerpluginv1.PermissionServicesWrite,
}

type Server struct {
	centerpluginv1.UnimplementedCenterPluginServer
	version string
	host    centerpluginv1.PluginHostClient
	mu      sync.Mutex
	active  bool
}

func New(version string, host centerpluginv1.PluginHostClient) *Server {
	return &Server{version: version, host: host}
}

func (server *Server) GetInfo(context.Context, *centerpluginv1.GetInfoRequest) (*centerpluginv1.GetInfoResponse, error) {
	return &centerpluginv1.GetInfoResponse{
		ApiVersion: contract.CenterPluginAPIVersion,
		PluginId:   pluginmeta.ID,
		Version:    server.version,
	}, nil
}

func (server *Server) Activate(_ context.Context, request *centerpluginv1.ActivateRequest) (*centerpluginv1.Activated, error) {
	if err := centerpluginv1.ValidateActivateRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid activation request")
	}
	if len(request.Permissions) != len(requiredPermissions) {
		return nil, status.Error(codes.InvalidArgument, "Xray plugin permissions do not match its manifest")
	}
	for index := range requiredPermissions {
		if request.Permissions[index] != requiredPermissions[index] {
			return nil, status.Error(codes.InvalidArgument, "Xray plugin permissions do not match its manifest")
		}
	}
	server.mu.Lock()
	server.active = true
	server.mu.Unlock()
	return &centerpluginv1.Activated{Permissions: append([]string(nil), requiredPermissions...)}, nil
}

func (server *Server) InvokeUI(ctx context.Context, request *centerpluginv1.InvokeUIRequest) (*centerpluginv1.InvokeUIResponse, error) {
	if err := centerpluginv1.ValidateInvokeUIRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Xray UI request")
	}
	server.mu.Lock()
	active := server.active
	server.mu.Unlock()
	if !active || server.host == nil {
		return nil, status.Error(codes.Unavailable, "Xray plugin is not active")
	}
	var value any
	var err error
	switch request.Method {
	case "service-types.list":
		value = map[string]any{"service_types": config.SupportedServiceTypes()}
	case "configuration.get":
		value, err = server.getConfiguration(ctx, request.Json)
	case "configuration.save":
		value, err = server.saveConfiguration(ctx, request.Json)
	case "diagnostics.get":
		value, err = server.getDiagnostics(ctx, request.Json)
	default:
		return nil, status.Error(codes.Unimplemented, "unsupported Xray UI method")
	}
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode Xray UI response")
	}
	response := &centerpluginv1.InvokeUIResponse{Json: raw}
	if err := centerpluginv1.ValidateInvokeUIResponse(response); err != nil {
		return nil, status.Error(codes.Internal, "Xray UI response is invalid")
	}
	return response, nil
}

type diagnosticsRequest struct {
	NodeID string `json:"node_id"`
}

type portDiagnostic struct {
	ServiceID     string               `json:"service_id"`
	Network       string               `json:"network"`
	LocalPort     uint32               `json:"local_port"`
	ListenAddress string               `json:"listen_address"`
	LocalState    string               `json:"local_state"`
	ObservedAt    int64                `json:"local_observed_at_unix_nano"`
	Endpoints     []endpointDiagnostic `json:"endpoints"`
}

type endpointDiagnostic struct {
	EndpointID   string `json:"endpoint_id"`
	DisplayName  string `json:"display_name"`
	Kind         string `json:"kind"`
	Address      string `json:"address"`
	Port         uint32 `json:"port"`
	Reachability string `json:"reachability"`
	Reason       string `json:"reason"`
}

func (server *Server) getDiagnostics(ctx context.Context, raw []byte) (any, error) {
	var request diagnosticsRequest
	if err := decodeStrict(raw, &request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid network diagnostic request")
	}
	configurationResponse, err := server.host.GetNodePluginConfiguration(ctx,
		&centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID})
	if status.Code(err) == codes.NotFound {
		return map[string]any{"diagnostics": []portDiagnostic{}}, nil
	}
	if err != nil {
		return nil, err
	}
	validationRequest := &centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID}
	if err := centerpluginv1.ValidateNodePluginConfiguration(validationRequest, configurationResponse); err != nil {
		return nil, status.Error(codes.Internal, "Relayward returned invalid Xray configuration state")
	}
	configuration, err := config.Decode(configurationResponse.Json)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Xray configuration is invalid")
	}
	ports := diagnosticPorts(configuration)
	if len(ports) == 0 {
		return map[string]any{"diagnostics": []portDiagnostic{}}, nil
	}
	diagnosticRequest := &centerpluginv1.DiagnoseNodePortsRequest{NodeId: request.NodeID, Ports: ports}
	response, err := server.host.DiagnoseNodePorts(ctx, diagnosticRequest)
	if err != nil {
		return nil, err
	}
	if err := centerpluginv1.ValidateDiagnoseNodePortsResponse(diagnosticRequest, response); err != nil {
		return nil, status.Error(codes.Internal, "Relayward returned invalid network diagnostics")
	}
	result := make([]portDiagnostic, len(response.Diagnostics))
	for index, value := range response.Diagnostics {
		result[index] = portDiagnostic{
			ServiceID: value.ServiceId, Network: value.Network, LocalPort: value.LocalPort,
			ListenAddress: value.ListenAddress, LocalState: localStateName(value.LocalState),
			ObservedAt: value.LocalObservedAtUnixNano, Endpoints: make([]endpointDiagnostic, len(value.Endpoints)),
		}
		for endpointIndex, endpoint := range value.Endpoints {
			result[index].Endpoints[endpointIndex] = endpointDiagnostic{
				EndpointID: endpoint.EndpointId, DisplayName: endpoint.DisplayName, Kind: endpoint.Kind,
				Address: endpoint.Address, Port: endpoint.Port, Reachability: reachabilityName(endpoint.Reachability),
				Reason: probeReasonName(endpoint.Reason),
			}
		}
	}
	return map[string]any{"diagnostics": result}, nil
}

func diagnosticPorts(configuration config.Configuration) []*centerpluginv1.ServicePort {
	result := make([]*centerpluginv1.ServicePort, 0, len(configuration.Services)*2)
	for _, service := range configuration.Services {
		if !service.Enabled {
			continue
		}
		networks := []string{"tcp"}
		if service.Type == config.ServiceTypeShadowsocks && service.Shadowsocks != nil {
			switch service.Shadowsocks.Network {
			case "udp":
				networks = []string{"udp"}
			case "tcp,udp":
				networks = []string{"tcp", "udp"}
			}
		}
		for _, network := range networks {
			result = append(result, &centerpluginv1.ServicePort{
				ServiceId: service.ServiceID, Network: network, Port: uint32(service.Port),
			})
		}
	}
	return result
}

func localStateName(value centerpluginv1.LocalListenerState) string {
	switch value {
	case centerpluginv1.LocalListenerState_LOCAL_LISTENER_STATE_LISTENING:
		return "listening"
	case centerpluginv1.LocalListenerState_LOCAL_LISTENER_STATE_NOT_LISTENING:
		return "not_listening"
	default:
		return "unknown"
	}
}

func reachabilityName(value centerpluginv1.PortReachability) string {
	switch value {
	case centerpluginv1.PortReachability_PORT_REACHABILITY_REACHABLE:
		return "reachable"
	case centerpluginv1.PortReachability_PORT_REACHABILITY_UNREACHABLE:
		return "unreachable"
	default:
		return "not_tested"
	}
}

func probeReasonName(value centerpluginv1.PortProbeReason) string {
	names := map[centerpluginv1.PortProbeReason]string{
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_NODE_OFFLINE:         "node_offline",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_LOCAL_NOT_LISTENING:  "local_not_listening",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_ENDPOINT_UNAVAILABLE: "endpoint_unavailable",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_PROXIED_ENDPOINT:     "proxied_endpoint",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_UNSUPPORTED_NETWORK:  "unsupported_network",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_DNS_FAILED:           "dns_failed",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_CONNECTION_REFUSED:   "connection_refused",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_TIMEOUT:              "timeout",
		centerpluginv1.PortProbeReason_PORT_PROBE_REASON_NETWORK_UNREACHABLE:  "network_unreachable",
	}
	return names[value]
}

type getConfigurationRequest struct {
	NodeID string `json:"node_id"`
}

type saveConfigurationRequest struct {
	NodeID             string                       `json:"node_id"`
	ExpectedGeneration uint64                       `json:"expected_generation"`
	Configuration      config.EditableConfiguration `json:"configuration"`
}

func (server *Server) getConfiguration(ctx context.Context, raw []byte) (any, error) {
	var request getConfigurationRequest
	if err := decodeStrict(raw, &request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration read request")
	}
	response, err := server.host.GetNodePluginConfiguration(ctx, &centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID})
	if status.Code(err) == codes.NotFound {
		return map[string]any{"exists": false, "node_id": request.NodeID}, nil
	}
	if err != nil {
		return nil, err
	}
	validationRequest := &centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID}
	if err := centerpluginv1.ValidateNodePluginConfiguration(validationRequest, response); err != nil {
		return nil, status.Error(codes.Internal, "Relayward returned an invalid Xray configuration")
	}
	configuration, err := config.Decode(response.Json)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Xray configuration is invalid")
	}
	return map[string]any{
		"exists": true, "node_id": request.NodeID, "generation": response.Generation,
		"version": response.Version, "sha256": response.Sha256, "configuration": config.Editable(configuration),
	}, nil
}

func (server *Server) saveConfiguration(ctx context.Context, raw []byte) (any, error) {
	var request saveConfigurationRequest
	if err := decodeStrict(raw, &request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration save request")
	}
	var configuration config.Configuration
	var err error
	if request.ExpectedGeneration == 0 {
		configuration, err = config.NewFromEditable(request.Configuration)
	} else {
		stored, getErr := server.host.GetNodePluginConfiguration(ctx,
			&centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID})
		if getErr != nil {
			return nil, getErr
		}
		validationRequest := &centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeID}
		if centerpluginv1.ValidateNodePluginConfiguration(validationRequest, stored) != nil {
			return nil, status.Error(codes.Internal, "Relayward returned an invalid Xray configuration")
		}
		if stored.Generation != request.ExpectedGeneration {
			return nil, status.Error(codes.Aborted, "Xray configuration generation changed")
		}
		current, decodeErr := config.Decode(stored.Json)
		if decodeErr != nil {
			return nil, status.Error(codes.Internal, "stored Xray configuration is invalid")
		}
		configuration, err = config.MergeEditable(current, request.Configuration)
	}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Xray plugin configuration")
	}
	encoded, err := config.Encode(configuration)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode Xray plugin configuration")
	}
	response, err := server.host.ConfigureNodePlugin(ctx, &centerpluginv1.ConfigureNodePluginRequest{
		NodeId: request.NodeID, ExpectedGeneration: request.ExpectedGeneration,
		Json: encoded,
	})
	if err != nil {
		return nil, err
	}
	validationRequest := &centerpluginv1.ConfigureNodePluginRequest{
		NodeId: request.NodeID, ExpectedGeneration: request.ExpectedGeneration, Json: encoded,
	}
	if err := centerpluginv1.ValidateNodePluginConfigured(validationRequest, response); err != nil {
		return nil, status.Error(codes.Internal, "Relayward returned invalid configured state")
	}
	if err := server.replaceServices(ctx, request.NodeID, configuration, response.Sha256); err != nil {
		return nil, err
	}
	return map[string]any{"generation": response.Generation, "sha256": response.Sha256}, nil
}

func (server *Server) replaceServices(ctx context.Context, nodeID string, configuration config.Configuration, digest string) error {
	services := make([]*centerpluginv1.PluginService, len(configuration.Services))
	for index, service := range configuration.Services {
		services[index] = &centerpluginv1.PluginService{
			Id: service.ServiceID, DisplayName: service.DisplayName,
			Enabled: service.Enabled, Capabilities: []string{"subscription.render"},
			SubscriptionSha256: digest,
		}
	}
	request := &centerpluginv1.ReplaceServicesRequest{
		NodeId:   nodeID,
		Services: services,
	}
	response, err := server.host.ReplaceServices(ctx, request)
	if err != nil {
		return err
	}
	if err := centerpluginv1.ValidateServicesReplaced(request, response); err != nil {
		return status.Error(codes.Internal, "Relayward returned invalid Xray service state")
	}
	return nil
}

func (server *Server) RenderSubscription(ctx context.Context, request *centerpluginv1.RenderSubscriptionRequest) (*centerpluginv1.RenderSubscriptionResponse, error) {
	if err := centerpluginv1.ValidateRenderSubscriptionRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Xray subscription request")
	}
	server.mu.Lock()
	active := server.active
	server.mu.Unlock()
	if !active || server.host == nil {
		return nil, status.Error(codes.Unavailable, "Xray plugin is not active")
	}
	configurationResponse, err := server.host.GetNodePluginConfiguration(ctx,
		&centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeId})
	if err != nil {
		return nil, err
	}
	validationRequest := &centerpluginv1.GetNodePluginConfigurationRequest{NodeId: request.NodeId}
	if err := centerpluginv1.ValidateNodePluginConfiguration(validationRequest, configurationResponse); err != nil {
		return nil, status.Error(codes.Internal, "Relayward returned invalid Xray configuration state")
	}
	configuration, err := config.Decode(configurationResponse.Json)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored Xray configuration is invalid")
	}
	response, err := subscription.Render(configuration, request)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return response, nil
}

func decodeStrict(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func (server *Server) GetStatus(context.Context, *centerpluginv1.GetStatusRequest) (*centerpluginv1.GetStatusResponse, error) {
	server.mu.Lock()
	active := server.active
	server.mu.Unlock()
	health := centerpluginv1.Health_HEALTH_STARTING
	if active {
		health = centerpluginv1.Health_HEALTH_HEALTHY
	}
	return &centerpluginv1.GetStatusResponse{Health: health}, nil
}
