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
