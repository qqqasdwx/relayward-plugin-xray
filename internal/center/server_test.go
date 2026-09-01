package center

import (
	"context"
	"encoding/json"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
	"github.com/Relayward/relayward-sdk/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
)

func TestServerLifecycle(t *testing.T) {
	t.Parallel()
	server := New("0.1.0", &hostStub{})
	info, err := server.GetInfo(context.Background(), &centerpluginv1.GetInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if info.ApiVersion != contract.CenterPluginAPIVersion || info.PluginId != pluginmeta.ID || info.Version != "0.1.0" {
		t.Fatalf("GetInfo() = %+v", info)
	}
	before, err := server.GetStatus(context.Background(), &centerpluginv1.GetStatusRequest{})
	if err != nil || before.Health != centerpluginv1.Health_HEALTH_STARTING {
		t.Fatalf("GetStatus() before activation = %+v, %v", before, err)
	}
	activation := &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}
	activated, err := server.Activate(context.Background(), activation)
	if err != nil {
		t.Fatal(err)
	}
	if err := centerpluginv1.ValidateActivated(activation, activated); err != nil {
		t.Fatalf("ValidateActivated() error = %v", err)
	}
	after, err := server.GetStatus(context.Background(), &centerpluginv1.GetStatusRequest{})
	if err != nil || after.Health != centerpluginv1.Health_HEALTH_HEALTHY {
		t.Fatalf("GetStatus() after activation = %+v, %v", after, err)
	}
}

func TestServerRejectsPermissions(t *testing.T) {
	t.Parallel()
	_, err := New("0.1.0", &hostStub{}).Activate(context.Background(), &centerpluginv1.ActivateRequest{Permissions: []string{centerpluginv1.PermissionNodesRead}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Activate() code = %v, want InvalidArgument", status.Code(err))
	}
}

type hostStub struct {
	centerpluginv1.PluginHostClient
	configuration     *centerpluginv1.NodePluginConfiguration
	configured        *centerpluginv1.ConfigureNodePluginRequest
	services          *centerpluginv1.ReplaceServicesRequest
	diagnosticRequest *centerpluginv1.DiagnoseNodePortsRequest
	diagnostics       *centerpluginv1.DiagnoseNodePortsResponse
}

func (host *hostStub) DiagnoseNodePorts(_ context.Context, request *centerpluginv1.DiagnoseNodePortsRequest,
	_ ...grpc.CallOption,
) (*centerpluginv1.DiagnoseNodePortsResponse, error) {
	host.diagnosticRequest = request
	return host.diagnostics, nil
}

func (host *hostStub) ReplaceServices(_ context.Context, request *centerpluginv1.ReplaceServicesRequest,
	_ ...grpc.CallOption,
) (*centerpluginv1.ServicesReplaced, error) {
	host.services = request
	return &centerpluginv1.ServicesReplaced{ServiceCount: uint32(len(request.Services))}, nil
}

func (host *hostStub) GetNodePluginConfiguration(context.Context, *centerpluginv1.GetNodePluginConfigurationRequest,
	...grpc.CallOption,
) (*centerpluginv1.NodePluginConfiguration, error) {
	if host.configuration == nil {
		return nil, status.Error(codes.NotFound, "missing")
	}
	return host.configuration, nil
}

func (host *hostStub) ConfigureNodePlugin(_ context.Context, request *centerpluginv1.ConfigureNodePluginRequest,
	_ ...grpc.CallOption,
) (*centerpluginv1.NodePluginConfigured, error) {
	host.configured = request
	digest, err := agentv1.PluginConfigurationDigest(request.Json)
	if err != nil {
		return nil, err
	}
	host.configuration = &centerpluginv1.NodePluginConfiguration{
		Generation: request.ExpectedGeneration + 1, Version: "0.1.0", Sha256: digest,
		Json: append([]byte(nil), request.Json...),
	}
	return &centerpluginv1.NodePluginConfigured{Generation: request.ExpectedGeneration + 1, Sha256: digest}, nil
}

func TestInvokeUIReadsAndSavesNodeConfiguration(t *testing.T) {
	host := &hostStub{}
	server := New("0.1.0", host)
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	serviceTypes, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "service-types.list", Json: []byte(`{}`)})
	if err != nil || !json.Valid(serviceTypes.GetJson()) ||
		!jsonContainsValue(serviceTypes.GetJson(), config.ServiceTypeVLESSReality) {
		t.Fatalf("service-types.list = %s, %v", serviceTypes.GetJson(), err)
	}
	nodeID := "10000000-0000-4000-8000-000000000001"
	fullConfiguration, err := config.Decode(testConfigurationJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	configuration := config.Editable(fullConfiguration)
	missingRequest := []byte(`{"node_id":"` + nodeID + `"}`)
	missing, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.get", Json: missingRequest})
	if err != nil || string(missing.Json) != `{"exists":false,"node_id":"`+nodeID+`"}` {
		t.Fatalf("configuration.get missing = %s, %v", missing.GetJson(), err)
	}
	saveRequest, err := json.Marshal(saveConfigurationRequest{
		NodeID: nodeID, ExpectedGeneration: 0, Configuration: configuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: saveRequest})
	if err != nil || host.configured == nil || host.services == nil || !json.Valid(saved.GetJson()) {
		t.Fatalf("configuration.save = %s, captured %+v, %v", saved.GetJson(), host.configured, err)
	}
	storedConfiguration, err := config.Decode(host.configured.Json)
	if err != nil || storedConfiguration.CredentialSeed == "" || len(storedConfiguration.Services) != 2 ||
		storedConfiguration.Services[0].VLESSReality.PrivateKey == "" || len(host.services.Services) != 2 ||
		len(storedConfiguration.Routing.Rules) != 1 || storedConfiguration.Routing.Rules[0].RuleID != "block-private" ||
		!storedConfiguration.DNS.Enabled || len(storedConfiguration.DNS.Servers) != 1 {
		t.Fatalf("stored configuration = %+v, %v", storedConfiguration, err)
	}
	loaded, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.get", Json: missingRequest})
	if err != nil || !json.Valid(loaded.GetJson()) || jsonContainsKey(loaded.Json, "credential_seed") ||
		jsonContainsKey(loaded.Json, "private_key") || jsonContainsKey(loaded.Json, "public_key") ||
		jsonContainsKey(loaded.Json, "short_ids") || jsonContainsNull(loaded.Json) {
		t.Fatalf("configuration.get = %s, %v", loaded.GetJson(), err)
	}
	configuration.Services[0].DisplayName = "Updated VLESS"
	updateRequest, err := json.Marshal(saveConfigurationRequest{
		NodeID: nodeID, ExpectedGeneration: 1, Configuration: configuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: updateRequest}); err != nil {
		t.Fatal(err)
	}
	updated, err := config.Decode(host.configured.Json)
	if err != nil || updated.CredentialSeed != storedConfiguration.CredentialSeed ||
		updated.Services[0].VLESSReality.PrivateKey != storedConfiguration.Services[0].VLESSReality.PrivateKey ||
		updated.Services[1].VLESSReality.PrivateKey != storedConfiguration.Services[1].VLESSReality.PrivateKey ||
		updated.Services[0].DisplayName != "Updated VLESS" {
		t.Fatalf("updated configuration = %+v, %v", updated, err)
	}
}

func jsonContainsValue(raw []byte, expected string) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var contains func(any) bool
	contains = func(candidate any) bool {
		switch typed := candidate.(type) {
		case string:
			return typed == expected
		case map[string]any:
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}

func jsonContainsKey(raw []byte, key string) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var contains func(any) bool
	contains = func(candidate any) bool {
		switch typed := candidate.(type) {
		case map[string]any:
			if _, exists := typed[key]; exists {
				return true
			}
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}

func jsonContainsNull(raw []byte) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	var contains func(any) bool
	contains = func(candidate any) bool {
		switch typed := candidate.(type) {
		case nil:
			return true
		case map[string]any:
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if contains(child) {
					return true
				}
			}
		}
		return false
	}
	return contains(value)
}

func TestRenderSubscription(t *testing.T) {
	t.Parallel()
	configuration := testConfigurationJSON(t)
	digest, err := agentv1.PluginConfigurationDigest(configuration)
	if err != nil {
		t.Fatal(err)
	}
	host := &hostStub{configuration: &centerpluginv1.NodePluginConfiguration{
		Generation: 1, Version: "0.1.0", Sha256: digest, Json: configuration,
	}}
	server := New("0.1.0", host)
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
			EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat", Address: "edge.example.com",
		}},
		Services: []*centerpluginv1.SubscriptionServiceBinding{
			{ServiceId: "reality-backup", DisplayName: "Edge Backup"},
			{ServiceId: "reality-main", DisplayName: "Edge Main"},
		},
	}
	response, err := server.RenderSubscription(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := centerpluginv1.ValidateRenderSubscriptionResponse(request, response); err != nil {
		t.Fatal(err)
	}
}

func TestInvokeUIDiagnosesConfiguredPorts(t *testing.T) {
	configuration := testConfigurationJSON(t)
	digest, err := agentv1.PluginConfigurationDigest(configuration)
	if err != nil {
		t.Fatal(err)
	}
	host := &hostStub{
		configuration: &centerpluginv1.NodePluginConfiguration{
			Generation: 1, Version: "0.1.0", Sha256: digest, Json: configuration,
		},
		diagnostics: &centerpluginv1.DiagnoseNodePortsResponse{Diagnostics: []*centerpluginv1.ServicePortDiagnostic{
			{ServiceId: "reality-backup", Network: "tcp", LocalPort: 8443,
				ListenAddress: "0.0.0.0", LocalState: centerpluginv1.LocalListenerState_LOCAL_LISTENER_STATE_LISTENING,
				LocalObservedAtUnixNano: 1},
			{ServiceId: "reality-main", Network: "tcp", LocalPort: 443,
				ListenAddress: "0.0.0.0", LocalState: centerpluginv1.LocalListenerState_LOCAL_LISTENER_STATE_LISTENING,
				LocalObservedAtUnixNano: 1},
		}},
	}
	server := New("0.1.0", host)
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	nodeID := "20000000-0000-4000-8000-000000000002"
	response, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{
		Method: "diagnostics.get", Json: []byte(`{"node_id":"` + nodeID + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.diagnosticRequest == nil || len(host.diagnosticRequest.Ports) != 2 ||
		host.diagnosticRequest.Ports[0].ServiceId != "reality-backup" ||
		!jsonContainsValue(response.Json, "listening") {
		t.Fatalf("diagnostics request = %+v, response = %s", host.diagnosticRequest, response.Json)
	}
}

func testConfigurationJSON(t *testing.T) json.RawMessage {
	t.Helper()
	value, err := config.NewConfiguration("26.7.28", 10085, []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "0.0.0.0", Port: 443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.microsoft.com:443"},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "0.0.0.0", Port: 8443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.cloudflare.com:443"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	value.Routing = config.RoutingConfiguration{Rules: []config.RoutingRule{{
		RuleID: "block-private", DisplayName: "Block private", Enabled: true,
		DestinationIPs: []string{"192.0.2.0/24"}, OutboundTag: config.RoutingOutboundBlocked,
	}}}
	value.DNS = config.DNSConfiguration{
		Enabled: true, QueryStrategy: config.DNSQueryStrategyUseIPv4,
		Servers: []config.DNSServer{{
			ServerID: "system", DisplayName: "System DNS", Enabled: true, Transport: config.DNSTransportSystem,
		}},
	}
	raw, err := config.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
