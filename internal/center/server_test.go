package center

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
	"github.com/Relayward/relayward-sdk/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayrelease"
)

type releaseStub struct {
	versions []xrayrelease.Version
	calls    int
}

func (stub *releaseStub) ListVersions(context.Context) ([]xrayrelease.Version, error) {
	stub.calls++
	return append([]xrayrelease.Version(nil), stub.versions...), nil
}

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
	configuration      *centerpluginv1.NodePluginConfiguration
	configured         *centerpluginv1.ConfigureNodePluginRequest
	services           *centerpluginv1.ReplaceServicesRequest
	diagnosticRequest  *centerpluginv1.DiagnoseNodePortsRequest
	diagnostics        *centerpluginv1.DiagnoseNodePortsResponse
	authorizations     *centerpluginv1.ListNodeAuthorizationsResponse
	nodeDiagnostic     *centerpluginv1.DiagnoseNodePluginResponse
	nodeDiagnosticReq  *centerpluginv1.DiagnoseNodePluginRequest
	configureCalls     int
	replaceCalls       int
	replaceServicesErr error
}

func (host *hostStub) ListNodeAuthorizations(_ context.Context, _ *centerpluginv1.ListNodeAuthorizationsRequest,
	_ ...grpc.CallOption,
) (*centerpluginv1.ListNodeAuthorizationsResponse, error) {
	return host.authorizations, nil
}

func (host *hostStub) DiagnoseNodePlugin(_ context.Context, request *centerpluginv1.DiagnoseNodePluginRequest,
	_ ...grpc.CallOption,
) (*centerpluginv1.DiagnoseNodePluginResponse, error) {
	host.nodeDiagnosticReq = request
	return host.nodeDiagnostic, nil
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
	host.replaceCalls++
	host.services = request
	if host.replaceServicesErr != nil {
		err := host.replaceServicesErr
		host.replaceServicesErr = nil
		return nil, err
	}
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
	host.configureCalls++
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
		len(storedConfiguration.AccessRules) != 1 || storedConfiguration.AccessRules[0].RuleID != "block-private" ||
		len(storedConfiguration.EgressLines) != 1 || storedConfiguration.EgressLines[0].LineID != config.DefaultEgressLineID {
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

func TestConfigurationSaveRetryRepairsServicesWithoutAdvancingGeneration(t *testing.T) {
	host := &hostStub{replaceServicesErr: status.Error(codes.Internal, "temporary service catalog failure")}
	server := New("0.1.0", host)
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	fullConfiguration, err := config.Decode(testConfigurationJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(saveConfigurationRequest{
		NodeID: "10000000-0000-4000-8000-000000000001", Configuration: config.Editable(fullConfiguration),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: request}); status.Code(err) != codes.Internal {
		t.Fatalf("first configuration.save code = %v", status.Code(err))
	}
	if host.configuration == nil || host.configuration.Generation != 1 || host.configureCalls != 1 || host.replaceCalls != 1 {
		t.Fatalf("first save host state = %+v, configure calls = %d, replace calls = %d", host.configuration, host.configureCalls, host.replaceCalls)
	}
	retried, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: request})
	if err != nil {
		t.Fatalf("retried configuration.save error = %v", err)
	}
	var retriedValue map[string]any
	decodeErr := json.Unmarshal(retried.GetJson(), &retriedValue)
	if decodeErr != nil || retriedValue["generation"] != float64(1) {
		t.Fatalf("retried configuration.save = %s, %v", retried.GetJson(), decodeErr)
	}
	if host.configureCalls != 1 || host.replaceCalls != 2 {
		t.Fatalf("retry configure calls = %d, replace calls = %d", host.configureCalls, host.replaceCalls)
	}

	updated := config.Editable(fullConfiguration)
	updated.Services[0].DisplayName = "Updated VLESS"
	updateRequest, err := json.Marshal(saveConfigurationRequest{
		NodeID: "10000000-0000-4000-8000-000000000001", ExpectedGeneration: 1, Configuration: updated,
	})
	if err != nil {
		t.Fatal(err)
	}
	host.replaceServicesErr = status.Error(codes.Internal, "temporary service catalog failure")
	if _, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: updateRequest}); status.Code(err) != codes.Internal {
		t.Fatalf("first updated configuration.save code = %v", status.Code(err))
	}
	if host.configuration.Generation != 2 || host.configureCalls != 2 || host.replaceCalls != 3 {
		t.Fatalf("updated save host state = %+v, configure calls = %d, replace calls = %d", host.configuration, host.configureCalls, host.replaceCalls)
	}
	if _, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "configuration.save", Json: updateRequest}); err != nil {
		t.Fatalf("retried updated configuration.save error = %v", err)
	}
	if host.configureCalls != 2 || host.replaceCalls != 4 {
		t.Fatalf("updated retry configure calls = %d, replace calls = %d", host.configureCalls, host.replaceCalls)
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
			{ServiceId: "reality-backup", Network: "tcp", LocalPort: 28443,
				ListenAddress: "0.0.0.0", LocalState: centerpluginv1.LocalListenerState_LOCAL_LISTENER_STATE_LISTENING,
				LocalObservedAtUnixNano: 1},
			{ServiceId: "reality-main", Network: "tcp", LocalPort: 24443,
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

func TestDiagnosticPortsCoverMaximumShadowsocksServices(t *testing.T) {
	configuration := config.Configuration{Services: make([]config.Service, config.MaximumServices)}
	for index := range configuration.Services {
		configuration.Services[index] = config.Service{
			Type: config.ServiceTypeShadowsocks, Enabled: true,
			ServiceID: fmt.Sprintf("shadowsocks-%02d", index), Port: uint16(20000 + index),
			Shadowsocks: &config.Shadowsocks{Method: config.ShadowsocksMethod2022AES256},
		}
	}
	ports := diagnosticPorts(configuration)
	if len(ports) != 2*config.MaximumServices {
		t.Fatalf("diagnosticPorts() count = %d, want %d", len(ports), 2*config.MaximumServices)
	}
	request := &centerpluginv1.DiagnoseNodePortsRequest{
		NodeId: "20000000-0000-4000-8000-000000000002", Ports: ports,
	}
	if err := centerpluginv1.ValidateDiagnoseNodePortsRequest(request); err != nil {
		t.Fatalf("ValidateDiagnoseNodePortsRequest() error = %v", err)
	}
}

func TestInvokeUIReadsAuthorizationsAndNodeDiagnostics(t *testing.T) {
	nodeID := "20000000-0000-4000-8000-000000000002"
	host := &hostStub{
		authorizations: &centerpluginv1.ListNodeAuthorizationsResponse{Authorizations: []*centerpluginv1.NodeAuthorization{{
			Id: "10000000-0000-4000-8000-000000000001", UserIdentifier: "alice", Enabled: true,
		}}},
		nodeDiagnostic: &centerpluginv1.DiagnoseNodePluginResponse{Json: []byte(`{"addresses":[{"address":"2001:db8::1","family":"ipv6","interface":"eth0"}]}`)},
	}
	server := New("0.1.0", host)
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	authorizations, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{
		Method: "authorizations.list", Json: []byte(`{"node_id":"` + nodeID + `"}`),
	})
	if err != nil || !jsonContainsValue(authorizations.GetJson(), "alice") {
		t.Fatalf("authorizations.list = %s, %v", authorizations.GetJson(), err)
	}
	diagnostics, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{
		Method: "network.addresses", Json: []byte(`{"node_id":"` + nodeID + `","input":{}}`),
	})
	if err != nil || host.nodeDiagnosticReq == nil || host.nodeDiagnosticReq.Name != "network.addresses" ||
		!jsonContainsValue(diagnostics.GetJson(), "2001:db8::1") {
		t.Fatalf("network.addresses = %s, request %+v, %v", diagnostics.GetJson(), host.nodeDiagnosticReq, err)
	}
}

func TestInvokeUIListsAndCachesOfficialXrayVersions(t *testing.T) {
	releases := &releaseStub{versions: []xrayrelease.Version{
		{Version: "26.8.1"}, {Version: "26.8.0", Prerelease: true},
	}}
	server := New("0.1.0", &hostStub{})
	server.releases = releases
	if _, err := server.Activate(t.Context(), &centerpluginv1.ActivateRequest{Permissions: append([]string(nil), requiredPermissions...)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response, err := server.InvokeUI(t.Context(), &centerpluginv1.InvokeUIRequest{Method: "xray-versions.list", Json: []byte(`{}`)})
		if err != nil || !jsonContainsValue(response.GetJson(), "26.8.1") {
			t.Fatalf("xray-versions.list = %s, %v", response.GetJson(), err)
		}
	}
	if releases.calls != 1 {
		t.Fatalf("ListVersions() calls = %d, want 1", releases.calls)
	}
}

func testConfigurationJSON(t *testing.T) json.RawMessage {
	t.Helper()
	value, err := config.NewConfiguration("26.7.28", []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Port:         24443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.microsoft.com:443"},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Port:         28443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.cloudflare.com:443"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	value.AccessRules = []config.AccessRule{{
		RuleID: "block-private", DisplayName: "Block private", Enabled: true,
		DestinationIPs: []string{"192.0.2.0/24"}, Action: config.AccessActionBlock,
	}}
	raw, err := config.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
