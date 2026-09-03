package node

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

type fakeRuntime struct {
	status        xrayruntime.Status
	applied       config.Configuration
	serviceState  bool
	serviceID     string
	authorization string
	blocks        []xrayruntime.DynamicBlock
	blockRevision uint64
	addresses     []xrayruntime.NetworkAddress
	probe         xrayruntime.EgressProbe
	probeLineID   string
}

func (*fakeRuntime) Validate(context.Context, config.Configuration) error { return nil }
func (runtime *fakeRuntime) Apply(_ context.Context, generation uint64, digest string, configuration config.Configuration) error {
	runtime.applied = configuration
	runtime.status = xrayruntime.Status{Generation: generation, ConfigurationSHA256: digest, Healthy: true}
	return nil
}

func TestServerReportsListenerStatus(t *testing.T) {
	t.Parallel()
	runtime := &fakeRuntime{status: xrayruntime.Status{
		Generation: 1, ConfigurationSHA256: strings.Repeat("a", 64), Healthy: true,
		Listeners: []xrayruntime.ListenerStatus{{
			ServiceID: testServiceID, Network: "tcp", ListenAddress: "0.0.0.0", Port: 443,
			State: xrayruntime.ListenerListening,
		}},
	}}
	server := New("0.1.0", runtime)
	info, err := server.GetInfo(t.Context(), &nodepluginv1.GetInfoRequest{})
	if err != nil || !slices.Contains(info.Capabilities, nodepluginv1.CapabilityListenerStatus) {
		t.Fatalf("GetInfo() = %+v, %v", info, err)
	}
	response, err := server.GetStatus(t.Context(), &nodepluginv1.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateStatusResponse(response); err != nil {
		t.Fatal(err)
	}
	if len(response.Listeners) != 1 || response.Listeners[0].State != nodepluginv1.ListenerState_LISTENER_STATE_LISTENING {
		t.Fatalf("GetStatus() = %+v", response)
	}
}
func (runtime *fakeRuntime) GetStatus() xrayruntime.Status { return runtime.status }
func (runtime *fakeRuntime) ApplyServiceState(_ context.Context, _, _ uint64, authorizationID, serviceID string, enabled bool) error {
	runtime.authorization = authorizationID
	runtime.serviceID = serviceID
	runtime.serviceState = enabled
	return nil
}
func (*fakeRuntime) CollectTraffic(context.Context) ([]xrayruntime.TrafficCounter, error) {
	return []xrayruntime.TrafficCounter{{
		AuthorizationID: "10000000-0000-4000-8000-000000000001",
		ServiceID:       testServiceID, CounterEpoch: "epoch-1", UploadBytes: 12, DownloadBytes: 34,
	}}, nil
}
func (*fakeRuntime) TelemetryStreamID() string { return "0123456789abcdef0123456789abcdef" }
func (*fakeRuntime) CollectActivity(context.Context, uint64, uint32) (xrayruntime.ActivityPage, error) {
	return xrayruntime.ActivityPage{Events: []xrayruntime.ActivityEvent{{
		Sequence: 1, EventID: "online-1", ObservedAt: time.Now().UTC().UnixNano(),
		AuthorizationID: "10000000-0000-4000-8000-000000000001",
		ServiceID:       testServiceID, SourceIP: "192.0.2.1",
	}}, NextSequence: 1}, nil
}
func (runtime *fakeRuntime) ApplyDynamicBlocks(_ context.Context, _ uint64, revision uint64, blocks []xrayruntime.DynamicBlock) error {
	runtime.blockRevision = revision
	runtime.blocks = append([]xrayruntime.DynamicBlock(nil), blocks...)
	return nil
}
func (runtime *fakeRuntime) NetworkAddresses() ([]xrayruntime.NetworkAddress, error) {
	return append([]xrayruntime.NetworkAddress(nil), runtime.addresses...), nil
}
func (runtime *fakeRuntime) ProbeEgress(_ context.Context, lineID string) (xrayruntime.EgressProbe, error) {
	runtime.probeLineID = lineID
	return runtime.probe, nil
}

func TestServerRunsDiagnostics(t *testing.T) {
	t.Parallel()
	runtime := &fakeRuntime{
		addresses: []xrayruntime.NetworkAddress{{Address: "2001:db8::1", Family: "ipv6", Interface: "eth0"}},
		probe: xrayruntime.EgressProbe{
			LineID: "default", Address: "192.0.2.10", Country: "US", Colocation: "SJC",
			ObservedAtUnixNano: time.Now().UTC().UnixNano(), ElapsedMillis: 12,
		},
	}
	server := New("0.1.0", runtime)
	addressesRequest := &nodepluginv1.DiagnoseRequest{Name: "network.addresses", Json: []byte(`{}`)}
	addresses, err := server.Diagnose(t.Context(), addressesRequest)
	if err != nil || !strings.Contains(string(addresses.GetJson()), "2001:db8::1") {
		t.Fatalf("Diagnose(network.addresses) = %s, %v", addresses.GetJson(), err)
	}
	probeRequest := &nodepluginv1.DiagnoseRequest{Name: "egress.probe", Json: []byte(`{"line_id":"default"}`)}
	probe, err := server.Diagnose(t.Context(), probeRequest)
	if err != nil || runtime.probeLineID != "default" || !strings.Contains(string(probe.GetJson()), "192.0.2.10") {
		t.Fatalf("Diagnose(egress.probe) = %s, line %q, %v", probe.GetJson(), runtime.probeLineID, err)
	}
}

func TestServerAppliesConfiguration(t *testing.T) {
	t.Parallel()
	runtime := &fakeRuntime{}
	server := New("0.1.0", runtime)
	raw := testConfigurationJSON(t)
	digest, err := agentv1.PluginConfigurationDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	request := &nodepluginv1.ConfigurationRequest{Generation: 3, Sha256: digest, Json: raw}
	validated, err := server.ValidateConfiguration(context.Background(), request)
	if err != nil {
		t.Fatalf("ValidateConfiguration() error = %v", err)
	}
	if err := nodepluginv1.ValidateConfigurationValidated(request, validated); err != nil {
		t.Fatal(err)
	}
	applied, err := server.ApplyConfiguration(context.Background(), request)
	if err != nil {
		t.Fatalf("ApplyConfiguration() error = %v", err)
	}
	if err := nodepluginv1.ValidateConfigurationApplied(request, applied); err != nil {
		t.Fatal(err)
	}
	result, err := server.GetStatus(context.Background(), &nodepluginv1.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateStatusResponse(result); err != nil {
		t.Fatal(err)
	}
	if result.Health != nodepluginv1.Health_HEALTH_HEALTHY || runtime.applied.XrayVersion != "26.7.28" {
		t.Fatalf("GetStatus() = %+v, applied = %+v", result, runtime.applied)
	}
}

func TestServerControlsServiceAndReturnsTraffic(t *testing.T) {
	t.Parallel()
	runtime := &fakeRuntime{}
	server := New("0.1.0", runtime)
	info, err := server.GetInfo(context.Background(), &nodepluginv1.GetInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateInfoResponse(info, info.PluginId, info.Version); err != nil {
		t.Fatal(err)
	}
	authorizationID := "10000000-0000-4000-8000-000000000001"
	state := &nodepluginv1.SetServiceStateRequest{
		PolicyGeneration: 1, StateRevision: 2, AuthorizationId: authorizationID,
		ServiceId: testServiceID, Enabled: true,
		Reason: nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ACTIVE,
	}
	applied, err := server.SetServiceState(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateSetServiceStateResponse(state, applied); err != nil {
		t.Fatal(err)
	}
	if !runtime.serviceState || runtime.authorization != authorizationID || runtime.serviceID != testServiceID {
		t.Fatalf("runtime state = %+v", runtime)
	}
	request := &nodepluginv1.CollectTelemetryRequest{MaximumEvents: 10}
	telemetry, err := server.CollectTelemetry(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateCollectTelemetryResponse(request, telemetry); err != nil {
		t.Fatal(err)
	}
	if len(telemetry.Counters) != 1 || telemetry.Counters[0].UploadBytes != 12 || len(telemetry.Events) != 1 ||
		telemetry.Events[0].SourceIp != "192.0.2.1" {
		t.Fatalf("telemetry = %+v", telemetry)
	}
	blocks := &nodepluginv1.ReplaceDynamicBlocksRequest{
		PolicyGeneration: 1, BlockRevision: 3,
		Blocks: []*nodepluginv1.DynamicBlock{{
			AuthorizationId: authorizationID, ServiceId: testServiceID,
			SourceIp: "192.0.2.2", ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(),
		}},
	}
	blockResponse, err := server.ReplaceDynamicBlocks(context.Background(), blocks)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepluginv1.ValidateReplaceDynamicBlocksResponse(blocks, blockResponse); err != nil {
		t.Fatal(err)
	}
	if runtime.blockRevision != 3 || len(runtime.blocks) != 1 || runtime.blocks[0].SourceIP != "192.0.2.2" {
		t.Fatalf("runtime blocks = %+v", runtime.blocks)
	}
}

func TestServerRejectsUnknownConfigurationField(t *testing.T) {
	t.Parallel()
	valid := testConfigurationJSON(t)
	raw := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"secret":"value"}`)...)
	digest, err := agentv1.PluginConfigurationDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = New("0.1.0", &fakeRuntime{}).ValidateConfiguration(context.Background(), &nodepluginv1.ConfigurationRequest{
		Generation: 1, Sha256: digest, Json: raw,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ValidateConfiguration() code = %v, want InvalidArgument", status.Code(err))
	}
}

func testConfigurationJSON(t *testing.T) []byte {
	t.Helper()
	value, err := config.NewConfiguration("26.7.28", []config.EditableService{{
		Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: testServiceID, DisplayName: "VLESS Reality",
		Port:         24443,
		VLESSReality: &config.EditableVLESSReality{Target: "www.microsoft.com:443"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const testServiceID = "vless-reality"
