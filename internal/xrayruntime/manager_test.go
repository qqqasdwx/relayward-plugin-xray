package xrayruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayrelease"
)

type fakeInstaller struct {
	installation xrayrelease.Installation
}

type fakeRuntimeAPI struct{}

func (*fakeRuntimeAPI) addUser(context.Context, string, runtimeCredential) error { return nil }
func (*fakeRuntimeAPI) removeUser(context.Context, string, string) error         { return nil }
func (*fakeRuntimeAPI) close()                                                   {}
func (*fakeRuntimeAPI) queryStats(context.Context) ([]trafficStat, error) {
	return []trafficStat{
		{email: "relayward:10000000-0000-4000-8000-000000000001:vless-reality", direction: "uplink", value: 12},
		{email: "relayward:10000000-0000-4000-8000-000000000001:vless-reality", direction: "downlink", value: 34},
	}, nil
}
func (*fakeRuntimeAPI) queryOnlineIPs(context.Context, string) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (*fakeRuntimeAPI) replaceRoutingRules(context.Context, string, []xrayconfig.CompiledRoutingRule) error {
	return nil
}

type failingTrafficRuntimeAPI struct {
	removed bool
}

type trackingRuntimeAPI struct {
	online       map[string]map[string]int64
	stats        []trafficStat
	added        []string
	replacements [][]xrayconfig.CompiledRoutingRule
}

func (*failingTrafficRuntimeAPI) addUser(context.Context, string, runtimeCredential) error {
	return nil
}
func (api *failingTrafficRuntimeAPI) removeUser(context.Context, string, string) error {
	api.removed = true
	return nil
}
func (*failingTrafficRuntimeAPI) close() {}
func (*failingTrafficRuntimeAPI) queryStats(context.Context) ([]trafficStat, error) {
	return nil, errors.New("traffic unavailable")
}
func (*failingTrafficRuntimeAPI) queryOnlineIPs(context.Context, string) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (*failingTrafficRuntimeAPI) replaceRoutingRules(context.Context, string, []xrayconfig.CompiledRoutingRule) error {
	return nil
}

func (api *trackingRuntimeAPI) addUser(_ context.Context, inboundTag string, credential runtimeCredential) error {
	api.added = append(api.added, inboundTag+"\x00"+credential.email)
	return nil
}
func (*trackingRuntimeAPI) removeUser(context.Context, string, string) error { return nil }
func (*trackingRuntimeAPI) close()                                           {}
func (api *trackingRuntimeAPI) queryStats(context.Context) ([]trafficStat, error) {
	return append([]trafficStat(nil), api.stats...), nil
}
func (api *trackingRuntimeAPI) queryOnlineIPs(_ context.Context, email string) (map[string]int64, error) {
	values := make(map[string]int64, len(api.online[email]))
	for ip, lastSeen := range api.online[email] {
		values[ip] = lastSeen
	}
	return values, nil
}
func (api *trackingRuntimeAPI) replaceRoutingRules(_ context.Context, _ string, rules []xrayconfig.CompiledRoutingRule) error {
	api.replacements = append(api.replacements, append([]xrayconfig.CompiledRoutingRule(nil), rules...))
	return nil
}

func (installer fakeInstaller) Ensure(context.Context, string) (xrayrelease.Installation, error) {
	return installer.installation, nil
}

func TestManagerAppliesAndStopsConfiguration(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Validate(context.Background(), configuration); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := manager.Apply(context.Background(), 7, digestA, configuration); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	status := manager.GetStatus()
	if !status.Healthy || status.Generation != 7 || status.ConfigurationSHA256 != digestA {
		t.Fatalf("GetStatus() = %+v", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagerRejectsInvalidXrayConfiguration(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "127.0.0.3")
	if err := manager.Validate(context.Background(), configuration); !errors.Is(err, ErrConfigurationRejected) {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestManagerIgnoresLegacyConfigurationCacheKeyDuringUpgrade(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	directory := filepath.Join(manager.dataDirectory, "xray", "configurations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(directory, digestA+".json")
	if err := os.WriteFile(legacyPath, []byte(`{"legacy":true}`), 0o400); err != nil {
		t.Fatal(err)
	}
	configuration := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatalf("Apply() with legacy cache error = %v", err)
	}
	raw, err := xrayconfig.Render(configuration)
	if err != nil {
		t.Fatal(err)
	}
	generatedDigest := sha256.Sum256(raw)
	expectedPath := filepath.Join(directory, fmt.Sprintf("%x.json", generatedDigest))
	actualPath := ""
	if manager.running != nil {
		actualPath = manager.running.configPath
	}
	if actualPath != expectedPath || actualPath == legacyPath {
		t.Fatalf("running configuration path = %q, want %q", actualPath, expectedPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRestoresPreviousProcessAfterCandidateStartupFailure(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	manager.connectAPI = func(_ context.Context, configuration config.Configuration) (runtimeAPI, error) {
		if configuration.Services[0].VLESSReality.Target == "candidate.example.com:443" {
			return nil, errors.New("candidate API unavailable")
		}
		return &fakeRuntimeAPI{}, nil
	}
	first := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Apply(context.Background(), 1, digestA, first); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	second := testConfigurationValue(t, "127.0.0.2")
	if err := manager.Apply(context.Background(), 2, digestB, second); err == nil {
		t.Fatal("second Apply() unexpectedly succeeded")
	}
	status := manager.GetStatus()
	if !status.Healthy || status.Generation != 1 || status.ConfigurationSHA256 != digestA {
		t.Fatalf("GetStatus() after rollback = %+v", status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestManagerRestartsUnexpectedlyExitedProcess(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	manager.restartDelay = 10 * time.Millisecond
	configuration := testConfigurationValue(t, "0.0.0.0")
	firstAPI := &trackingRuntimeAPI{}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return firstAPI, nil }
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	authorizationID := "10000000-0000-4000-8000-000000000001"
	if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, testServiceID, true); err != nil {
		t.Fatal(err)
	}
	blocks := []DynamicBlock{{
		AuthorizationID: authorizationID, ServiceID: testServiceID, SourceIP: "192.0.2.20",
		ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(),
	}}
	if err := manager.ApplyDynamicBlocks(context.Background(), 1, 1, blocks); err != nil {
		t.Fatal(err)
	}

	restoredAPI := &trackingRuntimeAPI{}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return restoredAPI, nil }
	manager.state.Lock()
	previous := manager.process
	manager.state.Unlock()
	if err := syscall.Kill(-previous.command.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("terminate Xray process: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		manager.state.Lock()
		current := manager.process
		manager.state.Unlock()
		if current != nil && current != previous && manager.GetStatus().Healthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Xray process was not restarted: %+v", manager.GetStatus())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(restoredAPI.added) != 1 || len(restoredAPI.replacements) != 1 {
		t.Fatalf("restored runtime = added %q, replacements %+v", restoredAPI.added, restoredAPI.replacements)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRejectsProcessThatExitsCleanlyDuringStartup(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	manager.startupGrace = 250 * time.Millisecond
	configuration := testConfigurationValue(t, "127.0.0.4")
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err == nil {
		t.Fatal("Apply() unexpectedly succeeded")
	}
	if status := manager.GetStatus(); status.Generation != 0 || status.Healthy {
		t.Fatalf("GetStatus() = %+v", status)
	}
}

func TestManagerControlsUsersAndCollectsTraffic(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	authorizationID := "10000000-0000-4000-8000-000000000001"
	if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, testServiceID, true); err != nil {
		t.Fatalf("ApplyServiceState(enable) error = %v", err)
	}
	counters, err := manager.CollectTraffic(context.Background())
	if err != nil {
		t.Fatalf("CollectTraffic() error = %v", err)
	}
	if len(counters) != 1 || counters[0].AuthorizationID != authorizationID || counters[0].UploadBytes != 12 || counters[0].DownloadBytes != 34 || counters[0].CounterEpoch == "" {
		t.Fatalf("CollectTraffic() = %+v", counters)
	}
	if err := manager.ApplyServiceState(context.Background(), 1, 2, authorizationID, testServiceID, false); err != nil {
		t.Fatalf("ApplyServiceState(disable) error = %v", err)
	}
	if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, testServiceID, true); !errors.Is(err, ErrServiceStateConflict) {
		t.Fatalf("ApplyServiceState(stale) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerKeepsUserEnabledWhenFinalTrafficCollectionFails(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	authorizationID := "10000000-0000-4000-8000-000000000001"
	if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, testServiceID, true); err != nil {
		t.Fatal(err)
	}
	failingAPI := &failingTrafficRuntimeAPI{}
	manager.process.api = failingAPI
	if err := manager.ApplyServiceState(context.Background(), 1, 2, authorizationID, testServiceID, false); err == nil {
		t.Fatal("ApplyServiceState(disable) unexpectedly succeeded")
	}
	state := manager.services[serviceKey(authorizationID, testServiceID)]
	if state == nil || !state.enabled || failingAPI.removed {
		t.Fatalf("service state = %+v, removed = %v", state, failingAPI.removed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerCollectsActivityAndRestoresDynamicBlocks(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "0.0.0.0")
	configuration.AccessRules = []config.AccessRule{{
		RuleID: "allow-example", DisplayName: "Allow example", Enabled: true,
		Domains: []string{"domain:example.com"}, Action: config.AccessActionEgress, EgressLineID: config.DefaultEgressLineID,
	}}
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	authorizationID := "10000000-0000-4000-8000-000000000001"
	if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, testServiceID, true); err != nil {
		t.Fatal(err)
	}
	email := config.UserEmail(authorizationID, testServiceID)
	api := &trackingRuntimeAPI{online: map[string]map[string]int64{
		email: {"192.0.2.10": time.Now().Unix()},
	}}
	manager.process.api = api
	page, err := manager.CollectActivity(context.Background(), 0, 10)
	if err != nil || len(page.Events) != 1 || page.Events[0].AuthorizationID != authorizationID ||
		page.Events[0].SourceIP != "192.0.2.10" || manager.TelemetryStreamID() == "" {
		t.Fatalf("CollectActivity() = %+v, %v", page, err)
	}
	blocks := []DynamicBlock{{
		AuthorizationID: authorizationID, ServiceID: testServiceID, SourceIP: "192.0.2.20",
		ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(),
	}}
	if err := manager.ApplyDynamicBlocks(context.Background(), 1, 1, blocks); err != nil {
		t.Fatal(err)
	}
	if len(api.replacements) != 1 || len(api.replacements[0]) != 8 ||
		api.replacements[0][0].RuleTag != xrayconfig.APIRuleTag ||
		api.replacements[0][4].UserEmails[0] != email ||
		api.replacements[0][4].InboundTags[0] != testServiceID ||
		api.replacements[0][4].SourceIPs[0].Prefix.String() != "192.0.2.20/32" ||
		api.replacements[0][5].RuleTag != "relayward/access/allow-example" {
		t.Fatalf("replacement = %+v", api.replacements)
	}
	if err := manager.ApplyDynamicBlocks(context.Background(), 1, 1, blocks); err != nil || len(api.replacements) != 1 {
		t.Fatalf("idempotent ApplyDynamicBlocks() = %v, calls = %d", err, len(api.replacements))
	}
	conflicting := append([]DynamicBlock(nil), blocks...)
	conflicting[0].ExpiresAtUnixNano++
	if err := manager.ApplyDynamicBlocks(context.Background(), 1, 1, conflicting); !errors.Is(err, ErrDynamicBlockConflict) {
		t.Fatalf("conflicting ApplyDynamicBlocks() error = %v", err)
	}
	restoredAPI := &trackingRuntimeAPI{}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return restoredAPI, nil }
	if err := manager.Apply(context.Background(), 2, digestB, configuration); err != nil {
		t.Fatal(err)
	}
	if len(restoredAPI.replacements) != 1 || len(restoredAPI.replacements[0]) != 8 ||
		restoredAPI.replacements[0][4].SourceIPs[0].Prefix.String() != "192.0.2.20/32" ||
		restoredAPI.replacements[0][5].RuleTag != "relayward/access/allow-example" {
		t.Fatalf("restored replacement = %+v", restoredAPI.replacements)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestManagerControlsAndRestoresMultipleServices(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration, err := config.NewConfiguration("26.7.28", []config.EditableService{
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
	authorizationID := "10000000-0000-4000-8000-000000000001"
	mainEmail := config.UserEmail(authorizationID, "reality-main")
	backupEmail := config.UserEmail(authorizationID, "reality-backup")
	api := &trackingRuntimeAPI{
		online: map[string]map[string]int64{
			mainEmail:   {"192.0.2.10": time.Now().Unix()},
			backupEmail: {"192.0.2.11": time.Now().Unix()},
		},
		stats: []trafficStat{
			{email: mainEmail, direction: "uplink", value: 10},
			{email: mainEmail, direction: "downlink", value: 20},
			{email: backupEmail, direction: "uplink", value: 30},
			{email: backupEmail, direction: "downlink", value: 40},
		},
	}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return api, nil }
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	for _, serviceID := range []string{"reality-main", "reality-backup"} {
		if err := manager.ApplyServiceState(context.Background(), 1, 1, authorizationID, serviceID, true); err != nil {
			t.Fatalf("ApplyServiceState(%q) error = %v", serviceID, err)
		}
	}
	if len(api.added) != 2 || api.added[0] != "reality-main\x00"+mainEmail ||
		api.added[1] != "reality-backup\x00"+backupEmail {
		t.Fatalf("added users = %q", api.added)
	}
	counters, err := manager.CollectTraffic(context.Background())
	if err != nil || len(counters) != 2 || counters[0].ServiceID != "reality-backup" ||
		counters[0].UploadBytes != 30 || counters[0].DownloadBytes != 40 ||
		counters[1].ServiceID != "reality-main" || counters[1].UploadBytes != 10 || counters[1].DownloadBytes != 20 {
		t.Fatalf("CollectTraffic() = %+v, %v", counters, err)
	}
	activity, err := manager.CollectActivity(context.Background(), 0, 10)
	if err != nil || len(activity.Events) != 2 {
		t.Fatalf("CollectActivity() = %+v, %v", activity, err)
	}
	blocks := []DynamicBlock{
		{AuthorizationID: authorizationID, ServiceID: "reality-backup", SourceIP: "192.0.2.20", ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano()},
		{AuthorizationID: authorizationID, ServiceID: "reality-main", SourceIP: "192.0.2.20", ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano()},
	}
	if err := manager.ApplyDynamicBlocks(context.Background(), 1, 1, blocks); err != nil {
		t.Fatal(err)
	}
	restored := &trackingRuntimeAPI{}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return restored, nil }
	if err := manager.Apply(context.Background(), 2, digestB, configuration); err != nil {
		t.Fatal(err)
	}
	if len(restored.added) != 2 || len(restored.replacements) != 1 || len(restored.replacements[0]) != 10 {
		t.Fatalf("restored runtime = added %q, blocks %+v", restored.added, restored.replacements)
	}
	editable := config.Editable(configuration)
	editable.Services = editable.Services[1:]
	withoutBackup, err := config.MergeEditable(configuration, editable)
	if err != nil {
		t.Fatal(err)
	}
	removed := &trackingRuntimeAPI{}
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) { return removed, nil }
	if err := manager.Apply(context.Background(), 3, digestC, withoutBackup); err != nil {
		t.Fatal(err)
	}
	backupState := manager.services[serviceKey(authorizationID, "reality-backup")]
	mainState := manager.services[serviceKey(authorizationID, "reality-main")]
	if backupState == nil || backupState.enabled || mainState == nil || !mainState.enabled ||
		len(manager.blocks) != 1 || manager.blocks[0].ServiceID != "reality-main" || manager.blockRevision != 0 ||
		len(removed.added) != 1 || len(removed.replacements) != 1 || len(removed.replacements[0]) != 7 {
		t.Fatalf("state after service removal = backup %+v, main %+v, blocks %+v, runtime %+v", backupState, mainState, manager.blocks, removed)
	}
	if err := manager.ApplyServiceState(context.Background(), 4, 4, authorizationID, "reality-backup", false); err != nil {
		t.Fatalf("disable removed service: %v", err)
	}
	backupState = manager.services[serviceKey(authorizationID, "reality-backup")]
	if backupState.enabled || backupState.policyGeneration != 4 || backupState.stateRevision != 4 {
		t.Fatalf("removed service state = %+v", backupState)
	}
	if err := manager.ApplyServiceState(context.Background(), 4, 5, authorizationID, "retired-service", false); err != nil {
		t.Fatalf("disable unknown retired service: %v", err)
	}
	retiredState := manager.services[serviceKey(authorizationID, "retired-service")]
	if retiredState == nil || retiredState.enabled || retiredState.policyGeneration != 4 || retiredState.stateRevision != 5 {
		t.Fatalf("retired service state = %+v", retiredState)
	}
	if err := manager.ApplyServiceState(context.Background(), 4, 6, authorizationID, "retired-service", true); !errors.Is(err, ErrUnsupportedService) {
		t.Fatalf("enable unknown retired service error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func testConfigurationValue(t *testing.T, scenario string) config.Configuration {
	t.Helper()
	target := "www.microsoft.com:443"
	switch scenario {
	case "127.0.0.2":
		target = "candidate.example.com:443"
	case "127.0.0.3":
		target = "invalid.example.com:443"
	case "127.0.0.4":
		target = "exit.example.com:443"
	}
	value, err := config.NewConfiguration("26.7.28", []config.EditableService{{
		Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: testServiceID, DisplayName: "VLESS Reality",
		Port:         24443,
		VLESSReality: &config.EditableVLESSReality{Target: target},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	directory := t.TempDir()
	binary := filepath.Join(directory, "fake-xray")
	script := `#!/bin/sh
if [ "$1" = "api" ]; then
  case "$2" in
    statsquery)
      printf '%s\n' '{"stat":[{"name":"user>>>relayward:10000000-0000-4000-8000-000000000001:vless-reality>>>traffic>>>uplink","value":"12"},{"name":"user>>>relayward:10000000-0000-4000-8000-000000000001:vless-reality>>>traffic>>>downlink","value":"34"}]}'
      ;;
  esac
  exit 0
fi
config=""
test_mode=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    -test) test_mode=1 ;;
    -config) shift; config=$1 ;;
  esac
  shift
done
if grep -q '"rewriteAddress":"invalid.example.com"' "$config"; then
  exit 1
fi
if [ "$test_mode" -eq 1 ]; then
  exit 0
fi
if [ "$test_mode" -eq 0 ] && grep -q '"rewriteAddress":"candidate.example.com"' "$config"; then
  exit 1
fi
if [ "$test_mode" -eq 0 ] && grep -q '"rewriteAddress":"exit.example.com"' "$config"; then
  exit 0
fi
trap 'exit 0' TERM INT
while :; do sleep 1; done
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(directory, fakeInstaller{installation: xrayrelease.Installation{
		Version: "26.7.28", Binary: binary, AssetDir: directory,
	}})
	if err != nil {
		t.Fatal(err)
	}
	manager.startupGrace = 50 * time.Millisecond
	manager.connectAPI = func(context.Context, config.Configuration) (runtimeAPI, error) {
		return &fakeRuntimeAPI{}, nil
	}
	manager.inspect = func(configuration config.Configuration) []ListenerStatus {
		listeners := configuredListeners(configuration)
		for index := range listeners {
			listeners[index].State = ListenerListening
		}
		return listeners
	}
	return manager
}

const (
	testServiceID = "vless-reality"
	digestA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC       = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)
