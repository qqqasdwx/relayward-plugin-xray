package xrayruntime

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const accessLine = "2026/10/03 12:00:00.123 from tcp:192.0.2.1:54321 accepted tcp:example.com:443 [vless-reality -> relayward/egress/default] email: relayward:10000000-0000-4000-8000-000000000001:vless-reality\n"

func TestManagedAccessParsing(t *testing.T) {
	configuration := testConfigurationValue(t, "www.tesla.com")
	for _, line := range []string{accessLine, strings.ReplaceAll(accessLine, "from tcp:", "from "), strings.ReplaceAll(accessLine, "192.0.2.1:54321", "[2001:db8::1]:54321")} {
		event, ok, err := parseAccess(line, configuration)
		if err != nil || !ok || event.Destination != "example.com" || event.DestinationPort != 443 || event.ObservationKind != agentv1.ObservationConnection {
			t.Fatalf("parsed access mismatch: %v", err)
		}
	}
	event, ok, err := parseAccess(strings.ReplaceAll(accessLine, "relayward/egress/default", "relayward/blocked"), configuration)
	if err != nil || !ok || event.Action != agentv1.AccessActionBlocked {
		t.Fatalf("blocked access mismatch: %v", err)
	}
	if _, ok, err := parseAccess("2026/10/03 12:00:00 from tcp:127.0.0.1:5000 accepted tcp:127.0.0.1:10085\n", configuration); err != nil || ok {
		t.Fatal("internal access was counted")
	}
	if _, _, err := parseAccess("invalid email: relayward:test", configuration); err == nil {
		t.Fatal("malformed managed log accepted")
	}
}
func TestAccessCheckpointAndPartialLine(t *testing.T) {
	manager := testManager(t)
	configuration := testConfigurationValue(t, "www.tesla.com")
	path := filepath.Join(manager.dataDirectory, "xray", "access", "current.log")
	if err := os.WriteFile(path, []byte(accessLine+strings.TrimSuffix(accessLine, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	process := &managedProcess{api: &fakeRuntimeAPI{}}
	if err := manager.collectAccess(context.Background(), process, configuration); err != nil {
		t.Fatal(err)
	}
	if len(manager.telemetry.state.Events) != 1 {
		t.Fatal("partial line counted")
	}
	reopened, err := openTelemetryStore(manager.dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	manager.telemetry = reopened
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.WriteString("\n")
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.collectAccess(context.Background(), process, configuration); err != nil {
		t.Fatal(err)
	}
	if len(manager.telemetry.state.Events) != 2 || manager.telemetry.state.Events[1].EventID != "access-2" {
		t.Fatal("checkpoint replay duplicated access")
	}
}
func TestAccessLineBound(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 100000)+"\n"+accessLine), 4096)
	_, n, large, err := readAccessLine(reader)
	if err != nil || !large || n != 100001 {
		t.Fatal("oversized log not bounded")
	}
	line, _, large, err := readAccessLine(reader)
	if err != nil || large || line != accessLine {
		t.Fatal("oversized line consumed next record")
	}
}

type rotatingAPI struct {
	fakeRuntimeAPI
	path  string
	calls int
}

func (a *rotatingAPI) restartLogger(context.Context) error {
	a.calls++
	return os.WriteFile(a.path, nil, 0600)
}
func TestAccessRotationAndDiskGap(t *testing.T) {
	manager := testManager(t)
	configuration := testConfigurationValue(t, "www.tesla.com")
	dir := filepath.Join(manager.dataDirectory, "xray", "access")
	path := filepath.Join(dir, "current.log")
	file, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Truncate(accessDiskLimit + 1)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	api := &rotatingAPI{path: path}
	if err = manager.collectAccess(context.Background(), &managedProcess{api: api}, configuration); err != nil {
		t.Fatal(err)
	}
	if !manager.telemetry.collectionGap() {
		t.Fatal("eviction not reported as gap")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil || len(files) != 1 {
		t.Fatal("raw log budget exceeded")
	}
}
