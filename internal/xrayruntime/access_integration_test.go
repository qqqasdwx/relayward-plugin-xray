package xrayruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// The official artifact is exercised by CI, never by the default local suite.
func TestOfficialXrayAccessAndLoggerRotation(t *testing.T) {
	binary := os.Getenv("XRAY_INTEGRATION_BINARY")
	if binary == "" {
		t.Skip("official Xray integration artifact is not configured")
	}
	directory := t.TempDir()
	accessPath := filepath.Join(directory, "xray", "access", "current.log")
	if err := os.MkdirAll(filepath.Dir(accessPath), 0700); err != nil {
		t.Fatal(err)
	}
	port := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		return p
	}
	serverPort, clientPort, apiPort := port(), port(), port()
	const credential = "30000000-0000-4000-8000-000000000001"
	serverConfig := map[string]any{
		"log": map[string]any{"access": accessPath, "loglevel": "warning"},
		"api": map[string]any{"tag": "api", "services": []string{"LoggerService"}},
		"inbounds": []any{
			map[string]any{"tag": testServiceID, "listen": "127.0.0.1", "port": serverPort, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": credential, "email": "relayward:10000000-0000-4000-8000-000000000001:vless-reality"}}}},
			map[string]any{"tag": "api", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}},
	}
	clientConfig := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": clientPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": serverPort, "users": []any{map[string]any{"id": credential, "encryption": "none"}}}}}}},
	}
	start := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name+".json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-config", path)
		cmd.Stdout = io.Discard
		cmd.Stderr = os.Stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-done
		})
	}
	start("server", serverConfig)
	start("client", clientConfig)
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)), 50*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("official Xray did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}, DisableKeepAlives: true}}
	request := func() {
		response, err := client.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("proxy request failed")
		}
	}
	request()
	configuration := testConfigurationValue(t, "www.tesla.com")
	configuration.APIPort = uint16(apiPort)
	api, err := connectXrayAPI(t.Context(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer api.close()
	store, err := openTelemetryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{dataDirectory: directory, telemetry: store}
	if err = manager.collectAccess(t.Context(), &managedProcess{api: api}, configuration); err != nil {
		t.Fatal(err)
	}
	if len(store.state.Events) != 1 || store.state.Events[0].DestinationPort == 0 {
		t.Fatal("real access record was not parsed")
	}
	if err = os.Truncate(accessPath, accessLogLimit); err != nil {
		t.Fatal(err)
	}
	if err = manager.collectAccess(t.Context(), &managedProcess{api: api}, configuration); err != nil {
		t.Fatal(err)
	}
	request()
	if err = manager.collectAccess(t.Context(), &managedProcess{api: api}, configuration); err != nil {
		t.Fatal(err)
	}
	if len(store.state.Events) != 2 {
		t.Fatal("access logging did not resume after LoggerService rotation")
	}
}
