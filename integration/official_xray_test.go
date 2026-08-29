package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayrelease"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

func TestOfficialXrayLifecycle(t *testing.T) {
	if os.Getenv("RELAYWARD_XRAY_INTEGRATION") != "1" {
		t.Skip("set RELAYWARD_XRAY_INTEGRATION=1 to download and run official Xray")
	}
	apiPort := freePort(t)
	mainPort := freePort(t)
	backupPort := freePort(t)
	shadowsocks2022Port := freePort(t)
	shadowsocksAEADPort := freePort(t)
	configuration, err := config.NewConfiguration("26.3.27", apiPort, []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "127.0.0.1", Port: mainPort, PublicHost: "edge.example.com", PublicPort: mainPort,
			TCP: config.TCPSettings{Header: config.TCPHeader{Type: config.TCPHeaderNone}},
			Sniffing: config.Sniffing{
				Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"},
				MetadataOnly: true, RouteOnly: true,
				IPsExcluded: []string{"192.0.2.0/24"}, DomainsExcluded: []string{"domain:excluded.example"},
			},
			VLESSReality: &config.EditableVLESSReality{
				Decryption: "none", Encryption: "none", TestSeed: []uint32{900, 500, 900, 256},
				Fallbacks: []config.VLESSFallback{{Dest: strconv.Itoa(int(backupPort)), Xver: 0}},
				Show:      true, Target: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"},
				MinClientVersion: "1.0.0", MaxClientVersion: "26.3.27", MaxTimeDiff: 1000,
				LimitFallbackUpload:   &config.RealityLimitFallback{AfterBytes: 1024, BytesPerSec: 2048, BurstBytesPerSec: 4096},
				LimitFallbackDownload: &config.RealityLimitFallback{AfterBytes: 2048, BytesPerSec: 4096, BurstBytesPerSec: 8192},
				Fingerprint:           "chrome", SpiderX: "/integration",
			},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "127.0.0.1", Port: backupPort, PublicHost: "backup.example.com", PublicPort: backupPort,
			TCP: config.TCPSettings{Header: config.TCPHeader{
				Type: config.TCPHeaderHTTP,
				Request: &config.TCPHTTPRequest{
					Version: "1.1", Method: "GET", Path: []string{"/integration"},
					Headers: map[string][]string{"Host": {"www.microsoft.com"}},
				},
				Response: &config.TCPHTTPResponse{
					Version: "1.1", Status: "200", Reason: "OK",
					Headers: map[string][]string{"Content-Type": {"application/octet-stream"}},
				},
			}},
			VLESSReality: &config.EditableVLESSReality{
				Decryption: "none", Encryption: "none",
				Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
				Fingerprint: "chrome", SpiderX: "/",
			},
		},
		{
			Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-2022", DisplayName: "Shadowsocks 2022",
			Listen: "127.0.0.1", Port: shadowsocks2022Port, PublicHost: "ss2022.example.com", PublicPort: shadowsocks2022Port,
			Shadowsocks: &config.EditableShadowsocks{
				Method: config.ShadowsocksMethod2022AES256, Network: config.ShadowsocksNetworkTCPUDP,
			},
		},
		{
			Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-aead", DisplayName: "Shadowsocks AEAD",
			Listen: "127.0.0.1", Port: shadowsocksAEADPort, PublicHost: "ss.example.com", PublicPort: shadowsocksAEADPort,
			Shadowsocks: &config.EditableShadowsocks{
				Method: config.ShadowsocksMethodChaCha20, Network: config.ShadowsocksNetworkTCPUDP, IVCheck: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration.Routing = config.RoutingConfiguration{Rules: []config.RoutingRule{
		{
			RuleID: "block-documentation", DisplayName: "Block documentation range", Enabled: true,
			IPCIDRs: []string{"192.0.2.0/24"}, Action: config.RoutingActionBlocked,
		},
		{
			RuleID: "allow-example-tls", DisplayName: "Allow example TLS", Enabled: true,
			Domains: []string{"example.com"}, Protocols: []string{"tls"}, Action: config.RoutingActionDirect,
		},
	}}
	configuration.DNS = config.DNSConfiguration{
		Enabled: true, QueryStrategy: config.DNSQueryStrategyUseIPv4,
		Servers: []config.DNSServer{
			{ServerID: "system", DisplayName: "System DNS", Enabled: true, Transport: config.DNSTransportSystem},
			{
				ServerID: "udp", DisplayName: "UDP DNS", Enabled: true, Transport: config.DNSTransportUDP,
				Address: "1.1.1.1", Port: 53, Domains: []string{"example.com"},
			},
			{
				ServerID: "tcp", DisplayName: "TCP DNS", Enabled: true, Transport: config.DNSTransportTCP,
				Address: "2001:4860:4860::8888", Port: 53, Domains: []string{"example.net"},
			},
			{
				ServerID: "doh", DisplayName: "DoH", Enabled: true, Transport: config.DNSTransportDoH,
				Address: "https://1.1.1.1/dns-query", Domains: []string{"example.org"},
			},
		},
	}
	raw, err := config.Encode(configuration)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentv1.PluginConfigurationDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	directory := integrationDataDirectory(t)
	installer := xrayrelease.NewInstaller(directory, xrayrelease.NewClient())
	runtime, err := xrayruntime.NewManager(directory, installer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := runtime.Validate(ctx, configuration); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := runtime.Apply(ctx, 1, digest, configuration); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	status := runtime.GetStatus()
	if !status.Healthy || status.Generation != 1 || status.ConfigurationSHA256 != digest {
		t.Fatalf("GetStatus() = %+v", status)
	}
	waitForTCP(t, mainPort)
	waitForTCP(t, backupPort)
	waitForTCP(t, shadowsocks2022Port)
	waitForTCP(t, shadowsocksAEADPort)
	authorizationID := "10000000-0000-4000-8000-000000000001"
	for revision, serviceID := range []string{"reality-main", "reality-backup", "shadowsocks-2022", "shadowsocks-aead"} {
		if err := runtime.ApplyServiceState(ctx, 1, uint64(revision+1), authorizationID, serviceID, true); err != nil {
			t.Fatalf("ApplyServiceState(%q) error = %v", serviceID, err)
		}
	}
	counters, err := runtime.CollectTraffic(ctx)
	if err != nil || len(counters) != 4 || counters[0].AuthorizationID != authorizationID ||
		counters[0].ServiceID != "reality-backup" || counters[1].ServiceID != "reality-main" ||
		counters[2].ServiceID != "shadowsocks-2022" || counters[3].ServiceID != "shadowsocks-aead" {
		t.Fatalf("CollectTraffic() = %+v, %v", counters, err)
	}
	activity, err := runtime.CollectActivity(ctx, 0, 10)
	if err != nil || len(activity.Events) != 0 || activity.NextSequence != 0 {
		t.Fatalf("CollectActivity() = %+v, %v", activity, err)
	}
	blocks := []xrayruntime.DynamicBlock{
		{
			AuthorizationID: authorizationID, ServiceID: "reality-main", SourceIP: "192.0.2.1",
			ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(),
		},
		{
			AuthorizationID: authorizationID, ServiceID: "reality-backup", SourceIP: "192.0.2.1",
			ExpiresAtUnixNano: time.Now().Add(time.Hour).UnixNano(),
		},
	}
	if err := runtime.ApplyDynamicBlocks(ctx, 1, 1, blocks); err != nil {
		t.Fatalf("ApplyDynamicBlocks() error = %v", err)
	}
	if err := runtime.ApplyDynamicBlocks(ctx, 1, 2, nil); err != nil {
		t.Fatalf("clear ApplyDynamicBlocks() error = %v", err)
	}
	closeContext, closeCancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer closeCancel()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func waitForTCP(t *testing.T, port uint16) {
	t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Xray listener %s is not reachable", address)
}

func integrationDataDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	t.Cleanup(func() {
		if err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return nil
		}); err != nil {
			t.Errorf("restore temporary directory permissions: %v", err)
		}
	})
	return directory
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}
