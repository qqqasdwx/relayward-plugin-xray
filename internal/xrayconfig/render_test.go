package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestRenderManagedServicesAndEgressLines(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration()
	raw, err := Render(configuration)
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		DNS       map[string]any   `json:"dns"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Routing   struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatal(err)
	}
	if rendered.DNS["queryStrategy"] != "UseIP" || len(rendered.DNS["servers"].([]any)) != 1 {
		t.Fatalf("managed DNS = %+v", rendered.DNS)
	}
	api := findTagged(t, rendered.Inbounds, APIRuleTag)
	if api["listen"] != "127.0.0.1" || api["port"] != float64(config.ManagedAPIPort) {
		t.Fatalf("API inbound = %+v", api)
	}
	vless := findTagged(t, rendered.Inbounds, "reality-main")
	if _, exists := vless["listen"]; exists || vless["port"] != float64(24443) || vless["protocol"] != "vless" {
		t.Fatalf("VLESS inbound = %+v", vless)
	}
	vlessSettings := vless["settings"].(map[string]any)
	stream := vless["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	rawSettings := stream["rawSettings"].(map[string]any)
	if vlessSettings["decryption"] != "none" || stream["method"] != "raw" || stream["security"] != "reality" ||
		rawSettings["acceptProxyProtocol"] != true || reality["xver"] != float64(2) ||
		reality["minClientVer"] != "1.0.0" || reality["privateKey"] != configuration.Services[0].VLESSReality.PrivateKey ||
		reality["shortIds"].([]any)[0] != configuration.Services[0].VLESSReality.ShortID {
		t.Fatalf("VLESS settings = %+v", vless)
	}
	tunnelPort, err := strconv.Atoi(strings.TrimPrefix(reality["target"].(string), "127.0.0.1:"))
	if err != nil || tunnelPort < realityTunnelPortStart {
		t.Fatalf("REALITY target = %q", reality["target"])
	}
	tunnel := findTagged(t, rendered.Inbounds, realityTunnelTag("reality-main"))
	tunnelSettings := tunnel["settings"].(map[string]any)
	tunnelStream := tunnel["streamSettings"].(map[string]any)
	if tunnel["listen"] != "127.0.0.1" || tunnel["port"] != float64(tunnelPort) || tunnel["protocol"] != "tunnel" ||
		tunnelSettings["rewriteAddress"] != "www.tesla.com" || tunnelSettings["rewritePort"] != float64(443) ||
		tunnelStream["rawSettings"].(map[string]any)["acceptProxyProtocol"] != true {
		t.Fatalf("REALITY tunnel = %+v", tunnel)
	}
	shadowsocks := findTagged(t, rendered.Inbounds, "shadowsocks-main")
	ssSettings := shadowsocks["settings"].(map[string]any)
	if shadowsocks["protocol"] != "shadowsocks" || ssSettings["network"] != "tcp,udp" ||
		ssSettings["method"] != config.ShadowsocksMethod2022AES256 || len(ssSettings["clients"].([]any)) != 1 {
		t.Fatalf("Shadowsocks inbound = %+v", shadowsocks)
	}

	defaultOutbound := findTagged(t, rendered.Outbounds, config.EgressOutboundTag(config.DefaultEgressLineID))
	if defaultOutbound["protocol"] != "freedom" {
		t.Fatalf("default outbound = %+v", defaultOutbound)
	}
	ipv6Outbound := findTagged(t, rendered.Outbounds, config.EgressOutboundTag("ipv6"))
	if ipv6Outbound["sendThrough"] != "2001:db8::10" ||
		ipv6Outbound["settings"].(map[string]any)["domainStrategy"] != "UseIPv6" {
		t.Fatalf("IPv6 outbound = %+v", ipv6Outbound)
	}
	socksOutbound := findTagged(t, rendered.Outbounds, config.EgressOutboundTag("socks-us"))
	if socksOutbound["protocol"] != "socks" || socksOutbound["settings"].(map[string]any)["user"] != "alice" {
		t.Fatalf("SOCKS outbound = %+v", socksOutbound)
	}
	ssOutbound := findTagged(t, rendered.Outbounds, config.EgressOutboundTag("ss-jp"))
	if ssOutbound["protocol"] != "shadowsocks" || ssOutbound["settings"].(map[string]any)["password"] != "server-password" {
		t.Fatalf("Shadowsocks outbound = %+v", ssOutbound)
	}
	if findTagged(t, rendered.Outbounds, SystemDirectOutboundTag)["protocol"] != "freedom" ||
		findTagged(t, rendered.Outbounds, BlockedOutboundTag)["protocol"] != "blackhole" {
		t.Fatalf("managed outbounds = %+v", rendered.Outbounds)
	}
}

func TestInternalPortsAreStableAndAvoidManagedListeners(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration()
	first, exists, err := DiagnosticPort(configuration, "ipv6")
	if err != nil || !exists {
		t.Fatalf("DiagnosticPort() = %d, %t, %v", first, exists, err)
	}
	second, _, err := DiagnosticPort(configuration, "ipv6")
	if err != nil || first != second {
		t.Fatalf("DiagnosticPort() is unstable: %d, %d, %v", first, second, err)
	}
	for _, service := range configuration.Services {
		if first == service.Port {
			t.Fatalf("diagnostic port %d conflicts with service %q", first, service.ServiceID)
		}
	}
	if _, exists, err := DiagnosticPort(configuration, "missing"); err != nil || exists {
		t.Fatalf("DiagnosticPort(missing) = %t, %v", exists, err)
	}
}

func findTagged(t *testing.T, values []map[string]any, tag string) map[string]any {
	t.Helper()
	for _, value := range values {
		if value["tag"] == tag {
			return value
		}
	}
	t.Fatalf("tag %q not found in %+v", tag, values)
	return nil
}

func testConfiguration() config.Configuration {
	return config.Configuration{
		XrayVersion: "26.7.28", APIPort: config.ManagedAPIPort,
		CredentialSeed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Services: []config.Service{
			{
				Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main",
				DisplayName: "Reality Main", Port: 24443, AcceptProxyProtocol: true,
				VLESSReality: &config.VLESSReality{
					Target: "www.tesla.com:443", PrivateKey: "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
					ShortID: "0011223344556677",
				},
			},
			{
				Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main",
				DisplayName: "Shadowsocks Main", Port: 28443,
				Shadowsocks: &config.Shadowsocks{
					Method:    config.ShadowsocksMethod2022AES256,
					ServerKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))),
				},
			},
		},
		EgressLines: []config.EgressLine{
			{
				LineID: config.DefaultEgressLineID, DisplayName: "Default", Enabled: true,
				Type: config.EgressTypeDirect, Direct: &config.DirectEgress{},
			},
			{
				LineID: "ipv6", DisplayName: "IPv6", Enabled: true, VLESSRoute: 6,
				Type: config.EgressTypeDirect, Direct: &config.DirectEgress{SendThrough: "2001:db8::10"},
			},
			{
				LineID: "socks-us", DisplayName: "SOCKS US", Enabled: true, VLESSRoute: 10,
				Type:   config.EgressTypeSOCKS5,
				SOCKS5: &config.SOCKS5Egress{Address: "proxy.example.com", Port: 1080, Username: "alice", Password: "secret"},
			},
			{
				LineID: "ss-jp", DisplayName: "SS JP", Enabled: true, VLESSRoute: 20,
				Type: config.EgressTypeShadowsocks,
				Shadowsocks: &config.ShadowsocksEgress{
					Address: "ss.example.com", Port: 8388, Method: config.ShadowsocksMethod2022AES256, Password: "server-password",
				},
			},
		},
	}
}
