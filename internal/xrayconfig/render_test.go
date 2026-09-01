package xrayconfig

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestRenderBuildsTypedServiceInbounds(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.Routing = config.RoutingConfiguration{Rules: []config.RoutingRule{
		{
			RuleID: "block-private", DisplayName: "Block private", Enabled: true,
			SourceIPs: []string{"198.51.100.10"}, SourcePort: "1000-2000", VLESSRoute: "8443",
			Network: "tcp", Attributes: map[string]string{"user-agent": "curl.*"},
			DestinationIPs: []string{"192.0.2.0/24"}, DestinationPort: "443",
			Users: []string{"relayward:test"}, InboundTags: []string{"reality-main"},
			OutboundTag: config.RoutingOutboundBlocked,
		},
		{
			RuleID: "allow-example", DisplayName: "Allow example", Enabled: true,
			Domains: []string{"domain:example.com"}, Protocols: []string{"tls"}, OutboundTag: config.RoutingOutboundDirect,
		},
	}}
	value.DNS = config.DNSConfiguration{
		Enabled: true, QueryStrategy: config.DNSQueryStrategyUseIPv4,
		Servers: []config.DNSServer{
			{
				ServerID: "regional", DisplayName: "Regional DNS", Enabled: true,
				Transport: config.DNSTransportUDP, Address: "1.1.1.1", Port: 53,
				Domains: []string{"example.com"},
			},
			{ServerID: "system", DisplayName: "System DNS", Enabled: true, Transport: config.DNSTransportSystem},
			{
				ServerID: "disabled", DisplayName: "Disabled DNS", Enabled: false,
				Transport: config.DNSTransportDoH, Address: "https://dns.google/dns-query",
			},
		},
	}
	raw, err := Render(value)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("Render() = %s, %v", raw, err)
	}
	var generated struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
		Inbounds []struct {
			Tag            string `json:"tag"`
			Protocol       string `json:"protocol"`
			StreamSettings struct {
				RealitySettings struct {
					Target string `json:"target"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
			Sniffing struct {
				Enabled      bool     `json:"enabled"`
				DestOverride []string `json:"destOverride"`
				RouteOnly    bool     `json:"routeOnly"`
			} `json:"sniffing"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				DomainStrategy string `json:"domainStrategy"`
			} `json:"settings"`
		} `json:"outbounds"`
		DNS struct {
			QueryStrategy          string `json:"queryStrategy"`
			DisableFallbackIfMatch bool   `json:"disableFallbackIfMatch"`
			Servers                []struct {
				Address       string   `json:"address"`
				Port          uint16   `json:"port"`
				Domains       []string `json:"domains"`
				QueryStrategy string   `json:"queryStrategy"`
				SkipFallback  bool     `json:"skipFallback"`
			} `json:"servers"`
		} `json:"dns"`
		Policy struct {
			Levels map[string]struct {
				StatsUserOnline bool `json:"statsUserOnline"`
			} `json:"levels"`
		} `json:"policy"`
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				RuleTag     string            `json:"ruleTag"`
				OutboundTag string            `json:"outboundTag"`
				Domain      []string          `json:"domain"`
				IP          []string          `json:"ip"`
				Protocol    []string          `json:"protocol"`
				InboundTag  []string          `json:"inboundTag"`
				SourceIP    []string          `json:"sourceIP"`
				SourcePort  string            `json:"sourcePort"`
				VLESSRoute  string            `json:"vlessRoute"`
				Network     string            `json:"network"`
				Port        string            `json:"port"`
				User        []string          `json:"user"`
				Attributes  map[string]string `json:"attrs"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.API.Services) != 3 || generated.API.Services[1] != "RoutingService" ||
		len(generated.Inbounds) != 5 || generated.Inbounds[1].Tag != "reality-backup" ||
		generated.Inbounds[1].Protocol != "vless" ||
		generated.Inbounds[1].StreamSettings.RealitySettings.Target == "www.cloudflare.com:443" ||
		!generated.Inbounds[1].Sniffing.Enabled || !generated.Inbounds[1].Sniffing.RouteOnly ||
		len(generated.Inbounds[1].Sniffing.DestOverride) != 3 ||
		generated.Inbounds[2].Tag != realityTunnelTag("reality-backup") || generated.Inbounds[2].Protocol != "tunnel" ||
		generated.Inbounds[3].Tag != "reality-main" || generated.Inbounds[4].Tag != realityTunnelTag("reality-main") ||
		len(generated.Outbounds) != 2 ||
		generated.Outbounds[1].Tag != "blocked" || generated.Outbounds[1].Protocol != "blackhole" ||
		generated.Outbounds[0].Settings.DomainStrategy != "AsIs" ||
		!generated.Policy.Levels["0"].StatsUserOnline {
		t.Fatalf("generated Xray configuration = %+v", generated)
	}
	if len(generated.Routing.Rules) != 7 || generated.Routing.Rules[0].RuleTag != APIRuleTag ||
		generated.Routing.DomainStrategy != "IPIfNonMatch" ||
		generated.Routing.Rules[1].RuleTag != realityTunnelAllowRuleTag("reality-backup") ||
		generated.Routing.Rules[1].Domain[0] != "full:www.cloudflare.com" ||
		generated.Routing.Rules[2].RuleTag != realityTunnelBlockRuleTag("reality-backup") ||
		generated.Routing.Rules[5].RuleTag != "relayward-static-block-private" ||
		generated.Routing.Rules[5].IP[0] != "192.0.2.0/24" ||
		generated.Routing.Rules[5].SourceIP[0] != "198.51.100.10" ||
		generated.Routing.Rules[5].SourcePort != "1000-2000" || generated.Routing.Rules[5].VLESSRoute != "8443" ||
		generated.Routing.Rules[5].Network != "tcp" || generated.Routing.Rules[5].Port != "443" ||
		generated.Routing.Rules[5].User[0] != "relayward:test" || generated.Routing.Rules[5].InboundTag[0] != "reality-main" ||
		generated.Routing.Rules[5].Attributes["user-agent"] != "curl.*" ||
		generated.Routing.Rules[6].Domain[0] != "domain:example.com" ||
		generated.Routing.Rules[6].Protocol[0] != "tls" || len(generated.Routing.Rules[6].InboundTag) != 0 {
		t.Fatalf("generated routing configuration = %+v", generated.Routing)
	}
	if generated.DNS.QueryStrategy != "UseIPv4" || !generated.DNS.DisableFallbackIfMatch ||
		len(generated.DNS.Servers) != 2 || generated.DNS.Servers[0].Address != "1.1.1.1" ||
		generated.DNS.Servers[0].Port != 53 || generated.DNS.Servers[0].Domains[0] != "domain:example.com" ||
		!generated.DNS.Servers[0].SkipFallback || generated.DNS.Servers[1].Address != "localhost" ||
		generated.DNS.Servers[1].QueryStrategy != "UseIPv4" {
		t.Fatalf("generated DNS configuration = %+v", generated.DNS)
	}
}

func TestRenderOmitsDisabledServices(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.Services[1].Enabled = false
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Inbounds []struct {
			Sniffing json.RawMessage `json:"sniffing"`
		} `json:"inbounds"`
		DNS       json.RawMessage `json:"dns"`
		Outbounds []struct {
			Settings struct {
				DomainStrategy string `json:"domainStrategy"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.Inbounds) != 3 {
		t.Fatalf("inbounds = %d, want API plus one VLESS and its tunnel", len(generated.Inbounds))
	}
	if len(generated.DNS) != 0 || generated.Outbounds[0].Settings.DomainStrategy != "AsIs" {
		t.Fatal("disabled DNS unexpectedly changed the Xray configuration")
	}
}

func TestRenderBuildsFreedomAndBlackholeOutbounds(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.Outbounds = append(value.Outbounds,
		config.Outbound{
			Tag: "IPv4", Protocol: config.OutboundProtocolFreedom,
			Freedom: &config.FreedomOutboundSettings{
				DomainStrategy: "UseIPv4", Redirect: "127.0.0.1:1080", UserLevel: 1, ProxyProtocol: 2,
				Fragment:   &config.FreedomFragment{Packets: "tlshello", Length: "100-200", Interval: "10-20", MaxSplit: "300-400"},
				Noises:     []config.FreedomNoise{{Type: "rand", Packet: "10-20", Delay: "10-16", ApplyTo: "ipv4"}},
				FinalRules: []config.FreedomFinalRule{{Action: "block", Network: "tcp", Port: "443", IPs: []string{"geoip:private"}, BlockDelay: "5000-10000"}},
			},
		},
		config.Outbound{Tag: "ads_blocked", Protocol: config.OutboundProtocolBlackhole, Blackhole: &config.BlackholeOutboundSettings{ResponseType: "http"}},
	)
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Outbounds []struct {
			Tag      string         `json:"tag"`
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.Outbounds) != 4 || generated.Outbounds[2].Tag != "IPv4" || generated.Outbounds[2].Protocol != "freedom" ||
		generated.Outbounds[2].Settings["domainStrategy"] != "UseIPv4" || generated.Outbounds[2].Settings["redirect"] != "127.0.0.1:1080" ||
		generated.Outbounds[2].Settings["proxyProtocol"] != float64(2) || len(generated.Outbounds[2].Settings["finalRules"].([]any)) != 1 ||
		generated.Outbounds[3].Tag != "ads_blocked" || generated.Outbounds[3].Protocol != "blackhole" {
		t.Fatalf("rendered outbounds = %+v", generated.Outbounds)
	}
	response := generated.Outbounds[3].Settings["response"].(map[string]any)
	if response["type"] != "http" {
		t.Fatalf("blackhole response = %+v", response)
	}
}

func TestRenderShadowsocks2022Inbound(t *testing.T) {
	t.Parallel()
	value, err := config.NewConfiguration("26.7.28", 10085, []config.EditableService{{
		Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main", DisplayName: "Shadowsocks Main",
		Listen: "0.0.0.0", Port: 8388,
		Shadowsocks: &config.EditableShadowsocks{
			Method: config.ShadowsocksMethod2022AES256, Network: config.ShadowsocksNetworkTCPUDP,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Inbounds []struct {
			Tag      string         `json:"tag"`
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.Inbounds) != 2 || generated.Inbounds[1].Tag != "shadowsocks-main" ||
		generated.Inbounds[1].Protocol != "shadowsocks" ||
		generated.Inbounds[1].Settings["method"] != config.ShadowsocksMethod2022AES256 ||
		generated.Inbounds[1].Settings["password"] != value.Services[0].Shadowsocks.ServerKey ||
		generated.Inbounds[1].Settings["network"] != config.ShadowsocksNetworkTCPUDP ||
		len(generated.Inbounds[1].Settings["clients"].([]any)) != 1 ||
		generated.Inbounds[1].Settings["clients"].([]any)[0].(map[string]any)["email"] != "relayward:bootstrap:shadowsocks-main" {
		t.Fatalf("generated Shadowsocks inbound = %s", raw)
	}
}

func TestRenderVLESSRealityStaticContract(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	service := &value.Services[0]
	service.TCP.AcceptProxyProtocol = true
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var inbound, tunnel map[string]any
	for _, candidate := range root["inbounds"].([]any) {
		item := candidate.(map[string]any)
		if item["tag"] == service.ServiceID {
			inbound = item
		}
		if item["tag"] == realityTunnelTag(service.ServiceID) {
			tunnel = item
		}
	}
	if inbound == nil || tunnel == nil {
		t.Fatal("rendered VLESS inbound or tunnel was not found")
	}
	settings := inbound["settings"].(map[string]any)
	stream := inbound["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	rawSettings := stream["rawSettings"].(map[string]any)
	if len(settings) != 1 || settings["decryption"] != "none" || stream["method"] != "raw" || stream["security"] != "reality" ||
		len(stream) != 4 || rawSettings["acceptProxyProtocol"] != true || reality["minClientVer"] != "1.0.0" ||
		reality["xver"] != float64(2) ||
		reality["serverNames"].([]any)[0] != "www.cloudflare.com" || reality["shortIds"].([]any)[0] != service.VLESSReality.ShortIDs[0] ||
		reality["limitFallbackUpload"].(map[string]any)["afterBytes"] != float64(10*1024*1024) ||
		reality["limitFallbackDownload"].(map[string]any)["bytesPerSec"] != float64(1024*1024) {
		t.Fatalf("rendered VLESS inbound = %s", raw)
	}
	for _, field := range []string{"network", "tcpSettings", "sockopt", "finalmask"} {
		if _, exists := stream[field]; exists {
			t.Fatalf("streamSettings unexpectedly contains %q: %s", field, raw)
		}
	}
	for _, field := range []string{"show", "masterKeyLog", "mldsa65Seed", "maxClientVer", "maxTimeDiff"} {
		if _, exists := reality[field]; exists {
			t.Fatalf("realitySettings unexpectedly contains %q: %s", field, raw)
		}
	}
	tunnelPort := uint16(tunnel["port"].(float64))
	targetHost, targetPort, err := net.SplitHostPort(reality["target"].(string))
	if err != nil || targetHost != "127.0.0.1" || targetPort != strconv.Itoa(int(tunnelPort)) ||
		tunnel["listen"] != "127.0.0.1" || tunnel["protocol"] != "tunnel" {
		t.Fatalf("rendered REALITY tunnel = %s", raw)
	}
	tunnelSettings := tunnel["settings"].(map[string]any)
	tunnelStream := tunnel["streamSettings"].(map[string]any)
	tunnelRawSettings := tunnelStream["rawSettings"].(map[string]any)
	if tunnelSettings["rewriteAddress"] != "www.cloudflare.com" || tunnelSettings["rewritePort"] != float64(443) ||
		tunnelSettings["allowedNetwork"] != "tcp" || tunnelStream["method"] != "raw" ||
		tunnelStream["security"] != "none" || tunnelRawSettings["acceptProxyProtocol"] != true {
		t.Fatalf("rendered REALITY tunnel settings = %s", raw)
	}
}

func TestRenderVLESSRealityGoldenConfiguration(t *testing.T) {
	t.Parallel()
	value := config.Configuration{
		XrayVersion: "26.7.28", APIPort: 10085,
		CredentialSeed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Services: []config.Service{{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "vless-main", DisplayName: "VLESS Main",
			Listen: "0.0.0.0", Port: 54321,
			TCP:      config.TCPSettings{AcceptProxyProtocol: true, Header: config.TCPHeader{Type: config.TCPHeaderNone}},
			Sniffing: config.Sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}, RouteOnly: true},
			VLESSReality: &config.VLESSReality{
				Decryption: "none", Encryption: "none", Xver: 2, Target: "addons.mozilla.org:443",
				ServerNames: []string{"addons.mozilla.org"},
				PrivateKey:  "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
				ShortIDs:    []string{"0011223344556677"}, MinClientVersion: "1.0.0",
				Flow: config.VLESSVisionFlow, Fingerprint: "chrome", SpiderX: "/",
			},
		}},
		Outbounds: config.DefaultOutbounds(),
	}
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted.WriteByte('\n')
	expected, err := os.ReadFile("testdata/vless_reality.golden.json")
	if err != nil {
		t.Fatalf("read golden configuration: %v\ngenerated:\n%s", err, formatted.Bytes())
	}
	if !bytes.Equal(formatted.Bytes(), expected) {
		t.Fatalf("generated VLESS configuration does not match testdata/vless_reality.golden.json\ngenerated:\n%s", formatted.Bytes())
	}
}

func TestRenderDNSLocalTransports(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.DNS = config.DNSConfiguration{
		Enabled: true, QueryStrategy: config.DNSQueryStrategyUseIPv6,
		Servers: []config.DNSServer{
			{ServerID: "tcp", DisplayName: "TCP", Enabled: true, Transport: config.DNSTransportTCP, Address: "2001:4860:4860::8888", Port: 53},
			{ServerID: "doh", DisplayName: "DoH", Enabled: true, Transport: config.DNSTransportDoH, Address: "https://dns.google/dns-query"},
		},
	}
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		DNS struct {
			Servers []struct {
				Address string `json:"address"`
			} `json:"servers"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.DNS.Servers) != 2 || generated.DNS.Servers[0].Address != "tcp+local://[2001:4860:4860::8888]" ||
		generated.DNS.Servers[1].Address != "https+local://dns.google/dns-query" {
		t.Fatalf("generated DNS transports = %+v", generated.DNS.Servers)
	}
}

func TestSupportsOnlyRegisteredServiceTypes(t *testing.T) {
	t.Parallel()
	if !SupportsServiceType(config.ServiceTypeVLESSReality) || !SupportsServiceType(config.ServiceTypeShadowsocks) || SupportsServiceType("unknown") {
		t.Fatal("Xray renderer service type support is inconsistent")
	}
}

func testConfiguration(t *testing.T) config.Configuration {
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
	return value
}
