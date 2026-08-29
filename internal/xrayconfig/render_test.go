package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestRenderBuildsTypedServiceInbounds(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.Routing = config.RoutingConfiguration{Rules: []config.RoutingRule{
		{
			RuleID: "block-private", DisplayName: "Block private", Enabled: true,
			IPCIDRs: []string{"192.0.2.0/24"}, Action: config.RoutingActionBlocked,
		},
		{
			RuleID: "allow-example", DisplayName: "Allow example", Enabled: true,
			Domains: []string{"example.com"}, Protocols: []string{"tls"}, Action: config.RoutingActionDirect,
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
				RuleTag     string   `json:"ruleTag"`
				OutboundTag string   `json:"outboundTag"`
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				Protocol    []string `json:"protocol"`
				InboundTag  []string `json:"inboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	if len(generated.API.Services) != 3 || generated.API.Services[1] != "RoutingService" ||
		len(generated.Inbounds) != 3 || generated.Inbounds[1].Tag != "reality-backup" ||
		generated.Inbounds[1].Protocol != "vless" ||
		generated.Inbounds[1].StreamSettings.RealitySettings.Target != "www.cloudflare.com:443" ||
		!generated.Inbounds[1].Sniffing.Enabled || !generated.Inbounds[1].Sniffing.RouteOnly ||
		len(generated.Inbounds[1].Sniffing.DestOverride) != 3 ||
		generated.Inbounds[2].Tag != "reality-main" || len(generated.Outbounds) != 2 ||
		generated.Outbounds[1].Tag != "blocked" || generated.Outbounds[1].Protocol != "blackhole" ||
		generated.Outbounds[0].Settings.DomainStrategy != "UseIPv4" ||
		!generated.Policy.Levels["0"].StatsUserOnline {
		t.Fatalf("generated Xray configuration = %+v", generated)
	}
	if len(generated.Routing.Rules) != 3 || generated.Routing.Rules[0].RuleTag != APIRuleTag ||
		generated.Routing.DomainStrategy != "IPIfNonMatch" ||
		generated.Routing.Rules[1].RuleTag != "relayward-static-block-private" ||
		generated.Routing.Rules[1].IP[0] != "192.0.2.0/24" ||
		generated.Routing.Rules[2].Domain[0] != "domain:example.com" ||
		generated.Routing.Rules[2].Protocol[0] != "tls" || len(generated.Routing.Rules[2].InboundTag) != 2 {
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
	if len(generated.Inbounds) != 2 {
		t.Fatalf("inbounds = %d, want API plus one enabled service", len(generated.Inbounds))
	}
	if len(generated.Inbounds[1].Sniffing) != 0 {
		t.Fatal("disabled or absent domain routing unexpectedly enabled sniffing")
	}
	if len(generated.DNS) != 0 || generated.Outbounds[0].Settings.DomainStrategy != "" {
		t.Fatal("disabled DNS unexpectedly changed the Xray configuration")
	}
}

func TestRenderShadowsocks2022Inbound(t *testing.T) {
	t.Parallel()
	value, err := config.NewConfiguration("26.3.27", 10085, []config.EditableService{{
		Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main", DisplayName: "Shadowsocks Main",
		Listen: "0.0.0.0", Port: 8388, PublicHost: "ss.example.com", PublicPort: 8388,
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

func TestRenderAppliesInboundTransportRealityAndSniffingSettings(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	service := &value.Services[0]
	service.TCP = config.TCPSettings{
		AcceptProxyProtocol: true,
		Header: config.TCPHeader{Type: config.TCPHeaderHTTP,
			Request:  &config.TCPHTTPRequest{Version: "1.1", Method: "GET", Path: []string{"/edge"}, Headers: map[string][]string{"Host": {"addons.mozilla.org"}}},
			Response: &config.TCPHTTPResponse{Version: "1.1", Status: "200", Reason: "OK", Headers: map[string][]string{"Content-Type": {"text/html"}}},
		},
	}
	service.Sniffing = config.Sniffing{
		Enabled: true, DestOverride: []string{"http", "tls"}, MetadataOnly: true,
		RouteOnly: true, IPsExcluded: []string{"geoip:private"}, DomainsExcluded: []string{"domain:example.com"},
	}
	service.VLESSReality.Show = true
	service.VLESSReality.Xver = 2
	service.VLESSReality.MinClientVersion = "1.0.0"
	service.VLESSReality.MaxClientVersion = "26.3.27"
	service.VLESSReality.MaxTimeDiff = 1000
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Inbounds []struct {
			Tag            string `json:"tag"`
			StreamSettings struct {
				TCPSettings struct {
					AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
					Header              struct {
						Type    string `json:"type"`
						Request struct {
							Path []string `json:"path"`
						} `json:"request"`
					} `json:"header"`
				} `json:"tcpSettings"`
				RealitySettings struct {
					Show             bool   `json:"show"`
					Xver             uint8  `json:"xver"`
					MinClientVersion string `json:"minClientVer"`
					MaxClientVersion string `json:"maxClientVer"`
					MaxTimeDiff      uint64 `json:"maxTimeDiff"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
			Sniffing struct {
				Enabled      bool     `json:"enabled"`
				MetadataOnly bool     `json:"metadataOnly"`
				IPsExcluded  []string `json:"ipsExcluded"`
			} `json:"sniffing"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	var inbound *struct {
		Tag            string `json:"tag"`
		StreamSettings struct {
			TCPSettings struct {
				AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
				Header              struct {
					Type    string `json:"type"`
					Request struct {
						Path []string `json:"path"`
					} `json:"request"`
				} `json:"header"`
			} `json:"tcpSettings"`
			RealitySettings struct {
				Show             bool   `json:"show"`
				Xver             uint8  `json:"xver"`
				MinClientVersion string `json:"minClientVer"`
				MaxClientVersion string `json:"maxClientVer"`
				MaxTimeDiff      uint64 `json:"maxTimeDiff"`
			} `json:"realitySettings"`
		} `json:"streamSettings"`
		Sniffing struct {
			Enabled      bool     `json:"enabled"`
			MetadataOnly bool     `json:"metadataOnly"`
			IPsExcluded  []string `json:"ipsExcluded"`
		} `json:"sniffing"`
	}
	for index := range generated.Inbounds {
		if generated.Inbounds[index].Tag == service.ServiceID {
			inbound = &generated.Inbounds[index]
		}
	}
	if inbound == nil || !inbound.StreamSettings.TCPSettings.AcceptProxyProtocol || inbound.StreamSettings.TCPSettings.Header.Type != "http" ||
		inbound.StreamSettings.TCPSettings.Header.Request.Path[0] != "/edge" || !inbound.StreamSettings.RealitySettings.Show ||
		inbound.StreamSettings.RealitySettings.Xver != 2 || inbound.StreamSettings.RealitySettings.MinClientVersion != "1.0.0" ||
		inbound.StreamSettings.RealitySettings.MaxClientVersion != "26.3.27" || inbound.StreamSettings.RealitySettings.MaxTimeDiff != 1000 ||
		!inbound.Sniffing.Enabled || !inbound.Sniffing.MetadataOnly || inbound.Sniffing.IPsExcluded[0] != "geoip:private" {
		t.Fatalf("generated inbound = %+v", inbound)
	}
}

func TestRenderEmitsCompleteSupportedInboundSettings(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	service := &value.Services[0]
	service.Sockopt = &config.SocketSettings{
		Mark: 10, TCPFastOpen: true, TProxy: config.TProxyRedirect, AcceptProxyProtocol: true,
		TCPMPTCP: true, TCPKeepAliveInterval: 15, TCPKeepAliveIdle: 300,
		TCPMaxSeg: 1440, TCPUserTimeout: 10000, TCPWindowClamp: 600,
		TCPCongestion: "cubic", V6Only: true,
		Custom: []config.CustomSockopt{{System: "linux", Network: "tcp4", Level: "6", Opt: "19", Type: "int", Value: "1"}},
	}
	service.VLESSReality.TestSeed = []uint32{900, 500, 900, 256}
	service.VLESSReality.Fallbacks = []config.VLESSFallback{{Name: "fallback.example.com", ALPN: "http/1.1", Path: "/edge", Dest: "127.0.0.1:8080", Xver: 1}}
	service.VLESSReality.MLDSA65Seed = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	service.VLESSReality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("v", 1952)))
	service.VLESSReality.MasterKeyLog = "/tmp/relayward-xray.keys"
	service.VLESSReality.LimitFallbackUpload = &config.RealityLimitFallback{AfterBytes: 1024, BytesPerSec: 2048, BurstBytesPerSec: 4096}
	service.VLESSReality.LimitFallbackDownload = &config.RealityLimitFallback{AfterBytes: 2048, BytesPerSec: 4096, BurstBytesPerSec: 8192}
	raw, err := Render(value)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var inbound map[string]any
	for _, candidate := range root["inbounds"].([]any) {
		item := candidate.(map[string]any)
		if item["tag"] == service.ServiceID {
			inbound = item
			break
		}
	}
	if inbound == nil {
		t.Fatal("rendered inbound was not found")
	}
	settings := inbound["settings"].(map[string]any)
	stream := inbound["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	sockopt := stream["sockopt"].(map[string]any)
	fallback := settings["fallbacks"].([]any)[0].(map[string]any)
	custom := sockopt["customSockopt"].([]any)[0].(map[string]any)
	if settings["decryption"] != "none" || len(settings["testseed"].([]any)) != 4 || fallback["dest"] != "127.0.0.1:8080" ||
		reality["mldsa65Seed"] != service.VLESSReality.MLDSA65Seed || reality["masterKeyLog"] != "/tmp/relayward-xray.keys" ||
		reality["limitFallbackUpload"].(map[string]any)["bytesPerSec"] != float64(2048) ||
		sockopt["tcpCongestion"] != "cubic" || sockopt["v6only"] != true || sockopt["tcpMptcp"] != true ||
		sockopt["tcpKeepAliveIdle"] != float64(300) || custom["opt"] != "19" || custom["network"] != "tcp4" {
		t.Fatalf("rendered complete inbound = %s", raw)
	}
	if _, exists := sockopt["tcpcongestion"]; exists {
		t.Fatalf("renderer used non-canonical tcpcongestion key: %s", raw)
	}
	if _, exists := sockopt["V6Only"]; exists {
		t.Fatalf("renderer used non-canonical V6Only key: %s", raw)
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
	value, err := config.NewConfiguration("26.3.27", 10085, []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "0.0.0.0", Port: 443, PublicHost: "edge.example.com", PublicPort: 443,
			VLESSReality: &config.EditableVLESSReality{
				Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, Fingerprint: "chrome",
			},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "0.0.0.0", Port: 8443, PublicHost: "backup.example.com", PublicPort: 8443,
			VLESSReality: &config.EditableVLESSReality{
				Target: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}, Fingerprint: "chrome",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
