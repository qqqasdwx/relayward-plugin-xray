package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestConfigurationRoundTripsTypedServicesAndStableCredentials(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.3.27", 10085, testEditableServices())
	if err != nil {
		t.Fatal(err)
	}
	value.Routing = testRoutingConfiguration()
	value.DNS = testDNSConfiguration()
	raw, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.XrayVersion != "26.3.27" || len(decoded.Services) != 2 || decoded.Services[0].ServiceID != "reality-backup" ||
		decoded.Services[1].ServiceID != "reality-main" || len(decoded.Routing.Rules) != 2 ||
		decoded.Routing.Rules[0].RuleID != "block-private" || !decoded.DNS.Enabled ||
		len(decoded.DNS.Servers) != 2 || decoded.DNS.Servers[0].ServerID != "regional" {
		t.Fatalf("configuration = %+v", decoded)
	}
	first, err := DeriveCredential(decoded.CredentialSeed, "10000000-0000-4000-8000-000000000001", "reality-main")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := DeriveCredential(decoded.CredentialSeed, "10000000-0000-4000-8000-000000000001", "reality-main")
	otherService, _ := DeriveCredential(decoded.CredentialSeed, "10000000-0000-4000-8000-000000000001", "reality-backup")
	otherAuthorization, _ := DeriveCredential(decoded.CredentialSeed, "20000000-0000-4000-8000-000000000002", "reality-main")
	if first != second || first == otherService || first == otherAuthorization {
		t.Fatalf("derived credentials = %q, %q, %q, %q", first, second, otherService, otherAuthorization)
	}
	for _, service := range decoded.Services {
		publicKey, err := RealityPublicKey(service.VLESSReality.PrivateKey)
		if err != nil || len(publicKey) != 43 {
			t.Fatalf("RealityPublicKey(%q) = %q, %v", service.ServiceID, publicKey, err)
		}
	}
}

func TestConfigurationRoundTripsCompleteInboundSettings(t *testing.T) {
	t.Parallel()
	editable := testEditableServices()[:1]
	service := &editable[0]
	service.TCP = TCPSettings{
		AcceptProxyProtocol: true,
		Header: TCPHeader{Type: TCPHeaderHTTP,
			Request: &TCPHTTPRequest{Version: "1.1", Method: "GET", Path: []string{"/edge"}, Headers: map[string][]string{
				"Host": {"addons.mozilla.org"},
			}},
			Response: &TCPHTTPResponse{Version: "1.1", Status: "200", Reason: "OK", Headers: map[string][]string{
				"Content-Type": {"text/html"},
			}},
		},
	}
	service.Sockopt = &SocketSettings{
		Mark: 10, TCPFastOpen: true, TProxy: TProxyRedirect, AcceptProxyProtocol: true,
		TCPMPTCP: true, TCPKeepAliveInterval: 15, TCPKeepAliveIdle: 300,
		TCPMaxSeg: 1440, TCPUserTimeout: 10000, TCPWindowClamp: 600,
		TCPCongestion: "cubic", V6Only: true,
		Custom: []CustomSockopt{{System: "linux", Network: "tcp4", Level: "6", Opt: "19", Type: "int", Value: "1"}},
	}
	service.Sniffing = Sniffing{
		Enabled: true, DestOverride: []string{"http", "tls", "quic", "fakedns"},
		MetadataOnly: true, RouteOnly: true, IPsExcluded: []string{"geoip:private"},
		DomainsExcluded: []string{"domain:example.com"},
	}
	service.VLESSReality.TestSeed = []uint32{900, 500, 900, 256}
	service.VLESSReality.Fallbacks = []VLESSFallback{{Name: "fallback.example.com", ALPN: "http/1.1", Path: "/fallback", Dest: "127.0.0.1:8080", Xver: 1}}
	service.VLESSReality.Show = true
	service.VLESSReality.Xver = 1
	service.VLESSReality.ServerNames = []string{"addons.mozilla.org", "www.mozilla.org"}
	service.VLESSReality.MinClientVersion = "1.0.0"
	service.VLESSReality.MaxClientVersion = "26.3.27"
	service.VLESSReality.MaxTimeDiff = 1000
	service.VLESSReality.MLDSA65Seed = base64.RawURLEncoding.EncodeToString(bytesOf(32, 1))
	service.VLESSReality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(bytesOf(1952, 2))
	service.VLESSReality.MasterKeyLog = "/tmp/relayward-xray.keys"
	service.VLESSReality.LimitFallbackUpload = &RealityLimitFallback{AfterBytes: 1024, BytesPerSec: 2048, BurstBytesPerSec: 4096}
	service.VLESSReality.LimitFallbackDownload = &RealityLimitFallback{AfterBytes: 2048, BytesPerSec: 4096, BurstBytesPerSec: 8192}
	service.VLESSReality.Flow = ""
	service.VLESSReality.SpiderX = "/spider"

	value, err := NewConfiguration("26.3.27", 10085, editable)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := Editable(decoded).Services[0]
	want := Editable(value).Services[0]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-tripped inbound = %#v, want %#v", got, want)
	}
	if got.VLESSReality.Flow != "" {
		t.Fatalf("empty flow changed to %q", got.VLESSReality.Flow)
	}
}

func TestSupportedServiceTypeCatalogIsDefensive(t *testing.T) {
	t.Parallel()
	definitions := SupportedServiceTypes()
	if len(definitions) != 2 || definitions[0].ID != ServiceTypeVLESSReality ||
		definitions[1].ID != ServiceTypeShadowsocks || len(definitions[0].Capabilities.SubscriptionFormats) != 3 ||
		len(definitions[1].Capabilities.SubscriptionFormats) != 3 {
		t.Fatalf("SupportedServiceTypes() = %+v", definitions)
	}
	definitions[0].Capabilities.SubscriptionFormats[0] = "changed"
	definition, exists := ServiceTypeDefinitionByID(ServiceTypeVLESSReality)
	if !exists || definition.Capabilities.SubscriptionFormats[0] != "base64" {
		t.Fatalf("ServiceTypeDefinitionByID() = %+v, %t", definition, exists)
	}
}

func TestShadowsocksConfigurationGeneratesStableIndependentCredentials(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.3.27", 10085, []EditableService{testEditableShadowsocks()})
	if err != nil {
		t.Fatal(err)
	}
	service := value.Services[0]
	if service.Shadowsocks == nil || service.VLESSReality != nil ||
		!validShadowsocksKey(service.Shadowsocks.ServerKey, 32) {
		t.Fatalf("Shadowsocks service = %+v", service)
	}
	first, err := DeriveShadowsocksPassword(value.CredentialSeed, "authorization-a", service.ServiceID, service.Shadowsocks.Method)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := DeriveShadowsocksPassword(value.CredentialSeed, "authorization-a", service.ServiceID, service.Shadowsocks.Method)
	other, _ := DeriveShadowsocksPassword(value.CredentialSeed, "authorization-b", service.ServiceID, service.Shadowsocks.Method)
	if first != second || first == other || !validShadowsocksKey(first, 32) ||
		ShadowsocksClientPassword(*service.Shadowsocks, first) != service.Shadowsocks.ServerKey+":"+first {
		t.Fatalf("derived Shadowsocks credentials = %q, %q, %q", first, second, other)
	}

	standard := testEditableShadowsocks()
	standard.Shadowsocks.Method = ShadowsocksMethodChaCha20
	standard.Shadowsocks.ServerKey = "ignored"
	standardValue, err := NewConfiguration("26.3.27", 10085, []EditableService{standard})
	if err != nil {
		t.Fatal(err)
	}
	standardService := standardValue.Services[0]
	standardPassword, err := DeriveShadowsocksPassword(
		standardValue.CredentialSeed, "authorization-a", standardService.ServiceID, standardService.Shadowsocks.Method,
	)
	if err != nil || standardService.Shadowsocks.ServerKey != "" || len(standardPassword) != 36 {
		t.Fatalf("standard Shadowsocks service = %+v, password = %q, error = %v", standardService, standardPassword, err)
	}
}

func TestShadowsocksValidationRejectsUnsupportedSettings(t *testing.T) {
	t.Parallel()
	valid, err := NewConfiguration("26.3.27", 10085, []EditableService{testEditableShadowsocks()})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Configuration){
		"method":       func(value *Configuration) { value.Services[0].Shadowsocks.Method = "rc4-md5" },
		"network":      func(value *Configuration) { value.Services[0].Shadowsocks.Network = "icmp" },
		"server key":   func(value *Configuration) { value.Services[0].Shadowsocks.ServerKey = "invalid" },
		"typed config": func(value *Configuration) { value.Services[0].VLESSReality = &VLESSReality{} },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestNewConfigurationNormalizesPublicHost(t *testing.T) {
	t.Parallel()
	services := testEditableServices()[:1]
	services[0].PublicHost = "EDGE.EXAMPLE.COM"
	value, err := NewConfiguration("26.3.27", 10085, services)
	if err != nil {
		t.Fatal(err)
	}
	if value.Services[0].PublicHost != "edge.example.com" {
		t.Fatalf("public host = %q", value.Services[0].PublicHost)
	}
}

func TestDecodeRejectsInvalidConfigurations(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.3.27", 10085, testEditableServices())
	if err != nil {
		t.Fatal(err)
	}
	value.Routing = testRoutingConfiguration()
	valid, _ := Encode(value)
	tests := map[string]func(*Configuration){
		"missing version":       func(value *Configuration) { value.XrayVersion = "" },
		"leading v":             func(value *Configuration) { value.XrayVersion = "v26.3.27" },
		"pre-release":           func(value *Configuration) { value.XrayVersion = "26.3.27-rc.1" },
		"privileged API":        func(value *Configuration) { value.APIPort = 80 },
		"invalid seed":          func(value *Configuration) { value.CredentialSeed = "secret" },
		"unsupported type":      func(value *Configuration) { value.Services[0].Type = "trojan" },
		"invalid service ID":    func(value *Configuration) { value.Services[0].ServiceID = "Invalid ID" },
		"missing public host":   func(value *Configuration) { value.Services[0].PublicHost = "" },
		"public host with port": func(value *Configuration) { value.Services[0].PublicHost = "edge.example.com:443" },
		"duplicate service ID":  func(value *Configuration) { value.Services[1].ServiceID = value.Services[0].ServiceID },
		"unsorted services": func(value *Configuration) {
			value.Services[0], value.Services[1] = value.Services[1], value.Services[0]
		},
		"missing typed config": func(value *Configuration) { value.Services[0].VLESSReality = nil },
		"invalid target": func(value *Configuration) {
			value.Services[0].VLESSReality.Target = "missing-port"
		},
		"invalid key": func(value *Configuration) {
			value.Services[0].VLESSReality.PrivateKey = "secret"
		},
		"invalid short ID": func(value *Configuration) {
			value.Services[0].VLESSReality.ShortIDs = []string{"xyz"}
		},
		"invalid xver": func(value *Configuration) {
			value.Services[0].VLESSReality.Xver = 3
		},
		"invalid client version": func(value *Configuration) {
			value.Services[0].VLESSReality.MinClientVersion = "256.0.0"
		},
		"invalid client version range": func(value *Configuration) {
			value.Services[0].VLESSReality.MinClientVersion = "2.0.0"
			value.Services[0].VLESSReality.MaxClientVersion = "1.0.0"
		},
		"invalid spider x": func(value *Configuration) {
			value.Services[0].VLESSReality.SpiderX = "missing-slash"
		},
		"invalid TCP header": func(value *Configuration) {
			value.Services[0].TCP.Header.Type = "smtp"
		},
		"enabled sniffing without destinations": func(value *Configuration) {
			value.Services[0].Sniffing.Enabled = true
			value.Services[0].Sniffing.DestOverride = nil
		},
		"negative socket mark": func(value *Configuration) {
			value.Services[0].Sockopt = &SocketSettings{Mark: -1}
		},
		"invalid custom integer socket option": func(value *Configuration) {
			value.Services[0].Sockopt = &SocketSettings{Custom: []CustomSockopt{{System: "linux", Level: "6", Opt: "19", Type: "int", Value: "enabled"}}}
		},
		"invalid custom socket option network": func(value *Configuration) {
			value.Services[0].Sockopt = &SocketSettings{Custom: []CustomSockopt{{System: "linux", Network: "udp", Level: "6", Opt: "19", Type: "int", Value: "1"}}}
		},
		"invalid fallback destination": func(value *Configuration) {
			value.Services[0].VLESSReality.Fallbacks = []VLESSFallback{{Dest: "missing-port"}}
		},
		"incomplete ML-DSA pair": func(value *Configuration) {
			value.Services[0].VLESSReality.MLDSA65Seed = base64.RawURLEncoding.EncodeToString(bytesOf(32, 1))
		},
		"invalid VLESS encryption": func(value *Configuration) {
			value.Services[0].VLESSReality.Decryption = "invalid"
			value.Services[0].VLESSReality.Encryption = "invalid"
		},
		"conflicting listener": func(value *Configuration) { value.Services[1].Port = value.Services[0].Port },
		"conflicting API port": func(value *Configuration) { value.Services[0].Port = value.APIPort },
		"too many services": func(value *Configuration) {
			service := value.Services[0]
			for len(value.Services) <= MaximumServices {
				service.ServiceID += "x"
				value.Services = append(value.Services, service)
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var candidate Configuration
			if err := json.Unmarshal(valid, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			raw, _ := json.Marshal(candidate)
			if _, err := Decode(raw); err == nil {
				t.Fatal("Decode() unexpectedly succeeded")
			}
		})
	}
	if _, err := Decode(append(valid, []byte(` {}`)...)); err == nil {
		t.Fatal("Decode() accepted trailing JSON")
	}
	var object map[string]any
	_ = json.Unmarshal(valid, &object)
	object["unknown"] = true
	raw, _ := json.Marshal(object)
	if _, err := Decode(raw); err == nil {
		t.Fatal("Decode() accepted an unknown field")
	}
	legacy := []byte(`{"xray_version":"26.3.27","api_port":10085,"credential_seed":"secret","vless_reality":{}}`)
	if _, err := Decode(legacy); err == nil {
		t.Fatal("Decode() accepted the retired single-service configuration")
	}
}

func TestRealityTargetsAcceptedByXrayAreValid(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"addons.mozilla.org:443", "127.0.0.1:443", "[2001:db8::1]:443", "443", "/run/fallback.sock", "@fallback"} {
		target := target
		t.Run(strings.ReplaceAll(target, "/", "_"), func(t *testing.T) {
			services := testEditableServices()[:1]
			services[0].VLESSReality.Target = target
			if _, err := NewConfiguration("26.3.27", 10085, services); err != nil {
				t.Fatalf("target %q was rejected: %v", target, err)
			}
		})
	}
}

func bytesOf(size int, value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), size))
}

func TestEditableConfigurationPreservesExistingSecretsAndGeneratesNewServiceSecrets(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.3.27", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	value.Routing = testRoutingConfiguration()
	value.DNS = testDNSConfiguration()
	editable := Editable(value)
	editable.Routing.Rules[0].DisplayName = "Updated route"
	editable.DNS.Servers[0].DisplayName = "Updated regional DNS"
	editable.DNS.Servers[0].Domains[0] = "updated.example.com"
	editable.Services[0].DisplayName = "Updated Main"
	editable.Services = append(editable.Services, testEditableServices()[1])
	merged, err := MergeEditable(value, editable)
	if err != nil {
		t.Fatal(err)
	}
	main, mainExists := merged.FindService("reality-main")
	backup, backupExists := merged.FindService("reality-backup")
	if merged.CredentialSeed != value.CredentialSeed || !mainExists || !backupExists ||
		main.VLESSReality.PrivateKey != value.Services[0].VLESSReality.PrivateKey ||
		main.VLESSReality.ShortIDs[0] != value.Services[0].VLESSReality.ShortIDs[0] ||
		main.DisplayName != "Updated Main" || merged.Routing.Rules[0].DisplayName != "Updated route" ||
		merged.DNS.Servers[0].DisplayName != "Updated regional DNS" ||
		merged.DNS.Servers[0].Domains[0] != "updated.example.com" ||
		value.Routing.Rules[0].DisplayName != "Block private destinations" ||
		value.DNS.Servers[0].Domains[0] != "regional.example.com" {
		t.Fatalf("MergeEditable() changed protected existing configuration: %+v", merged)
	}
	if backup.VLESSReality.PrivateKey == "" || backup.VLESSReality.PrivateKey == value.Services[0].VLESSReality.PrivateKey ||
		backup.VLESSReality.ShortIDs[0] == value.Services[0].VLESSReality.ShortIDs[0] {
		t.Fatalf("MergeEditable() did not generate independent service secrets: %+v", backup)
	}
	created, err := NewFromEditable(editable)
	createdMain, createdMainExists := created.FindService("reality-main")
	if err != nil || created.CredentialSeed == "" || created.CredentialSeed == value.CredentialSeed ||
		len(created.Services) != 2 || !createdMainExists ||
		createdMain.VLESSReality.PrivateKey != editable.Services[0].VLESSReality.PrivateKey {
		t.Fatalf("NewFromEditable() = %+v, %v", created, err)
	}
	deleteRequest := Editable(merged)
	deleteRequest.Services = deleteRequest.Services[:1]
	deleted, err := MergeEditable(merged, deleteRequest)
	if err != nil || len(deleted.Services) != 1 || deleted.Services[0].ServiceID != "reality-backup" ||
		deleted.Services[0].VLESSReality.PrivateKey != backup.VLESSReality.PrivateKey {
		t.Fatalf("MergeEditable(delete) = %+v, %v", deleted, err)
	}
}

func TestDNSValidationRejectsUnsafeOrAmbiguousServers(t *testing.T) {
	t.Parallel()
	valid, err := NewConfiguration("26.3.27", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	valid.DNS = testDNSConfiguration()
	tests := map[string]func(*Configuration){
		"invalid strategy": func(value *Configuration) { value.DNS.QueryStrategy = "prefer-ipv4" },
		"no enabled server": func(value *Configuration) {
			for index := range value.DNS.Servers {
				value.DNS.Servers[index].Enabled = false
			}
		},
		"invalid ID":       func(value *Configuration) { value.DNS.Servers[0].ServerID = "Invalid ID" },
		"duplicate ID":     func(value *Configuration) { value.DNS.Servers[1].ServerID = value.DNS.Servers[0].ServerID },
		"missing UDP port": func(value *Configuration) { value.DNS.Servers[0].Port = 0 },
		"noncanonical IP":  func(value *Configuration) { value.DNS.Servers[0].Address = "192.0.2.01" },
		"system endpoint": func(value *Configuration) {
			value.DNS.Servers[1].Address = "127.0.0.1"
		},
		"uppercase domain": func(value *Configuration) { value.DNS.Servers[0].Domains[0] = "Example.com" },
		"duplicate domain": func(value *Configuration) {
			value.DNS.Servers[0].Domains = append(value.DNS.Servers[0].Domains, value.DNS.Servers[0].Domains[0])
		},
		"insecure DoH": func(value *Configuration) {
			value.DNS.Servers[1] = DNSServer{
				ServerID: "doh", DisplayName: "DoH", Enabled: true, Transport: DNSTransportDoH,
				Address: "http://dns.example.com/dns-query",
			}
		},
		"too many servers": func(value *Configuration) {
			for len(value.DNS.Servers) <= MaximumDNSServers {
				server := value.DNS.Servers[0]
				server.ServerID = fmt.Sprintf("dns-%d", len(value.DNS.Servers))
				value.DNS.Servers = append(value.DNS.Servers, server)
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestDNSValidationAcceptsSupportedTransportsAndDisabledDefault(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.3.27", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(value); err != nil {
		t.Fatalf("disabled default DNS rejected: %v", err)
	}
	value.DNS = DNSConfiguration{
		Enabled: true, QueryStrategy: DNSQueryStrategyUseIPv6,
		Servers: []DNSServer{
			{ServerID: "udp", DisplayName: "UDP", Enabled: true, Transport: DNSTransportUDP, Address: "2001:4860:4860::8888", Port: 53},
			{ServerID: "tcp", DisplayName: "TCP", Enabled: true, Transport: DNSTransportTCP, Address: "1.1.1.1", Port: 853},
			{ServerID: "doh", DisplayName: "DoH", Enabled: true, Transport: DNSTransportDoH, Address: "https://dns.google/dns-query"},
		},
	}
	if err := Validate(value); err != nil {
		t.Fatalf("supported DNS configuration rejected: %v", err)
	}
}

func TestRoutingValidationRejectsUnsafeOrAmbiguousRules(t *testing.T) {
	t.Parallel()
	valid, err := NewConfiguration("26.3.27", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	valid.Routing = testRoutingConfiguration()
	tests := map[string]func(*Configuration){
		"invalid ID":       func(value *Configuration) { value.Routing.Rules[0].RuleID = "Invalid ID" },
		"duplicate ID":     func(value *Configuration) { value.Routing.Rules[1].RuleID = value.Routing.Rules[0].RuleID },
		"missing match":    func(value *Configuration) { value.Routing.Rules[0].Domains = nil; value.Routing.Rules[0].IPCIDRs = nil },
		"unknown action":   func(value *Configuration) { value.Routing.Rules[0].Action = "proxy" },
		"uppercase domain": func(value *Configuration) { value.Routing.Rules[0].Domains[0] = "Example.com" },
		"domain expression": func(value *Configuration) {
			value.Routing.Rules[0].Domains[0] = "regexp:example.com"
		},
		"host IP":       func(value *Configuration) { value.Routing.Rules[0].IPCIDRs[0] = "192.0.2.1" },
		"unmasked CIDR": func(value *Configuration) { value.Routing.Rules[0].IPCIDRs[0] = "192.0.2.1/24" },
		"unknown protocol": func(value *Configuration) {
			value.Routing.Rules[1].Protocols[0] = "ssh"
		},
		"duplicate value": func(value *Configuration) {
			value.Routing.Rules[0].Domains = append(value.Routing.Rules[0].Domains, value.Routing.Rules[0].Domains[0])
		},
		"too many rules": func(value *Configuration) {
			for len(value.Routing.Rules) <= MaximumRoutingRules {
				rule := value.Routing.Rules[0]
				rule.RuleID = fmt.Sprintf("rule-%d", len(value.Routing.Rules))
				value.Routing.Rules = append(value.Routing.Rules, rule)
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func testEditableServices() []EditableService {
	return []EditableService{
		{
			Type: ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "0.0.0.0", Port: 443, PublicHost: "edge.example.com", PublicPort: 443,
			VLESSReality: &EditableVLESSReality{
				Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, Fingerprint: "chrome",
			},
		},
		{
			Type: ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "0.0.0.0", Port: 8443, PublicHost: "backup.example.com", PublicPort: 8443,
			VLESSReality: &EditableVLESSReality{
				Target: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}, Fingerprint: "chrome",
			},
		},
	}
}

func testEditableShadowsocks() EditableService {
	return EditableService{
		Type: ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main", DisplayName: "Shadowsocks Main",
		Listen: "0.0.0.0", Port: 8388, PublicHost: "ss.example.com", PublicPort: 8388,
		Shadowsocks: &EditableShadowsocks{
			Method: ShadowsocksMethod2022AES256, Network: ShadowsocksNetworkTCPUDP, IVCheck: true,
		},
	}
}

func testRoutingConfiguration() RoutingConfiguration {
	return RoutingConfiguration{Rules: []RoutingRule{
		{
			RuleID: "block-private", DisplayName: "Block private destinations", Enabled: true,
			Domains: []string{"internal.example.com"}, IPCIDRs: []string{"192.0.2.0/24"},
			Action: RoutingActionBlocked,
		},
		{
			RuleID: "allow-web", DisplayName: "Allow web protocols", Enabled: true,
			Protocols: []string{"http", "tls"}, Action: RoutingActionDirect,
		},
	}}
}

func testDNSConfiguration() DNSConfiguration {
	return DNSConfiguration{
		Enabled: true, QueryStrategy: DNSQueryStrategyUseIPv4,
		Servers: []DNSServer{
			{
				ServerID: "regional", DisplayName: "Regional DNS", Enabled: true,
				Transport: DNSTransportUDP, Address: "1.1.1.1", Port: 53,
				Domains: []string{"regional.example.com"},
			},
			{ServerID: "system", DisplayName: "System DNS", Enabled: true, Transport: DNSTransportSystem},
		},
	}
}
