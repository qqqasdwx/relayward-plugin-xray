package xrayruntime

import (
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
)

func TestMarshalRuntimeAccountsForShadowsocks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		credential  runtimeCredential
		accountType string
		verify      func(*testing.T, []byte)
	}{
		{
			name: "2022", accountType: "xray.proxy.shadowsocks_2022.Account",
			credential: runtimeCredential{serviceType: config.ServiceTypeShadowsocks, method: config.ShadowsocksMethod2022AES256, password: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))},
			verify: func(t *testing.T, raw []byte) {
				value := &shadowsocks2022Account{}
				if err := proto.Unmarshal(raw, protoadapt.MessageV2Of(value)); err != nil || value.Key == "" {
					t.Fatalf("Shadowsocks 2022 account = %+v, %v", value, err)
				}
			},
		},
		{
			name: "AEAD", accountType: "xray.proxy.shadowsocks.Account",
			credential: runtimeCredential{serviceType: config.ServiceTypeShadowsocks, method: config.ShadowsocksMethodChaCha20, password: "password", ivCheck: true},
			verify: func(t *testing.T, raw []byte) {
				value := &shadowsocksAccount{}
				if err := proto.Unmarshal(raw, protoadapt.MessageV2Of(value)); err != nil || value.Password != "password" || value.CipherType != 7 || !value.IVCheck {
					t.Fatalf("Shadowsocks account = %+v, %v", value, err)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			accountType, raw, err := marshalRuntimeAccount(test.credential)
			if err != nil || accountType != test.accountType {
				t.Fatalf("marshalRuntimeAccount() = %q, %x, %v", accountType, raw, err)
			}
			test.verify(t, raw)
		})
	}
}

func TestOnlineIPResponseDecodesOfficialMapWireFormat(t *testing.T) {
	t.Parallel()
	entry := protowire.AppendTag(nil, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "2001:db8::1")
	entry = protowire.AppendTag(entry, 2, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 1786017600)
	raw := protowire.AppendTag(nil, 1, protowire.BytesType)
	raw = protowire.AppendString(raw, "user>>>relayward:test:vless-reality>>>online")
	raw = protowire.AppendTag(raw, 2, protowire.BytesType)
	raw = protowire.AppendBytes(raw, entry)
	response := &getStatsOnlineIPListResponse{}
	if err := proto.Unmarshal(raw, protoadapt.MessageV2Of(response)); err != nil {
		t.Fatal(err)
	}
	if response.IPs["2001:db8::1"] != 1786017600 {
		t.Fatalf("decoded response = %+v", response)
	}
}

func TestRoutingRuleWireFormatsAcrossOfficialXrayVersions(t *testing.T) {
	t.Parallel()
	domain, err := config.ParseRoutingDomainExpression("domain:example.com")
	if err != nil {
		t.Fatal(err)
	}
	destinationIP, err := config.ParseRoutingIPExpression("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	sourceIP, err := config.ParseRoutingIPExpression("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	rules := []xrayconfig.CompiledRoutingRule{{
		RuleTag: "relayward-static-test", OutboundTag: "blocked", Domains: []config.RoutingDomainExpression{domain},
		DestinationIPs: []config.RoutingIPExpression{destinationIP}, DestinationPorts: []config.RoutingPortRange{{From: 443, To: 443}},
		Networks: []string{"tcp"}, SourcePorts: []config.RoutingPortRange{{From: 1000, To: 2000}},
		UserEmails: []string{"relayward:test"}, InboundTags: []string{"reality-main"},
		SourceIPs: []config.RoutingIPExpression{sourceIP}, Protocols: []string{"http"},
		VLESSRoutes: []config.RoutingPortRange{{From: 8443, To: 8443}}, Attributes: map[string]string{"user-agent": "curl"},
	}}
	legacyRaw, err := marshalRoutingRules("26.3.27", rules)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &routerConfig{}
	if err := proto.Unmarshal(legacyRaw, protoadapt.MessageV2Of(legacy)); err != nil {
		t.Fatal(err)
	}
	if len(legacy.Rules) != 1 || legacy.Rules[0].Domain[0].Value != "example.com" ||
		legacy.Rules[0].GeoIP[0].CIDR[0].Prefix != 24 || legacy.Rules[0].SourceGeoIP[0].CIDR[0].Prefix != 128 ||
		legacy.Rules[0].Protocol[0] != "http" || legacy.Rules[0].PortList.Ranges[0].From != 443 ||
		legacy.Rules[0].SourcePortList.Ranges[0].To != 2000 || legacy.Rules[0].Networks[0] != 2 ||
		legacy.Rules[0].VLESSRouteList.Ranges[0].From != 8443 || legacy.Rules[0].Attributes["user-agent"] != "curl" {
		t.Fatalf("legacy routing rules = %+v", legacy.Rules)
	}

	geodataRaw, err := marshalRoutingRules("26.7.11", rules)
	if err != nil {
		t.Fatal(err)
	}
	geodata := &geodataRouterConfig{}
	if err := proto.Unmarshal(geodataRaw, protoadapt.MessageV2Of(geodata)); err != nil {
		t.Fatal(err)
	}
	if len(geodata.Rules) != 1 || geodata.Rules[0].Domain[0].Custom.Value != "example.com" ||
		geodata.Rules[0].IP[0].Custom.CIDR.Prefix != 24 || geodata.Rules[0].SourceIP[0].Custom.CIDR.Prefix != 128 ||
		geodata.Rules[0].Protocol[0] != "http" || geodata.Rules[0].PortList.Ranges[0].From != 443 ||
		geodata.Rules[0].SourcePortList.Ranges[0].To != 2000 || geodata.Rules[0].Networks[0] != 2 ||
		geodata.Rules[0].VLESSRouteList.Ranges[0].From != 8443 || geodata.Rules[0].Attributes["user-agent"] != "curl" {
		t.Fatalf("geodata routing rules = %+v", geodata.Rules)
	}
}

func TestGeodataRoutingVersionCutoff(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"26.3.27": false,
		"26.7.10": false,
		"26.7.11": true,
		"26.7.28": true,
		"27.1.1":  true,
	}
	for version, expected := range tests {
		if actual := usesGeodataRoutingRules(version); actual != expected {
			t.Fatalf("usesGeodataRoutingRules(%q) = %t, want %t", version, actual, expected)
		}
	}
}

func TestGeodataRoutingReferencesUseOfficialWireFields(t *testing.T) {
	t.Parallel()
	domain, err := config.ParseRoutingDomainExpression("geosite:cn@ads")
	if err != nil {
		t.Fatal(err)
	}
	destinationIP, err := config.ParseRoutingIPExpression("!geoip:private")
	if err != nil {
		t.Fatal(err)
	}
	rules := []xrayconfig.CompiledRoutingRule{{
		RuleTag: "relayward-static-geodata", OutboundTag: "blocked",
		Domains: []config.RoutingDomainExpression{domain}, DestinationIPs: []config.RoutingIPExpression{destinationIP},
	}}
	raw, err := marshalRoutingRules("26.7.11", rules)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &geodataRouterConfig{}
	if err := proto.Unmarshal(raw, protoadapt.MessageV2Of(decoded)); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Rules) != 1 || decoded.Rules[0].Domain[0].Geosite.File != "geosite.dat" ||
		decoded.Rules[0].Domain[0].Geosite.Code != "CN" || decoded.Rules[0].Domain[0].Geosite.Attrs != "ads" ||
		decoded.Rules[0].IP[0].GeoIP.File != "geoip.dat" || decoded.Rules[0].IP[0].GeoIP.Code != "PRIVATE" ||
		!decoded.Rules[0].IP[0].GeoIP.Reverse {
		t.Fatalf("geodata routing rule = %+v", decoded.Rules)
	}
	if _, err := marshalRoutingRules("26.7.10", rules); err == nil {
		t.Fatal("legacy routing unexpectedly accepted geodata references")
	}
}
