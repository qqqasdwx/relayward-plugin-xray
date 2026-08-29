package xrayruntime

import (
	"encoding/base64"
	"net/netip"
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
	rules := []xrayconfig.CompiledRoutingRule{{
		RuleTag: "relayward-static-test", OutboundTag: "blocked", Domains: []string{"example.com"},
		DestinationCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Protocols: []string{"http"},
		UserEmails: []string{"relayward:test"}, InboundTags: []string{"reality-main"},
		SourceCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
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
		legacy.Rules[0].Protocol[0] != "http" {
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
		geodata.Rules[0].Protocol[0] != "http" {
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
