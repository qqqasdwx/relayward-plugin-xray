package config

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigurationRoundTripAndSecretPreservation(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.7.28", testEditableServices())
	if err != nil {
		t.Fatal(err)
	}
	value.AccessRules = []AccessRule{{
		RuleID: "block-private", DisplayName: "Block private", Enabled: true,
		DestinationIPs: []string{"geoip:private"}, Action: AccessActionBlock,
	}}
	raw, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.APIPort != ManagedAPIPort || len(decoded.Services) != 2 ||
		decoded.Services[0].ServiceID != "reality-main" || decoded.Services[1].ServiceID != "shadowsocks-main" ||
		len(decoded.EgressLines) != 1 || decoded.EgressLines[0].LineID != DefaultEgressLineID ||
		len(decoded.AccessRules) != 1 {
		t.Fatalf("configuration = %+v", decoded)
	}
	if decoded.Services[0].VLESSReality.PrivateKey == "" || decoded.Services[0].VLESSReality.ShortID == "" ||
		decoded.Services[1].Shadowsocks.ServerKey == "" {
		t.Fatalf("generated service secrets = %+v", decoded.Services)
	}

	editable := Editable(decoded)
	editable.Services[0].DisplayName = "Updated Reality"
	merged, err := MergeEditable(decoded, editable)
	if err != nil {
		t.Fatal(err)
	}
	if merged.CredentialSeed != decoded.CredentialSeed ||
		merged.Services[0].VLESSReality.PrivateKey != decoded.Services[0].VLESSReality.PrivateKey ||
		merged.Services[0].VLESSReality.ShortID != decoded.Services[0].VLESSReality.ShortID ||
		merged.Services[1].Shadowsocks.ServerKey != decoded.Services[1].Shadowsocks.ServerKey ||
		merged.Services[0].DisplayName != "Updated Reality" {
		t.Fatalf("MergeEditable() did not preserve protected values: %+v", merged)
	}
	editableRaw, err := json.Marshal(editable)
	if err != nil {
		t.Fatal(err)
	}
	for _, secretField := range []string{"credential_seed", "private_key", "short_id", "server_key"} {
		if strings.Contains(string(editableRaw), secretField) {
			t.Fatalf("editable configuration exposed %q: %s", secretField, editableRaw)
		}
	}
}

func TestNewServiceGetsIndependentSecrets(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.7.28", testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	editable := Editable(value)
	second := editable.Services[0]
	second.ServiceID = "reality-second"
	second.DisplayName = "Reality Second"
	second.Port = 25443
	editable.Services = append(editable.Services, second)
	merged, err := MergeEditable(value, editable)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := merged.FindService("reality-main")
	created, exists := merged.FindService("reality-second")
	if !exists || first.VLESSReality.PrivateKey == created.VLESSReality.PrivateKey ||
		first.VLESSReality.ShortID == created.VLESSReality.ShortID {
		t.Fatalf("new service secrets = %+v", created)
	}
}

func TestDecodeRejectsUnknownAndInvalidConfiguration(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.7.28", testEditableServices())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["legacy_dns"] = map[string]any{}
	unknown, _ := json.Marshal(object)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("Decode() accepted an unknown field")
	}
	if _, err := Decode(append(valid, []byte(` {}`)...)); err == nil {
		t.Fatal("Decode() accepted trailing JSON")
	}

	tests := map[string]func(*Configuration){
		"managed API port":     func(candidate *Configuration) { candidate.APIPort++ },
		"old Xray":             func(candidate *Configuration) { candidate.XrayVersion = "26.7.10" },
		"duplicate service ID": func(candidate *Configuration) { candidate.Services[1].ServiceID = candidate.Services[0].ServiceID },
		"unsorted services": func(candidate *Configuration) {
			candidate.Services[0], candidate.Services[1] = candidate.Services[1], candidate.Services[0]
		},
		"duplicate port":      func(candidate *Configuration) { candidate.Services[1].Port = candidate.Services[0].Port },
		"invalid target":      func(candidate *Configuration) { candidate.Services[0].VLESSReality.Target = "127.0.0.1:443" },
		"invalid private key": func(candidate *Configuration) { candidate.Services[0].VLESSReality.PrivateKey = "secret" },
		"invalid short ID":    func(candidate *Configuration) { candidate.Services[0].VLESSReality.ShortID = "abcd" },
		"unsupported SS method": func(candidate *Configuration) {
			candidate.Services[1].Shadowsocks.Method = "chacha20-ietf-poly1305"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(value)
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}

func TestRealityTargetRequiresCanonicalDomainAndPort(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"addons.mozilla.org:443", "fallback.example.com:8443"} {
		services := testEditableServices()[:1]
		services[0].VLESSReality.Target = target
		if _, err := NewConfiguration("26.7.28", services); err != nil {
			t.Fatalf("target %q was rejected: %v", target, err)
		}
	}
	for _, target := range []string{"ADDONS.MOZILLA.ORG:443", "127.0.0.1:443", "[2001:db8::1]:443", "missing-port"} {
		services := testEditableServices()[:1]
		services[0].VLESSReality.Target = target
		if _, err := NewConfiguration("26.7.28", services); err == nil {
			t.Fatalf("target %q was accepted", target)
		}
	}
}

func TestCredentialForVLESSRoute(t *testing.T) {
	t.Parallel()
	credential := "12345678-1234-4234-9234-1234567890ab"
	routed, err := CredentialForVLESSRoute(credential, 0x3456)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(routed, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	if raw[6] != 0x34 || raw[7] != 0x56 || raw[8] != 0x92 || routed == credential {
		t.Fatalf("routed credential = %q (%x)", routed, raw)
	}
	if _, err := CredentialForVLESSRoute(strings.ToUpper(credential), 1); err == nil {
		t.Fatal("CredentialForVLESSRoute() accepted a non-canonical UUID")
	}
}

func testEditableServices() []EditableService {
	return []EditableService{
		{
			Type: ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main",
			DisplayName: "Reality Main", Port: 24443,
			VLESSReality: &EditableVLESSReality{Target: "www.tesla.com:443"},
		},
		{
			Type: ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main",
			DisplayName: "Shadowsocks Main", Port: 28443,
			Shadowsocks: &EditableShadowsocks{Method: ShadowsocksMethod2022AES256},
		},
	}
}
