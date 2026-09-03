package config

import "testing"

func TestEgressLineCredentialsAreWriteOnlyAndStable(t *testing.T) {
	t.Parallel()
	editable := EditableConfiguration{
		XrayVersion: "26.7.28",
		Services:    testEditableServices()[:1],
		EgressLines: []EditableEgressLine{
			DefaultEgressLine(),
			{
				LineID: "socks-us", DisplayName: "SOCKS US", Enabled: true, VLESSRoute: 10, Type: EgressTypeSOCKS5,
				SOCKS5: &EditableSOCKS5Egress{
					Address: "proxy.example.com", Port: 1080, UseAuthentication: true,
					Username: "alice", Password: "secret",
				},
			},
			{
				LineID: "ss-jp", DisplayName: "SS JP", Enabled: true, VLESSRoute: 20, Type: EgressTypeShadowsocks,
				Shadowsocks: &EditableShadowsocksEgress{
					Address: "ss.example.com", Port: 8388, Method: ShadowsocksMethod2022AES256, Password: "server-password",
				},
			},
		},
	}
	value, err := NewFromEditable(editable)
	if err != nil {
		t.Fatal(err)
	}
	redacted := Editable(value)
	if redacted.EgressLines[1].SOCKS5.Password != "" || !redacted.EgressLines[1].SOCKS5.PasswordConfigured ||
		redacted.EgressLines[2].Shadowsocks.Password != "" || !redacted.EgressLines[2].Shadowsocks.PasswordConfigured {
		t.Fatalf("editable egress lines = %+v", redacted.EgressLines)
	}
	redacted.EgressLines[1].DisplayName = "Updated SOCKS"
	merged, err := MergeEditable(value, redacted)
	if err != nil {
		t.Fatal(err)
	}
	if merged.EgressLines[1].SOCKS5.Password != "secret" ||
		merged.EgressLines[2].Shadowsocks.Password != "server-password" {
		t.Fatalf("merged egress secrets = %+v", merged.EgressLines)
	}
}

func TestEgressAndAccessRuleValidation(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.7.28", testEditableServices())
	if err != nil {
		t.Fatal(err)
	}
	base := Editable(value)
	base.EgressLines = append(base.EgressLines, EditableEgressLine{
		LineID: "ipv6", DisplayName: "IPv6", Enabled: true, VLESSRoute: 6,
		Type: EgressTypeDirect, Direct: &DirectEgress{SendThrough: "2001:db8::10"},
	})
	base.AccessRules = []AccessRule{{
		RuleID: "registration", DisplayName: "Registration", Enabled: true,
		Domains: []string{"domain:example.com"}, Protocols: []string{"tls"},
		AuthorizationIDs: []string{"10000000-0000-4000-8000-000000000001"},
		ServiceIDs:       []string{"reality-main"}, Action: AccessActionEgress, EgressLineID: "ipv6",
	}}
	valid, err := NewFromEditable(base)
	if err != nil {
		t.Fatal(err)
	}
	if valid.EgressLines[0].LineID != DefaultEgressLineID || valid.EgressLines[1].Direct.SendThrough != "2001:db8::10" {
		t.Fatalf("egress lines = %+v", valid.EgressLines)
	}
	tests := map[string]func(*Configuration){
		"default not first": func(candidate *Configuration) {
			candidate.EgressLines[0], candidate.EgressLines[1] = candidate.EgressLines[1], candidate.EgressLines[0]
		},
		"duplicate route": func(candidate *Configuration) { candidate.EgressLines[1].VLESSRoute = 0 },
		"noncanonical source address": func(candidate *Configuration) {
			candidate.EgressLines[1].Direct.SendThrough = "2001:0db8::10"
		},
		"empty rule": func(candidate *Configuration) {
			candidate.AccessRules[0] = AccessRule{
				RuleID: "empty", DisplayName: "Empty", Enabled: true, Action: AccessActionBlock,
			}
		},
		"unknown service": func(candidate *Configuration) { candidate.AccessRules[0].ServiceIDs = []string{"missing"} },
		"unknown line":    func(candidate *Configuration) { candidate.AccessRules[0].EgressLineID = "missing" },
		"disabled line":   func(candidate *Configuration) { candidate.EgressLines[1].Enabled = false },
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
