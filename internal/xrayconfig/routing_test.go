package xrayconfig

import (
	"testing"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestCompileRoutingRulesUsesManagedPriority(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration()
	configuration.AccessRules = []config.AccessRule{
		{
			RuleID: "disabled", DisplayName: "Disabled", Enabled: false,
			Domains: []string{"domain:disabled.example.com"}, Action: config.AccessActionBlock,
		},
		{
			RuleID: "registration", DisplayName: "Registration", Enabled: true,
			Domains: []string{"domain:example.com"}, Protocols: []string{"tls"},
			AuthorizationIDs: []string{"10000000-0000-4000-8000-000000000001"},
			ServiceIDs:       []string{"reality-main"}, Action: config.AccessActionEgress, EgressLineID: "ipv6",
		},
	}
	rules, err := CompileRoutingRules(configuration, []DynamicBlockRule{{
		UserEmail:  config.UserEmail("10000000-0000-4000-8000-000000000001", "reality-main"),
		InboundTag: "reality-main", SourceIP: "192.0.2.10",
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantTags := []string{
		APIRuleTag,
		realityTunnelAllowRuleTag("reality-main"),
		realityTunnelBlockRuleTag("reality-main"),
		diagnosticRuleTag("default"),
		diagnosticRuleTag("ipv6"),
		diagnosticRuleTag("socks-us"),
		diagnosticRuleTag("ss-jp"),
		"relayward/dynamic-block/1",
		"relayward/access/registration",
		"relayward/subscription-line/default",
		"relayward/subscription-line/ipv6",
		"relayward/subscription-line/socks-us",
		"relayward/subscription-line/ss-jp",
		"relayward/subscription-line/unknown",
	}
	if len(rules) != len(wantTags) {
		t.Fatalf("rule count = %d, want %d: %+v", len(rules), len(wantTags), rules)
	}
	for index, tag := range wantTags {
		if rules[index].RuleTag != tag {
			t.Fatalf("rule %d tag = %q, want %q", index, rules[index].RuleTag, tag)
		}
	}
	if rules[1].Domains[0].Raw != "full:www.tesla.com" || rules[1].OutboundTag != SystemDirectOutboundTag ||
		rules[2].OutboundTag != BlockedOutboundTag ||
		rules[7].SourceIPs[0].Prefix.String() != "192.0.2.10/32" ||
		rules[8].UserEmails[0] != config.UserEmail("10000000-0000-4000-8000-000000000001", "reality-main") ||
		rules[8].OutboundTag != config.EgressOutboundTag("ipv6") ||
		rules[10].VLESSRoutes[0].From != 6 || rules[len(rules)-1].OutboundTag != BlockedOutboundTag {
		t.Fatalf("compiled rules = %+v", rules)
	}
}

func TestCompileRoutingRulesRejectsInvalidDynamicBlock(t *testing.T) {
	t.Parallel()
	if _, err := CompileRoutingRules(testConfiguration(), []DynamicBlockRule{{SourceIP: "192.0.2.01"}}); err == nil {
		t.Fatal("CompileRoutingRules() accepted an invalid dynamic block")
	}
}
