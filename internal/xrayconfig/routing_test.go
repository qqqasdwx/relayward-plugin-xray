package xrayconfig

import (
	"testing"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestCompileRoutingRulesPreservesManagedPriority(t *testing.T) {
	t.Parallel()
	value := testConfiguration(t)
	value.Services[0].Enabled = false
	value.Routing = config.RoutingConfiguration{Rules: []config.RoutingRule{
		{
			RuleID: "disabled", DisplayName: "Disabled", Enabled: false,
			Domains: []string{"disabled.example.com"}, Action: config.RoutingActionBlocked,
		},
		{
			RuleID: "allow-example", DisplayName: "Allow example", Enabled: true,
			Domains: []string{"example.com"}, IPCIDRs: []string{"2001:db8::/32"},
			Protocols: []string{"http"}, Action: config.RoutingActionDirect,
		},
	}}
	rules, err := CompileRoutingRules(value, []DynamicBlockRule{{
		UserEmail: "relayward:authorization:reality-main", InboundTag: "reality-main", SourceIP: "192.0.2.10",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].RuleTag != APIRuleTag ||
		rules[1].RuleTag != "relayward-block-1" || rules[1].OutboundTag != config.RoutingActionBlocked ||
		rules[1].SourceCIDRs[0].String() != "192.0.2.10/32" ||
		rules[2].RuleTag != "relayward-static-allow-example" || rules[2].Domains[0] != "example.com" ||
		rules[2].DestinationCIDRs[0].String() != "2001:db8::/32" ||
		len(rules[2].InboundTags) != 1 || rules[2].InboundTags[0] != "reality-main" {
		t.Fatalf("CompileRoutingRules() = %+v", rules)
	}
	if !NeedsSniffing(value) {
		t.Fatal("NeedsSniffing() = false")
	}
}

func TestCompileRoutingRulesRejectsInvalidDynamicBlock(t *testing.T) {
	t.Parallel()
	if _, err := CompileRoutingRules(testConfiguration(t), []DynamicBlockRule{{SourceIP: "192.0.2.01"}}); err == nil {
		t.Fatal("CompileRoutingRules() unexpectedly accepted an invalid block")
	}
}
