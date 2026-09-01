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
			Domains: []string{"domain:disabled.example.com"}, OutboundTag: config.RoutingOutboundBlocked,
		},
		{
			RuleID: "allow-example", DisplayName: "Allow example", Enabled: true,
			Domains: []string{"domain:example.com"}, DestinationIPs: []string{"2001:db8::/32"},
			Protocols: []string{"http"}, OutboundTag: config.RoutingOutboundDirect,
		},
	}}
	rules, err := CompileRoutingRules(value, []DynamicBlockRule{{
		UserEmail: "relayward:authorization:reality-main", InboundTag: "reality-main", SourceIP: "192.0.2.10",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 || rules[0].RuleTag != APIRuleTag ||
		rules[1].RuleTag != realityTunnelAllowRuleTag("reality-main") ||
		rules[1].Domains[0].Raw != "full:www.microsoft.com" || rules[1].OutboundTag != config.RoutingOutboundDirect ||
		rules[2].RuleTag != realityTunnelBlockRuleTag("reality-main") || rules[2].OutboundTag != config.RoutingOutboundBlocked ||
		rules[3].RuleTag != "relayward-block-1" || rules[3].OutboundTag != config.RoutingOutboundBlocked ||
		rules[3].SourceIPs[0].Prefix.String() != "192.0.2.10/32" ||
		rules[4].RuleTag != "relayward-static-allow-example" || rules[4].Domains[0].Raw != "domain:example.com" ||
		rules[4].DestinationIPs[0].Prefix.String() != "2001:db8::/32" || len(rules[4].InboundTags) != 0 {
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
