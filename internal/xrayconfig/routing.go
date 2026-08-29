package xrayconfig

import (
	"fmt"
	"net/netip"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

const APIRuleTag = "relayward-api"

type DynamicBlockRule struct {
	UserEmail  string
	InboundTag string
	SourceIP   string
}

type CompiledRoutingRule struct {
	RuleTag          string
	OutboundTag      string
	Domains          []string
	DestinationCIDRs []netip.Prefix
	Protocols        []string
	UserEmails       []string
	InboundTags      []string
	SourceCIDRs      []netip.Prefix
}

func CompileRoutingRules(configuration config.Configuration, blocks []DynamicBlockRule) ([]CompiledRoutingRule, error) {
	if err := config.Validate(configuration); err != nil {
		return nil, err
	}
	inboundTags := enabledServiceIDs(configuration)
	rules := make([]CompiledRoutingRule, 0, 1+len(blocks)+len(configuration.Routing.Rules))
	rules = append(rules, CompiledRoutingRule{
		RuleTag: APIRuleTag, OutboundTag: APIRuleTag, InboundTags: []string{APIRuleTag},
	})
	for index, block := range blocks {
		address, err := netip.ParseAddr(block.SourceIP)
		if err != nil || address.String() != block.SourceIP || block.UserEmail == "" || block.InboundTag == "" {
			return nil, fmt.Errorf("dynamic block %d is invalid", index)
		}
		rules = append(rules, CompiledRoutingRule{
			RuleTag: fmt.Sprintf("relayward-block-%d", index+1), OutboundTag: config.RoutingActionBlocked,
			UserEmails: []string{block.UserEmail}, InboundTags: []string{block.InboundTag},
			SourceCIDRs: []netip.Prefix{netip.PrefixFrom(address, address.BitLen())},
		})
	}
	for _, rule := range configuration.Routing.Rules {
		if !rule.Enabled {
			continue
		}
		compiled := CompiledRoutingRule{
			RuleTag: "relayward-static-" + rule.RuleID, OutboundTag: rule.Action,
			Domains: append([]string(nil), rule.Domains...), Protocols: append([]string(nil), rule.Protocols...),
			InboundTags: append([]string(nil), inboundTags...),
		}
		for _, raw := range rule.IPCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("compile routing rule %q: %w", rule.RuleID, err)
			}
			compiled.DestinationCIDRs = append(compiled.DestinationCIDRs, prefix)
		}
		rules = append(rules, compiled)
	}
	return rules, nil
}

func NeedsSniffing(configuration config.Configuration) bool {
	for _, rule := range configuration.Routing.Rules {
		if rule.Enabled && (len(rule.Domains) > 0 || len(rule.Protocols) > 0) {
			return true
		}
	}
	return false
}

func enabledServiceIDs(configuration config.Configuration) []string {
	values := make([]string, 0, len(configuration.Services))
	for _, service := range configuration.Services {
		if service.Enabled {
			values = append(values, service.ServiceID)
		}
	}
	return values
}

func renderRoutingRules(rules []CompiledRoutingRule) []any {
	values := make([]any, len(rules))
	for index, rule := range rules {
		value := map[string]any{
			"type": "field", "ruleTag": rule.RuleTag, "outboundTag": rule.OutboundTag,
		}
		if len(rule.Domains) > 0 {
			domains := make([]string, len(rule.Domains))
			for domainIndex, domain := range rule.Domains {
				domains[domainIndex] = "domain:" + domain
			}
			value["domain"] = domains
		}
		if len(rule.DestinationCIDRs) > 0 {
			value["ip"] = prefixesAsStrings(rule.DestinationCIDRs)
		}
		if len(rule.Protocols) > 0 {
			value["protocol"] = rule.Protocols
		}
		if len(rule.UserEmails) > 0 {
			value["user"] = rule.UserEmails
		}
		if len(rule.InboundTags) > 0 {
			value["inboundTag"] = rule.InboundTags
		}
		if len(rule.SourceCIDRs) > 0 {
			value["sourceIP"] = prefixesAsStrings(rule.SourceCIDRs)
		}
		values[index] = value
	}
	return values
}

func prefixesAsStrings(prefixes []netip.Prefix) []string {
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = prefix.String()
	}
	return values
}
