package xrayconfig

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

const (
	APIRuleTag              = "relayward-api"
	SystemDirectOutboundTag = "relayward/system-direct"
	BlockedOutboundTag      = "relayward/blocked"
)

type DynamicBlockRule struct {
	UserEmail  string
	InboundTag string
	SourceIP   string
}

type CompiledRoutingRule struct {
	RuleTag          string
	OutboundTag      string
	Domains          []config.RoutingDomainExpression
	DestinationIPs   []config.RoutingIPExpression
	DestinationPorts []config.RoutingPortRange
	Networks         []string
	SourceIPs        []config.RoutingIPExpression
	SourcePorts      []config.RoutingPortRange
	VLESSRoutes      []config.RoutingPortRange
	UserEmails       []string
	InboundTags      []string
	Protocols        []string
	Attributes       map[string]string
}

func CompileRoutingRules(configuration config.Configuration, blocks []DynamicBlockRule) ([]CompiledRoutingRule, error) {
	if err := config.Validate(configuration); err != nil {
		return nil, err
	}
	rules := []CompiledRoutingRule{{
		RuleTag: APIRuleTag, OutboundTag: APIRuleTag, InboundTags: []string{APIRuleTag},
	}}
	for _, service := range configuration.Services {
		if !service.Enabled || service.Type != config.ServiceTypeVLESSReality {
			continue
		}
		domain, err := config.ParseRoutingDomainExpression("full:" + realityServerName(service))
		if err != nil {
			return nil, fmt.Errorf("compile REALITY protection for %q: %w", service.ServiceID, err)
		}
		tunnelTag := realityTunnelTag(service.ServiceID)
		rules = append(rules,
			CompiledRoutingRule{
				RuleTag: realityTunnelAllowRuleTag(service.ServiceID), OutboundTag: SystemDirectOutboundTag,
				Domains: []config.RoutingDomainExpression{domain}, InboundTags: []string{tunnelTag},
			},
			CompiledRoutingRule{
				RuleTag: realityTunnelBlockRuleTag(service.ServiceID), OutboundTag: BlockedOutboundTag,
				InboundTags: []string{tunnelTag},
			},
		)
	}
	for _, line := range configuration.EgressLines {
		if !line.Enabled {
			continue
		}
		rules = append(rules, CompiledRoutingRule{
			RuleTag: diagnosticRuleTag(line.LineID), OutboundTag: config.EgressOutboundTag(line.LineID),
			InboundTags: []string{diagnosticInboundTag(line.LineID)},
		})
	}
	for index, block := range blocks {
		address, err := netip.ParseAddr(block.SourceIP)
		if err != nil || address.String() != block.SourceIP || block.UserEmail == "" || block.InboundTag == "" {
			return nil, fmt.Errorf("dynamic block %d is invalid", index)
		}
		sourceIP, _ := config.ParseRoutingIPExpression(block.SourceIP)
		rules = append(rules, CompiledRoutingRule{
			RuleTag: fmt.Sprintf("relayward/dynamic-block/%d", index+1), OutboundTag: BlockedOutboundTag,
			UserEmails: []string{block.UserEmail}, InboundTags: []string{block.InboundTag},
			SourceIPs: []config.RoutingIPExpression{sourceIP},
		})
	}
	for _, rule := range configuration.AccessRules {
		if !rule.Enabled {
			continue
		}
		compiled, err := compileAccessRule(configuration, rule)
		if err != nil {
			return nil, fmt.Errorf("compile access rule %q: %w", rule.RuleID, err)
		}
		rules = append(rules, compiled)
	}
	vlessInbounds := enabledVLESSInbounds(configuration)
	if len(vlessInbounds) > 0 {
		for _, line := range configuration.EgressLines {
			if !line.Enabled {
				continue
			}
			rules = append(rules, CompiledRoutingRule{
				RuleTag:     "relayward/subscription-line/" + line.LineID,
				OutboundTag: config.EgressOutboundTag(line.LineID),
				VLESSRoutes: []config.RoutingPortRange{{From: line.VLESSRoute, To: line.VLESSRoute}},
				InboundTags: append([]string(nil), vlessInbounds...),
			})
		}
		rules = append(rules, CompiledRoutingRule{
			RuleTag: "relayward/subscription-line/unknown", OutboundTag: BlockedOutboundTag,
			InboundTags: append([]string(nil), vlessInbounds...),
		})
	}
	return rules, nil
}

func compileAccessRule(configuration config.Configuration, rule config.AccessRule) (CompiledRoutingRule, error) {
	outboundTag := BlockedOutboundTag
	if rule.Action == config.AccessActionEgress {
		outboundTag = config.EgressOutboundTag(rule.EgressLineID)
	}
	compiled := CompiledRoutingRule{
		RuleTag: "relayward/access/" + rule.RuleID, OutboundTag: outboundTag,
		Networks: splitNetwork(rule.Network), Protocols: append([]string(nil), rule.Protocols...),
		InboundTags: append([]string(nil), rule.ServiceIDs...),
	}
	var err error
	if compiled.Domains, err = parseRoutingDomains(rule.Domains); err != nil {
		return CompiledRoutingRule{}, err
	}
	if compiled.DestinationIPs, err = parseRoutingIPs(rule.DestinationIPs); err != nil {
		return CompiledRoutingRule{}, err
	}
	if compiled.SourceIPs, err = parseRoutingIPs(rule.SourceIPs); err != nil {
		return CompiledRoutingRule{}, err
	}
	if compiled.DestinationPorts, err = config.ParseRoutingPorts(rule.DestinationPort); err != nil {
		return CompiledRoutingRule{}, err
	}
	if len(rule.AuthorizationIDs) > 0 {
		serviceIDs := rule.ServiceIDs
		if len(serviceIDs) == 0 {
			serviceIDs = make([]string, 0, len(configuration.Services))
			for _, service := range configuration.Services {
				if service.Enabled {
					serviceIDs = append(serviceIDs, service.ServiceID)
				}
			}
		}
		for _, authorizationID := range rule.AuthorizationIDs {
			for _, serviceID := range serviceIDs {
				compiled.UserEmails = append(compiled.UserEmails, config.UserEmail(authorizationID, serviceID))
			}
		}
	}
	return compiled, nil
}

func enabledVLESSInbounds(configuration config.Configuration) []string {
	var result []string
	for _, service := range configuration.Services {
		if service.Enabled && service.Type == config.ServiceTypeVLESSReality {
			result = append(result, service.ServiceID)
		}
	}
	return result
}

func parseRoutingDomains(values []string) ([]config.RoutingDomainExpression, error) {
	parsed := make([]config.RoutingDomainExpression, len(values))
	for index, value := range values {
		item, err := config.ParseRoutingDomainExpression(value)
		if err != nil {
			return nil, err
		}
		parsed[index] = item
	}
	return parsed, nil
}

func parseRoutingIPs(values []string) ([]config.RoutingIPExpression, error) {
	parsed := make([]config.RoutingIPExpression, len(values))
	for index, value := range values {
		item, err := config.ParseRoutingIPExpression(value)
		if err != nil {
			return nil, err
		}
		parsed[index] = item
	}
	return parsed, nil
}

func renderRoutingRules(rules []CompiledRoutingRule) []any {
	values := make([]any, len(rules))
	for index, rule := range rules {
		value := map[string]any{"type": "field", "ruleTag": rule.RuleTag, "outboundTag": rule.OutboundTag}
		if len(rule.Domains) > 0 {
			value["domain"] = domainExpressions(rule.Domains)
		}
		if len(rule.DestinationIPs) > 0 {
			value["ip"] = ipExpressions(rule.DestinationIPs)
		}
		if len(rule.DestinationPorts) > 0 {
			value["port"] = portRanges(rule.DestinationPorts)
		}
		if len(rule.Networks) > 0 {
			value["network"] = strings.Join(rule.Networks, ",")
		}
		if len(rule.SourceIPs) > 0 {
			value["sourceIP"] = ipExpressions(rule.SourceIPs)
		}
		if len(rule.SourcePorts) > 0 {
			value["sourcePort"] = portRanges(rule.SourcePorts)
		}
		if len(rule.VLESSRoutes) > 0 {
			value["vlessRoute"] = portRanges(rule.VLESSRoutes)
		}
		if len(rule.UserEmails) > 0 {
			value["user"] = rule.UserEmails
		}
		if len(rule.InboundTags) > 0 {
			value["inboundTag"] = rule.InboundTags
		}
		if len(rule.Protocols) > 0 {
			value["protocol"] = rule.Protocols
		}
		if len(rule.Attributes) > 0 {
			value["attrs"] = rule.Attributes
		}
		values[index] = value
	}
	return values
}

func domainExpressions(values []config.RoutingDomainExpression) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Raw
	}
	return result
}

func ipExpressions(values []config.RoutingIPExpression) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Raw
	}
	return result
}

func portRanges(values []config.RoutingPortRange) string {
	parts := make([]string, len(values))
	for index, value := range values {
		if value.From == value.To {
			parts[index] = strconv.Itoa(int(value.From))
		} else {
			parts[index] = fmt.Sprintf("%d-%d", value.From, value.To)
		}
	}
	return strings.Join(parts, ",")
}

func splitNetwork(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func realityTunnelTag(serviceID string) string {
	return "relayward/internal/reality-tunnel/" + serviceID
}
func realityTunnelAllowRuleTag(serviceID string) string {
	return "relayward/internal/reality-sni-allow/" + serviceID
}
func realityTunnelBlockRuleTag(serviceID string) string {
	return "relayward/internal/reality-sni-block/" + serviceID
}
func diagnosticInboundTag(lineID string) string { return "relayward/internal/egress-probe/" + lineID }
func diagnosticRuleTag(lineID string) string {
	return "relayward/internal/egress-probe-route/" + lineID
}
