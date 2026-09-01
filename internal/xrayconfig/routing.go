package xrayconfig

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

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
	rules := make([]CompiledRoutingRule, 0, 1+len(blocks)+len(configuration.Routing.Rules))
	rules = append(rules, CompiledRoutingRule{
		RuleTag: APIRuleTag, OutboundTag: APIRuleTag, InboundTags: []string{APIRuleTag},
	})
	for _, service := range configuration.Services {
		if !service.Enabled || service.Type != config.ServiceTypeVLESSReality {
			continue
		}
		tunnelTag := realityTunnelTag(service.ServiceID)
		domain, err := config.ParseRoutingDomainExpression("full:" + service.VLESSReality.ServerNames[0])
		if err != nil {
			return nil, fmt.Errorf("compile REALITY protection for %q: %w", service.ServiceID, err)
		}
		rules = append(rules,
			CompiledRoutingRule{
				RuleTag: realityTunnelAllowRuleTag(service.ServiceID), OutboundTag: config.RoutingOutboundDirect,
				Domains: []config.RoutingDomainExpression{domain}, InboundTags: []string{tunnelTag},
			},
			CompiledRoutingRule{
				RuleTag: realityTunnelBlockRuleTag(service.ServiceID), OutboundTag: config.RoutingOutboundBlocked,
				InboundTags: []string{tunnelTag},
			},
		)
	}
	for index, block := range blocks {
		address, err := netip.ParseAddr(block.SourceIP)
		if err != nil || address.String() != block.SourceIP || block.UserEmail == "" || block.InboundTag == "" {
			return nil, fmt.Errorf("dynamic block %d is invalid", index)
		}
		sourceIP, err := config.ParseRoutingIPExpression(block.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("dynamic block %d is invalid", index)
		}
		rules = append(rules, CompiledRoutingRule{
			RuleTag: fmt.Sprintf("relayward-block-%d", index+1), OutboundTag: config.RoutingOutboundBlocked,
			UserEmails: []string{block.UserEmail}, InboundTags: []string{block.InboundTag},
			SourceIPs: []config.RoutingIPExpression{sourceIP},
		})
	}
	for _, rule := range configuration.Routing.Rules {
		if !rule.Enabled {
			continue
		}
		compiled, err := compileStaticRoutingRule(rule)
		if err != nil {
			return nil, fmt.Errorf("compile routing rule %q: %w", rule.RuleID, err)
		}
		rules = append(rules, compiled)
	}
	return rules, nil
}

func compileStaticRoutingRule(rule config.RoutingRule) (CompiledRoutingRule, error) {
	compiled := CompiledRoutingRule{
		RuleTag: "relayward-static-" + rule.RuleID, OutboundTag: rule.OutboundTag,
		Networks: splitNetwork(rule.Network), UserEmails: append([]string(nil), rule.Users...),
		InboundTags: append([]string(nil), rule.InboundTags...),
		Protocols:   append([]string(nil), rule.Protocols...), Attributes: cloneStringMap(rule.Attributes),
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
	if compiled.SourcePorts, err = config.ParseRoutingPorts(rule.SourcePort); err != nil {
		return CompiledRoutingRule{}, err
	}
	if compiled.VLESSRoutes, err = config.ParseRoutingPorts(rule.VLESSRoute); err != nil {
		return CompiledRoutingRule{}, err
	}
	return compiled, nil
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

func NeedsSniffing(configuration config.Configuration) bool {
	for _, rule := range configuration.Routing.Rules {
		if rule.Enabled && (len(rule.Domains) > 0 || len(rule.Protocols) > 0 || len(rule.Attributes) > 0) {
			return true
		}
	}
	return false
}

func renderRoutingRules(rules []CompiledRoutingRule) []any {
	values := make([]any, len(rules))
	for index, rule := range rules {
		value := map[string]any{
			"type": "field", "ruleTag": rule.RuleTag, "outboundTag": rule.OutboundTag,
		}
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

func cloneStringMap(value map[string]string) map[string]string {
	if len(value) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
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
