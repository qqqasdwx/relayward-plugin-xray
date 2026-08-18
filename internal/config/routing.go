package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const (
	RoutingActionDirect  = "direct"
	RoutingActionBlocked = "blocked"
)

var routingRuleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type RoutingConfiguration struct {
	Rules []RoutingRule `json:"rules"`
}

type RoutingRule struct {
	RuleID      string   `json:"rule_id"`
	DisplayName string   `json:"display_name"`
	Enabled     bool     `json:"enabled"`
	Domains     []string `json:"domains"`
	IPCIDRs     []string `json:"ip_cidrs"`
	Protocols   []string `json:"protocols"`
	Action      string   `json:"action"`
}

func validateRouting(value RoutingConfiguration) error {
	if len(value.Rules) > MaximumRoutingRules {
		return fmt.Errorf("routing.rules: must contain at most %d rules", MaximumRoutingRules)
	}
	seenIDs := make(map[string]struct{}, len(value.Rules))
	for index, rule := range value.Rules {
		field := fmt.Sprintf("routing.rules[%d]", index)
		if !routingRuleIDPattern.MatchString(rule.RuleID) {
			return fmt.Errorf("%s.rule_id: must match %s", field, routingRuleIDPattern)
		}
		if _, exists := seenIDs[rule.RuleID]; exists {
			return fmt.Errorf("%s.rule_id: duplicate rule ID", field)
		}
		seenIDs[rule.RuleID] = struct{}{}
		if err := validateDisplayName(rule.DisplayName); err != nil {
			return fmt.Errorf("%s.display_name: %w", field, err)
		}
		switch rule.Action {
		case RoutingActionDirect, RoutingActionBlocked:
		default:
			return fmt.Errorf("%s.action: must be direct or blocked", field)
		}
		if len(rule.Domains)+len(rule.IPCIDRs)+len(rule.Protocols) == 0 {
			return fmt.Errorf("%s: must contain at least one match value", field)
		}
		if err := validateRoutingDomains(rule.Domains, field+".domains"); err != nil {
			return err
		}
		if err := validateRoutingCIDRs(rule.IPCIDRs, field+".ip_cidrs"); err != nil {
			return err
		}
		if err := validateRoutingProtocols(rule.Protocols, field+".protocols"); err != nil {
			return err
		}
	}
	return nil
}

func validateRoutingDomains(values []string, field string) error {
	if len(values) > MaximumRoutingValues {
		return fmt.Errorf("%s: must contain at most %d values", field, MaximumRoutingValues)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value != strings.ToLower(value) || !validServerName(value) {
			return fmt.Errorf("%s[%d]: must be a lowercase domain name", field, index)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d]: duplicate domain", field, index)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRoutingCIDRs(values []string, field string) error {
	if len(values) > MaximumRoutingValues {
		return fmt.Errorf("%s: must contain at most %d values", field, MaximumRoutingValues)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return fmt.Errorf("%s[%d]: must be a canonical IP CIDR", field, index)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d]: duplicate CIDR", field, index)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRoutingProtocols(values []string, field string) error {
	if len(values) > MaximumRoutingValues {
		return fmt.Errorf("%s: must contain at most %d values", field, MaximumRoutingValues)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		switch value {
		case "http", "tls", "quic", "bittorrent":
		default:
			return fmt.Errorf("%s[%d]: unsupported protocol", field, index)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d]: duplicate protocol", field, index)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func cloneRouting(value RoutingConfiguration) RoutingConfiguration {
	rules := make([]RoutingRule, len(value.Rules))
	for index, rule := range value.Rules {
		rule.Domains = append([]string{}, rule.Domains...)
		rule.IPCIDRs = append([]string{}, rule.IPCIDRs...)
		rule.Protocols = append([]string{}, rule.Protocols...)
		rules[index] = rule
	}
	value.Rules = rules
	return value
}
