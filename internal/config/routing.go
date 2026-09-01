package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	RoutingOutboundDirect  = OutboundTagDirect
	RoutingOutboundBlocked = OutboundTagBlocked
)

const (
	RoutingDomainSubstring = iota
	RoutingDomainRegex
	RoutingDomainSuffix
	RoutingDomainFull
)

const (
	defaultGeoIPFile   = "geoip.dat"
	defaultGeoSiteFile = "geosite.dat"
)

var (
	routingRuleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	routingAssetPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	routingAttributeKey  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type RoutingConfiguration struct {
	Rules []RoutingRule `json:"rules"`
}

// RoutingRule mirrors the field-rule surface exposed by 3x-ui. RuleID and
// DisplayName are Relayward metadata and are not rendered into Xray.
type RoutingRule struct {
	RuleID          string            `json:"rule_id"`
	DisplayName     string            `json:"display_name"`
	Enabled         bool              `json:"enabled"`
	SourceIPs       []string          `json:"source_ips"`
	SourcePort      string            `json:"source_port"`
	VLESSRoute      string            `json:"vless_route"`
	Network         string            `json:"network"`
	Protocols       []string          `json:"protocols"`
	Attributes      map[string]string `json:"attributes"`
	DestinationIPs  []string          `json:"destination_ips"`
	Domains         []string          `json:"domains"`
	Users           []string          `json:"users"`
	DestinationPort string            `json:"destination_port"`
	InboundTags     []string          `json:"inbound_tags"`
	OutboundTag     string            `json:"outbound_tag"`
}

type RoutingPortRange struct {
	From uint16
	To   uint16
}

type RoutingDomainExpression struct {
	Raw      string
	Type     int
	Value    string
	GeoFile  string
	GeoCode  string
	GeoAttrs string
}

type RoutingIPExpression struct {
	Raw     string
	Prefix  netip.Prefix
	GeoFile string
	GeoCode string
	Reverse bool
}

func validateRouting(value RoutingConfiguration, services []Service, outbounds []Outbound, xrayVersion string) error {
	if len(value.Rules) > MaximumRoutingRules {
		return fmt.Errorf("routing.rules: must contain at most %d rules", MaximumRoutingRules)
	}
	serviceIDs := make(map[string]struct{}, len(services))
	for _, service := range services {
		serviceIDs[service.ServiceID] = struct{}{}
	}
	outboundTags := make(map[string]struct{}, len(outbounds))
	for _, outbound := range outbounds {
		outboundTags[outbound.Tag] = struct{}{}
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
		if _, exists := outboundTags[rule.OutboundTag]; !exists {
			return fmt.Errorf("%s.outbound_tag: unknown outbound", field)
		}
		if err := validateRoutingStringList(rule.SourceIPs, field+".source_ips", validateRoutingIPExpression); err != nil {
			return err
		}
		if err := validateRoutingStringList(rule.DestinationIPs, field+".destination_ips", validateRoutingIPExpression); err != nil {
			return err
		}
		if err := validateRoutingStringList(rule.Domains, field+".domains", validateRoutingDomainExpression); err != nil {
			return err
		}
		if err := validateRoutingPorts(rule.SourcePort, field+".source_port"); err != nil {
			return err
		}
		if err := validateRoutingPorts(rule.DestinationPort, field+".destination_port"); err != nil {
			return err
		}
		if err := validateRoutingPorts(rule.VLESSRoute, field+".vless_route"); err != nil {
			return err
		}
		switch rule.Network {
		case "", "tcp", "udp", "tcp,udp":
		default:
			return fmt.Errorf("%s.network: must be empty, tcp, udp, or tcp,udp", field)
		}
		if err := validateRoutingProtocols(rule.Protocols, field+".protocols"); err != nil {
			return err
		}
		if err := validateRoutingPlainValues(rule.Users, field+".users"); err != nil {
			return err
		}
		if err := validateRoutingInboundTags(rule.InboundTags, serviceIDs, field+".inbound_tags"); err != nil {
			return err
		}
		if err := validateRoutingAttributes(rule.Attributes, field+".attributes"); err != nil {
			return err
		}
		if routingRuleConditionCount(rule) == 0 {
			return fmt.Errorf("%s: must contain at least one match field", field)
		}
		if compareVersions(xrayVersion, MinimumVLESSXrayVersion) < 0 && routingRuleUsesGeodata(rule) {
			return fmt.Errorf("%s: geosite and geoip rules require Xray %s or newer", field, MinimumVLESSXrayVersion)
		}
	}
	return nil
}

func routingRuleConditionCount(rule RoutingRule) int {
	return len(rule.SourceIPs) + len(rule.Protocols) + len(rule.Attributes) +
		len(rule.DestinationIPs) + len(rule.Domains) + len(rule.Users) + len(rule.InboundTags) +
		boolInt(rule.SourcePort != "") + boolInt(rule.VLESSRoute != "") +
		boolInt(rule.Network != "") + boolInt(rule.DestinationPort != "")
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func routingRuleUsesGeodata(rule RoutingRule) bool {
	for _, value := range rule.Domains {
		parsed, _ := ParseRoutingDomainExpression(value)
		if parsed.GeoFile != "" {
			return true
		}
	}
	for _, values := range [][]string{rule.SourceIPs, rule.DestinationIPs} {
		for _, value := range values {
			parsed, _ := ParseRoutingIPExpression(value)
			if parsed.GeoFile != "" {
				return true
			}
		}
	}
	return false
}

func validateRoutingStringList(values []string, field string, validate func(string) error) error {
	if len(values) > MaximumRoutingValues {
		return fmt.Errorf("%s: must contain at most %d values", field, MaximumRoutingValues)
	}
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validate(value); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, index, err)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s[%d]: duplicate value", field, index)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRoutingDomains(values []string, field string) error {
	return validateRoutingStringList(values, field, func(value string) error {
		if value != strings.ToLower(value) || !validServerName(value) {
			return fmt.Errorf("must be a lowercase domain name")
		}
		return nil
	})
}

func validateRoutingDomainExpression(value string) error {
	_, err := ParseRoutingDomainExpression(value)
	return err
}

func ParseRoutingDomainExpression(value string) (RoutingDomainExpression, error) {
	parsed := RoutingDomainExpression{Raw: value, Type: RoutingDomainSubstring}
	if err := validateRoutingText(value); err != nil {
		return parsed, err
	}
	if strings.HasPrefix(value, "geosite:") {
		value = "ext:" + defaultGeoSiteFile + ":" + strings.TrimPrefix(value, "geosite:")
	}
	for _, prefix := range []string{"ext:", "ext-domain:", "ext-site:"} {
		if strings.HasPrefix(value, prefix) {
			file, codeWithAttrs, ok := strings.Cut(strings.TrimPrefix(value, prefix), ":")
			if !ok || !routingAssetPattern.MatchString(file) {
				return parsed, fmt.Errorf("invalid geosite file or code")
			}
			code, attrs, _ := strings.Cut(codeWithAttrs, "@")
			if code == "" || strings.HasSuffix(codeWithAttrs, "@") || strings.Contains(codeWithAttrs, "@@") {
				return parsed, fmt.Errorf("invalid geosite file or code")
			}
			parsed.GeoFile = file
			parsed.GeoCode = strings.ToUpper(code)
			parsed.GeoAttrs = strings.ToLower(attrs)
			return parsed, nil
		}
	}
	switch {
	case strings.HasPrefix(value, "regexp:"):
		parsed.Type, parsed.Value = RoutingDomainRegex, strings.TrimPrefix(value, "regexp:")
		if parsed.Value == "" {
			return parsed, fmt.Errorf("regular expression must not be empty")
		}
		if _, err := regexp.Compile(parsed.Value); err != nil {
			return parsed, fmt.Errorf("invalid regular expression")
		}
	case strings.HasPrefix(value, "domain:"):
		parsed.Type, parsed.Value = RoutingDomainSuffix, strings.TrimPrefix(value, "domain:")
	case strings.HasPrefix(value, "full:"):
		parsed.Type, parsed.Value = RoutingDomainFull, strings.TrimPrefix(value, "full:")
	case strings.HasPrefix(value, "keyword:"):
		parsed.Value = strings.TrimPrefix(value, "keyword:")
	case strings.HasPrefix(value, "dotless:"):
		part := strings.TrimPrefix(value, "dotless:")
		if strings.Contains(part, ".") {
			return parsed, fmt.Errorf("dotless value must not contain a dot")
		}
		parsed.Type = RoutingDomainRegex
		if part == "" {
			parsed.Value = `^[^.]*$`
		} else {
			parsed.Value = `^[^.]*` + regexp.QuoteMeta(part) + `[^.]*$`
		}
	default:
		parsed.Value = value
	}
	if parsed.Value == "" {
		return parsed, fmt.Errorf("domain value must not be empty")
	}
	return parsed, nil
}

func validateRoutingIPExpression(value string) error {
	_, err := ParseRoutingIPExpression(value)
	return err
}

func ParseRoutingIPExpression(value string) (RoutingIPExpression, error) {
	parsed := RoutingIPExpression{Raw: value}
	if err := validateRoutingText(value); err != nil {
		return parsed, err
	}
	raw := value
	for strings.HasPrefix(raw, "!") {
		parsed.Reverse = !parsed.Reverse
		raw = strings.TrimPrefix(raw, "!")
	}
	if strings.HasPrefix(raw, "geoip:") {
		raw = "ext:" + defaultGeoIPFile + ":" + strings.TrimPrefix(raw, "geoip:")
	}
	for _, prefix := range []string{"ext:", "ext-ip:"} {
		if strings.HasPrefix(raw, prefix) {
			file, code, ok := strings.Cut(strings.TrimPrefix(raw, prefix), ":")
			if !ok || !routingAssetPattern.MatchString(file) {
				return parsed, fmt.Errorf("invalid geoip file or code")
			}
			for strings.HasPrefix(code, "!") {
				parsed.Reverse = !parsed.Reverse
				code = strings.TrimPrefix(code, "!")
			}
			if code == "" {
				return parsed, fmt.Errorf("invalid geoip file or code")
			}
			parsed.GeoFile = file
			parsed.GeoCode = strings.ToUpper(code)
			return parsed, nil
		}
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		parsed.Prefix = netip.PrefixFrom(address, address.BitLen())
		return parsed, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix != prefix.Masked() || prefix.String() != raw {
		return parsed, fmt.Errorf("must be an IP address, canonical CIDR, or geoip expression")
	}
	parsed.Prefix = prefix
	return parsed, nil
}

func validateRoutingPorts(value, field string) error {
	if value == "" {
		return nil
	}
	if _, err := ParseRoutingPorts(value); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func ParseRoutingPorts(value string) ([]RoutingPortRange, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > MaximumRoutingValues {
		return nil, fmt.Errorf("must contain at most %d port ranges", MaximumRoutingValues)
	}
	ranges := make([]RoutingPortRange, 0, len(parts))
	for _, part := range parts {
		if part == "" || part != strings.TrimSpace(part) {
			return nil, fmt.Errorf("must use comma-separated ports or ranges without spaces")
		}
		first, last, hasRange := strings.Cut(part, "-")
		if !hasRange {
			last = first
		}
		from, err := strconv.ParseUint(first, 10, 16)
		if err != nil || from == 0 {
			return nil, fmt.Errorf("contains an invalid port")
		}
		to, err := strconv.ParseUint(last, 10, 16)
		if err != nil || to == 0 || from > to {
			return nil, fmt.Errorf("contains an invalid port range")
		}
		ranges = append(ranges, RoutingPortRange{From: uint16(from), To: uint16(to)})
	}
	return ranges, nil
}

func validateRoutingProtocols(values []string, field string) error {
	return validateRoutingStringList(values, field, func(value string) error {
		switch value {
		case "http", "tls", "quic", "bittorrent":
			return nil
		default:
			return fmt.Errorf("unsupported protocol")
		}
	})
}

func validateRoutingPlainValues(values []string, field string) error {
	return validateRoutingStringList(values, field, validateRoutingText)
}

func validateRoutingInboundTags(values []string, serviceIDs map[string]struct{}, field string) error {
	return validateRoutingStringList(values, field, func(value string) error {
		if _, exists := serviceIDs[value]; !exists {
			return fmt.Errorf("unknown inbound")
		}
		return nil
	})
}

func validateRoutingAttributes(values map[string]string, field string) error {
	if len(values) > MaximumRoutingValues {
		return fmt.Errorf("%s: must contain at most %d values", field, MaximumRoutingValues)
	}
	for key, value := range values {
		if !routingAttributeKey.MatchString(key) {
			return fmt.Errorf("%s: invalid attribute name", field)
		}
		if err := validateRoutingText(value); err != nil {
			return fmt.Errorf("%s.%s: %w", field, key, err)
		}
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("%s.%s: invalid regular expression", field, key)
		}
	}
	return nil
}

func validateRoutingText(value string) error {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 512 {
		return fmt.Errorf("must contain 1 to 512 trimmed characters")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func cloneRouting(value RoutingConfiguration) RoutingConfiguration {
	rules := make([]RoutingRule, len(value.Rules))
	for index, rule := range value.Rules {
		rule.SourceIPs = append([]string{}, rule.SourceIPs...)
		rule.Protocols = append([]string{}, rule.Protocols...)
		rule.DestinationIPs = append([]string{}, rule.DestinationIPs...)
		rule.Domains = append([]string{}, rule.Domains...)
		rule.Users = append([]string{}, rule.Users...)
		rule.InboundTags = append([]string{}, rule.InboundTags...)
		rule.Attributes = make(map[string]string, len(rule.Attributes))
		for key, value := range value.Rules[index].Attributes {
			rule.Attributes[key] = value
		}
		rules[index] = rule
	}
	value.Rules = rules
	return value
}
