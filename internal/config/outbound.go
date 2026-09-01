package config

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	OutboundProtocolFreedom   = "freedom"
	OutboundProtocolBlackhole = "blackhole"

	OutboundTagDirect  = "direct"
	OutboundTagBlocked = "blocked"
)

var outboundDomainStrategies = map[string]struct{}{
	"": {}, "AsIs": {}, "UseIP": {}, "UseIPv4": {}, "UseIPv6": {}, "UseIPv6v4": {}, "UseIPv4v6": {},
	"ForceIP": {}, "ForceIPv6v4": {}, "ForceIPv6": {}, "ForceIPv4v6": {}, "ForceIPv4": {},
}

type Outbound struct {
	Tag       string                     `json:"tag"`
	Protocol  string                     `json:"protocol"`
	Freedom   *FreedomOutboundSettings   `json:"freedom,omitempty"`
	Blackhole *BlackholeOutboundSettings `json:"blackhole,omitempty"`
}

type FreedomOutboundSettings struct {
	DomainStrategy string             `json:"domain_strategy"`
	Redirect       string             `json:"redirect"`
	UserLevel      uint32             `json:"user_level"`
	ProxyProtocol  uint8              `json:"proxy_protocol"`
	Fragment       *FreedomFragment   `json:"fragment,omitempty"`
	Noises         []FreedomNoise     `json:"noises"`
	FinalRules     []FreedomFinalRule `json:"final_rules"`
}

type FreedomFragment struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
	MaxSplit string `json:"max_split"`
}

type FreedomNoise struct {
	Type    string `json:"type"`
	Packet  string `json:"packet"`
	Delay   string `json:"delay"`
	ApplyTo string `json:"apply_to"`
}

type FreedomFinalRule struct {
	Action     string   `json:"action"`
	Network    string   `json:"network"`
	Port       string   `json:"port"`
	IPs        []string `json:"ips"`
	BlockDelay string   `json:"block_delay"`
}

type BlackholeOutboundSettings struct {
	ResponseType string `json:"response_type"`
}

func DefaultOutbounds() []Outbound {
	return []Outbound{
		{
			Tag: OutboundTagDirect, Protocol: OutboundProtocolFreedom,
			Freedom: &FreedomOutboundSettings{
				DomainStrategy: "AsIs",
				Noises:         []FreedomNoise{},
				FinalRules:     []FreedomFinalRule{{Action: "allow", IPs: []string{}}},
			},
		},
		{
			Tag: OutboundTagBlocked, Protocol: OutboundProtocolBlackhole,
			Blackhole: &BlackholeOutboundSettings{},
		},
	}
}

func validateOutbounds(values []Outbound) error {
	if len(values) < 2 {
		return fmt.Errorf("outbounds: must contain direct and blocked outbounds")
	}
	if len(values) > MaximumOutbounds {
		return fmt.Errorf("outbounds: must contain at most %d outbounds", MaximumOutbounds)
	}
	seen := make(map[string]struct{}, len(values))
	hasDirect, hasBlocked := false, false
	for index, outbound := range values {
		field := fmt.Sprintf("outbounds[%d]", index)
		if err := validateDisplayName(outbound.Tag); err != nil {
			return fmt.Errorf("%s.tag: %w", field, err)
		}
		if outbound.Tag == "relayward-api" || strings.HasPrefix(outbound.Tag, "relayward/") {
			return fmt.Errorf("%s.tag: is reserved", field)
		}
		if _, exists := seen[outbound.Tag]; exists {
			return fmt.Errorf("%s.tag: duplicate outbound tag", field)
		}
		seen[outbound.Tag] = struct{}{}
		switch outbound.Protocol {
		case OutboundProtocolFreedom:
			if outbound.Freedom == nil || outbound.Blackhole != nil {
				return fmt.Errorf("%s: freedom settings are required and blackhole settings must be absent", field)
			}
			if err := validateFreedomOutbound(*outbound.Freedom, field+".freedom"); err != nil {
				return err
			}
		case OutboundProtocolBlackhole:
			if outbound.Blackhole == nil || outbound.Freedom != nil {
				return fmt.Errorf("%s: blackhole settings are required and freedom settings must be absent", field)
			}
			if err := validateBlackholeOutbound(*outbound.Blackhole, field+".blackhole"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s.protocol: must be freedom or blackhole", field)
		}
		switch outbound.Tag {
		case OutboundTagDirect:
			hasDirect = true
			if outbound.Protocol != OutboundProtocolFreedom {
				return fmt.Errorf("%s: direct must use the freedom protocol", field)
			}
		case OutboundTagBlocked:
			hasBlocked = true
			if outbound.Protocol != OutboundProtocolBlackhole {
				return fmt.Errorf("%s: blocked must use the blackhole protocol", field)
			}
		}
	}
	if !hasDirect || !hasBlocked {
		return fmt.Errorf("outbounds: must contain direct and blocked outbounds")
	}
	return nil
}

func validateFreedomOutbound(value FreedomOutboundSettings, field string) error {
	if _, exists := outboundDomainStrategies[value.DomainStrategy]; !exists {
		return fmt.Errorf("%s.domain_strategy: unsupported domain strategy", field)
	}
	if value.Redirect != "" {
		if err := validateRoutingText(value.Redirect); err != nil {
			return fmt.Errorf("%s.redirect: %w", field, err)
		}
	}
	if value.ProxyProtocol > 2 {
		return fmt.Errorf("%s.proxy_protocol: must be 0, 1, or 2", field)
	}
	if value.Fragment != nil {
		if value.Fragment.Packets != "" && value.Fragment.Packets != "tlshello" {
			if err := validatePositiveRange(value.Fragment.Packets); err != nil {
				return fmt.Errorf("%s.fragment.packets: %w", field, err)
			}
		}
		for name, item := range map[string]string{
			"length": value.Fragment.Length, "interval": value.Fragment.Interval, "max_split": value.Fragment.MaxSplit,
		} {
			if item == "" {
				continue
			}
			if err := validatePositiveRange(item); err != nil {
				return fmt.Errorf("%s.fragment.%s: %w", field, name, err)
			}
		}
		if value.Fragment.Length == "" && value.Fragment.Interval == "" && value.Fragment.MaxSplit == "" {
			return fmt.Errorf("%s.fragment: length, interval, or max_split is required", field)
		}
	}
	if len(value.Noises) > MaximumRoutingValues {
		return fmt.Errorf("%s.noises: must contain at most %d entries", field, MaximumRoutingValues)
	}
	for index, noise := range value.Noises {
		noiseField := fmt.Sprintf("%s.noises[%d]", field, index)
		switch noise.Type {
		case "rand", "str", "base64", "hex":
		default:
			return fmt.Errorf("%s.type: unsupported noise type", noiseField)
		}
		if err := validateRoutingText(noise.Packet); err != nil {
			return fmt.Errorf("%s.packet: %w", noiseField, err)
		}
		if err := validatePositiveRange(noise.Delay); err != nil {
			return fmt.Errorf("%s.delay: %w", noiseField, err)
		}
		switch noise.ApplyTo {
		case "ip", "ipv4", "ipv6":
		default:
			return fmt.Errorf("%s.apply_to: must be ip, ipv4, or ipv6", noiseField)
		}
	}
	if len(value.FinalRules) > MaximumRoutingValues {
		return fmt.Errorf("%s.final_rules: must contain at most %d entries", field, MaximumRoutingValues)
	}
	for index, rule := range value.FinalRules {
		ruleField := fmt.Sprintf("%s.final_rules[%d]", field, index)
		switch rule.Action {
		case "allow", "block":
		default:
			return fmt.Errorf("%s.action: must be allow or block", ruleField)
		}
		switch rule.Network {
		case "", "tcp", "udp", "tcp,udp":
		default:
			return fmt.Errorf("%s.network: must be empty, tcp, udp, or tcp,udp", ruleField)
		}
		if err := validateRoutingPorts(rule.Port, ruleField+".port"); err != nil {
			return err
		}
		if err := validateRoutingStringList(rule.IPs, ruleField+".ips", validateRoutingIPExpression); err != nil {
			return err
		}
		if rule.BlockDelay != "" {
			if rule.Action != "block" {
				return fmt.Errorf("%s.block_delay: is only valid for block rules", ruleField)
			}
			if err := validatePositiveRange(rule.BlockDelay); err != nil {
				return fmt.Errorf("%s.block_delay: %w", ruleField, err)
			}
		}
	}
	return nil
}

func validateBlackholeOutbound(value BlackholeOutboundSettings, field string) error {
	switch value.ResponseType {
	case "", "none", "http":
		return nil
	default:
		return fmt.Errorf("%s.response_type: must be empty, none, or http", field)
	}
}

func validatePositiveRange(value string) error {
	first, last, ok := strings.Cut(value, "-")
	if !ok || first == "" || last == "" {
		return fmt.Errorf("must be a positive numeric range")
	}
	from, firstErr := strconv.ParseUint(first, 10, 32)
	to, lastErr := strconv.ParseUint(last, 10, 32)
	if firstErr != nil || lastErr != nil || from == 0 || from > to || strconv.FormatUint(from, 10) != first || strconv.FormatUint(to, 10) != last {
		return fmt.Errorf("must be a positive numeric range")
	}
	return nil
}

func cloneOutbounds(values []Outbound) []Outbound {
	result := append([]Outbound{}, values...)
	for index := range result {
		if result[index].Freedom != nil {
			settings := *result[index].Freedom
			if settings.Fragment != nil {
				fragment := *settings.Fragment
				settings.Fragment = &fragment
			}
			settings.Noises = append([]FreedomNoise{}, settings.Noises...)
			settings.FinalRules = append([]FreedomFinalRule{}, settings.FinalRules...)
			for ruleIndex := range settings.FinalRules {
				settings.FinalRules[ruleIndex].IPs = append([]string{}, settings.FinalRules[ruleIndex].IPs...)
			}
			result[index].Freedom = &settings
		}
		if result[index].Blackhole != nil {
			settings := *result[index].Blackhole
			result[index].Blackhole = &settings
		}
	}
	return result
}
