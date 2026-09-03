package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	EgressTypeDirect      = "direct"
	EgressTypeSOCKS5      = "socks5"
	EgressTypeShadowsocks = "shadowsocks"
	DefaultEgressLineID   = "default"
)

type EgressLine struct {
	LineID      string             `json:"line_id"`
	DisplayName string             `json:"display_name"`
	Enabled     bool               `json:"enabled"`
	VLESSRoute  uint16             `json:"vless_route"`
	Type        string             `json:"type"`
	Direct      *DirectEgress      `json:"direct,omitempty"`
	SOCKS5      *SOCKS5Egress      `json:"socks5,omitempty"`
	Shadowsocks *ShadowsocksEgress `json:"shadowsocks,omitempty"`
}

type DirectEgress struct {
	SendThrough string `json:"send_through"`
}

type SOCKS5Egress struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ShadowsocksEgress struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Method   string `json:"method"`
	Password string `json:"password"`
}

type EditableEgressLine struct {
	LineID      string                     `json:"line_id"`
	DisplayName string                     `json:"display_name"`
	Enabled     bool                       `json:"enabled"`
	VLESSRoute  uint16                     `json:"vless_route"`
	Type        string                     `json:"type"`
	Direct      *DirectEgress              `json:"direct,omitempty"`
	SOCKS5      *EditableSOCKS5Egress      `json:"socks5,omitempty"`
	Shadowsocks *EditableShadowsocksEgress `json:"shadowsocks,omitempty"`
}

type EditableSOCKS5Egress struct {
	Address            string `json:"address"`
	Port               uint16 `json:"port"`
	UseAuthentication  bool   `json:"use_authentication"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	PasswordConfigured bool   `json:"password_configured"`
}

type EditableShadowsocksEgress struct {
	Address            string `json:"address"`
	Port               uint16 `json:"port"`
	Method             string `json:"method"`
	Password           string `json:"password"`
	PasswordConfigured bool   `json:"password_configured"`
}

func DefaultEgressLine() EditableEgressLine {
	return EditableEgressLine{
		LineID: DefaultEgressLineID, DisplayName: "Default", Enabled: true,
		VLESSRoute: 0, Type: EgressTypeDirect, Direct: &DirectEgress{},
	}
}

func EgressOutboundTag(lineID string) string { return "relayward/egress/" + lineID }

func editableEgressLine(value EgressLine) EditableEgressLine {
	result := EditableEgressLine{
		LineID: value.LineID, DisplayName: value.DisplayName, Enabled: value.Enabled,
		VLESSRoute: value.VLESSRoute, Type: value.Type,
	}
	if value.Direct != nil {
		direct := *value.Direct
		result.Direct = &direct
	}
	if value.SOCKS5 != nil {
		result.SOCKS5 = &EditableSOCKS5Egress{
			Address: value.SOCKS5.Address, Port: value.SOCKS5.Port,
			UseAuthentication: value.SOCKS5.Username != "", Username: value.SOCKS5.Username,
			PasswordConfigured: value.SOCKS5.Password != "",
		}
	}
	if value.Shadowsocks != nil {
		result.Shadowsocks = &EditableShadowsocksEgress{
			Address: value.Shadowsocks.Address, Port: value.Shadowsocks.Port,
			Method: value.Shadowsocks.Method, PasswordConfigured: value.Shadowsocks.Password != "",
		}
	}
	return result
}

func mergeEgressLine(existing EgressLine, sameType bool, editable EditableEgressLine) (EgressLine, error) {
	result := EgressLine{
		LineID: editable.LineID, DisplayName: editable.DisplayName, Enabled: editable.Enabled,
		VLESSRoute: editable.VLESSRoute, Type: editable.Type,
	}
	switch editable.Type {
	case EgressTypeDirect:
		if editable.Direct == nil || editable.SOCKS5 != nil || editable.Shadowsocks != nil {
			return EgressLine{}, fmt.Errorf("direct: configuration is required")
		}
		direct := *editable.Direct
		result.Direct = &direct
	case EgressTypeSOCKS5:
		if editable.SOCKS5 == nil || editable.Direct != nil || editable.Shadowsocks != nil {
			return EgressLine{}, fmt.Errorf("socks5: configuration is required")
		}
		settings := editable.SOCKS5
		password := settings.Password
		if settings.UseAuthentication && password == "" && sameType && existing.SOCKS5 != nil {
			password = existing.SOCKS5.Password
		}
		if !settings.UseAuthentication {
			result.SOCKS5 = &SOCKS5Egress{Address: settings.Address, Port: settings.Port}
		} else {
			result.SOCKS5 = &SOCKS5Egress{
				Address: settings.Address, Port: settings.Port,
				Username: settings.Username, Password: password,
			}
		}
	case EgressTypeShadowsocks:
		if editable.Shadowsocks == nil || editable.Direct != nil || editable.SOCKS5 != nil {
			return EgressLine{}, fmt.Errorf("shadowsocks: configuration is required")
		}
		settings := editable.Shadowsocks
		password := settings.Password
		if password == "" && sameType && existing.Shadowsocks != nil {
			password = existing.Shadowsocks.Password
		}
		result.Shadowsocks = &ShadowsocksEgress{
			Address: settings.Address, Port: settings.Port, Method: settings.Method,
			Password: password,
		}
	default:
		return EgressLine{}, fmt.Errorf("unsupported egress type %q", editable.Type)
	}
	return result, nil
}

func validateEgressLines(values []EgressLine) error {
	if len(values) == 0 || len(values) > MaximumEgressLines {
		return fmt.Errorf("egress_lines: must contain between 1 and %d lines", MaximumEgressLines)
	}
	seenIDs := make(map[string]struct{}, len(values))
	seenRoutes := make(map[uint16]struct{}, len(values))
	for index, line := range values {
		field := fmt.Sprintf("egress_lines[%d]", index)
		if !serviceIDPattern.MatchString(line.LineID) {
			return fmt.Errorf("%s.line_id: invalid line ID", field)
		}
		if _, exists := seenIDs[line.LineID]; exists {
			return fmt.Errorf("%s.line_id: duplicate line ID", field)
		}
		seenIDs[line.LineID] = struct{}{}
		if _, exists := seenRoutes[line.VLESSRoute]; exists {
			return fmt.Errorf("%s.vless_route: duplicate VLESS route", field)
		}
		seenRoutes[line.VLESSRoute] = struct{}{}
		if err := validateDisplayName(line.DisplayName); err != nil {
			return fmt.Errorf("%s.display_name: %w", field, err)
		}
		if line.LineID == DefaultEgressLineID {
			if index != 0 || !line.Enabled || line.VLESSRoute != 0 {
				return fmt.Errorf("%s: default line must be first, enabled, and use VLESS route 0", field)
			}
		} else if line.VLESSRoute == 0 {
			return fmt.Errorf("%s.vless_route: route 0 is reserved for the default line", field)
		}
		switch line.Type {
		case EgressTypeDirect:
			if line.Direct == nil || line.SOCKS5 != nil || line.Shadowsocks != nil {
				return fmt.Errorf("%s.direct: configuration is required", field)
			}
			if line.Direct.SendThrough != "" {
				address, err := netip.ParseAddr(line.Direct.SendThrough)
				if err != nil || address.String() != line.Direct.SendThrough || address.IsUnspecified() || address.IsMulticast() {
					return fmt.Errorf("%s.direct.send_through: must be a canonical local unicast IP address", field)
				}
			}
		case EgressTypeSOCKS5:
			if line.SOCKS5 == nil || line.Direct != nil || line.Shadowsocks != nil {
				return fmt.Errorf("%s.socks5: configuration is required", field)
			}
			if err := validateProxyEndpoint(line.SOCKS5.Address, line.SOCKS5.Port); err != nil {
				return fmt.Errorf("%s.socks5: %w", field, err)
			}
			if (line.SOCKS5.Username == "") != (line.SOCKS5.Password == "") {
				return fmt.Errorf("%s.socks5: username and password must be configured together", field)
			}
			if err := validateCredential(line.SOCKS5.Username); err != nil {
				return fmt.Errorf("%s.socks5.username: %w", field, err)
			}
			if err := validateCredential(line.SOCKS5.Password); err != nil {
				return fmt.Errorf("%s.socks5.password: %w", field, err)
			}
		case EgressTypeShadowsocks:
			if line.Shadowsocks == nil || line.Direct != nil || line.SOCKS5 != nil {
				return fmt.Errorf("%s.shadowsocks: configuration is required", field)
			}
			if err := validateProxyEndpoint(line.Shadowsocks.Address, line.Shadowsocks.Port); err != nil {
				return fmt.Errorf("%s.shadowsocks: %w", field, err)
			}
			if !IsShadowsocksMethod(line.Shadowsocks.Method) {
				return fmt.Errorf("%s.shadowsocks.method: unsupported Shadowsocks 2022 method", field)
			}
			if line.Shadowsocks.Password == "" {
				return fmt.Errorf("%s.shadowsocks.password: is required", field)
			}
			if err := validateCredential(line.Shadowsocks.Password); err != nil {
				return fmt.Errorf("%s.shadowsocks.password: %w", field, err)
			}
		default:
			return fmt.Errorf("%s.type: unsupported egress type", field)
		}
	}
	if _, exists := seenIDs[DefaultEgressLineID]; !exists {
		return fmt.Errorf("egress_lines: default line is required")
	}
	return nil
}

func validateProxyEndpoint(host string, port uint16) error {
	if host == "" || host != strings.TrimSpace(host) || port == 0 {
		return fmt.Errorf("address and port are required")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.String() != host || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("address must be a canonical unicast IP or lowercase domain")
		}
		return nil
	}
	if host != strings.ToLower(host) || !validServerName(host) {
		return fmt.Errorf("address must be a canonical unicast IP or lowercase domain")
	}
	return nil
}

func validateCredential(value string) error {
	if !utf8.ValidString(value) || len(value) > 1024 {
		return fmt.Errorf("must contain at most 1024 valid UTF-8 bytes")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func EgressAddress(line EgressLine) string {
	switch line.Type {
	case EgressTypeDirect:
		return line.Direct.SendThrough
	case EgressTypeSOCKS5:
		return net.JoinHostPort(line.SOCKS5.Address, strconv.Itoa(int(line.SOCKS5.Port)))
	case EgressTypeShadowsocks:
		return net.JoinHostPort(line.Shadowsocks.Address, strconv.Itoa(int(line.Shadowsocks.Port)))
	default:
		return ""
	}
}

func cloneEgressLines(values []EgressLine) []EgressLine {
	result := append([]EgressLine(nil), values...)
	for index := range result {
		if result[index].Direct != nil {
			value := *result[index].Direct
			result[index].Direct = &value
		}
		if result[index].SOCKS5 != nil {
			value := *result[index].SOCKS5
			result[index].SOCKS5 = &value
		}
		if result[index].Shadowsocks != nil {
			value := *result[index].Shadowsocks
			result[index].Shadowsocks = &value
		}
	}
	return result
}
