package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	TCPHeaderNone  = "none"
	TCPHeaderHTTP  = "http"
	TProxyOff      = "off"
	TProxyRedirect = "redirect"
	TProxyTProxy   = "tproxy"
)

type TCPSettings struct {
	AcceptProxyProtocol bool      `json:"accept_proxy_protocol"`
	Header              TCPHeader `json:"header"`
}

type TCPHeader struct {
	Type     string           `json:"type"`
	Request  *TCPHTTPRequest  `json:"request,omitempty"`
	Response *TCPHTTPResponse `json:"response,omitempty"`
}

type TCPHTTPRequest struct {
	Version string              `json:"version"`
	Method  string              `json:"method"`
	Path    []string            `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type TCPHTTPResponse struct {
	Version string              `json:"version"`
	Status  string              `json:"status"`
	Reason  string              `json:"reason"`
	Headers map[string][]string `json:"headers"`
}

type Sniffing struct {
	Enabled         bool     `json:"enabled"`
	DestOverride    []string `json:"dest_override"`
	MetadataOnly    bool     `json:"metadata_only"`
	RouteOnly       bool     `json:"route_only"`
	IPsExcluded     []string `json:"ips_excluded"`
	DomainsExcluded []string `json:"domains_excluded"`
}

type SocketSettings struct {
	Mark                 int32           `json:"mark"`
	TCPFastOpen          bool            `json:"tcp_fast_open"`
	TProxy               string          `json:"tproxy"`
	AcceptProxyProtocol  bool            `json:"accept_proxy_protocol"`
	TCPMPTCP             bool            `json:"tcp_mptcp"`
	TCPKeepAliveInterval uint32          `json:"tcp_keep_alive_interval"`
	TCPKeepAliveIdle     uint32          `json:"tcp_keep_alive_idle"`
	TCPMaxSeg            uint32          `json:"tcp_max_seg"`
	TCPUserTimeout       uint32          `json:"tcp_user_timeout"`
	TCPWindowClamp       uint32          `json:"tcp_window_clamp"`
	TCPCongestion        string          `json:"tcp_congestion"`
	V6Only               bool            `json:"v6_only"`
	Custom               []CustomSockopt `json:"custom"`
}

type CustomSockopt struct {
	System  string `json:"system"`
	Network string `json:"network"`
	Level   string `json:"level"`
	Opt     string `json:"opt"`
	Type    string `json:"type"`
	Value   string `json:"value"`
}

type VLESSFallback struct {
	Name string `json:"name"`
	ALPN string `json:"alpn"`
	Path string `json:"path"`
	Dest string `json:"dest"`
	Xver uint8  `json:"xver"`
}

type RealityLimitFallback struct {
	AfterBytes       uint64 `json:"after_bytes"`
	BytesPerSec      uint64 `json:"bytes_per_sec"`
	BurstBytesPerSec uint64 `json:"burst_bytes_per_sec"`
}

func validateTCPSettings(value TCPSettings, field string) error {
	switch value.Header.Type {
	case TCPHeaderNone:
		if value.Header.Request != nil || value.Header.Response != nil {
			return fmt.Errorf("%s.header: none header must not contain HTTP settings", field)
		}
	case TCPHeaderHTTP:
		if value.Header.Request == nil || value.Header.Response == nil {
			return fmt.Errorf("%s.header: HTTP request and response settings are required", field)
		}
		if err := validateHTTPRequest(*value.Header.Request, field+".header.request"); err != nil {
			return err
		}
		if err := validateHTTPResponse(*value.Header.Response, field+".header.response"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s.header.type: must be %q or %q", field, TCPHeaderNone, TCPHeaderHTTP)
	}
	return nil
}

func validateHTTPRequest(value TCPHTTPRequest, field string) error {
	if value.Version == "" || value.Method == "" || len(value.Path) == 0 {
		return fmt.Errorf("%s: version, method, and at least one path are required", field)
	}
	for index, path := range value.Path {
		if path == "" || !strings.HasPrefix(path, "/") {
			return fmt.Errorf("%s.path[%d]: must start with /", field, index)
		}
	}
	return validateHTTPHeaders(value.Headers, field+".headers")
}

func validateHTTPResponse(value TCPHTTPResponse, field string) error {
	if value.Version == "" || value.Status == "" || value.Reason == "" {
		return fmt.Errorf("%s: version, status, and reason are required", field)
	}
	return validateHTTPHeaders(value.Headers, field+".headers")
}

func validateHTTPHeaders(values map[string][]string, field string) error {
	for name, entries := range values {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n:") || len(entries) == 0 {
			return fmt.Errorf("%s: invalid header name or empty value list", field)
		}
		for _, value := range entries {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("%s.%s: header values must not contain newlines", field, name)
			}
		}
	}
	return nil
}

func validateSniffing(value Sniffing, field string) error {
	seen := make(map[string]struct{}, len(value.DestOverride))
	for index, item := range value.DestOverride {
		switch item {
		case "http", "tls", "quic", "fakedns":
		default:
			return fmt.Errorf("%s.dest_override[%d]: unsupported destination override", field, index)
		}
		if _, exists := seen[item]; exists {
			return fmt.Errorf("%s.dest_override[%d]: duplicate destination override", field, index)
		}
		seen[item] = struct{}{}
	}
	if value.Enabled && len(value.DestOverride) == 0 {
		return fmt.Errorf("%s.dest_override: enabled sniffing requires at least one value", field)
	}
	for index, value := range value.IPsExcluded {
		if value == "" {
			return fmt.Errorf("%s.ips_excluded[%d]: must not be empty", field, index)
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.String() != value {
			return fmt.Errorf("%s.ips_excluded[%d]: CIDR must be canonical", field, index)
		}
	}
	for index, value := range value.DomainsExcluded {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s.domains_excluded[%d]: invalid domain expression", field, index)
		}
	}
	return nil
}

func validateSocketSettings(value *SocketSettings, field string) error {
	if value == nil {
		return nil
	}
	if value.Mark < 0 {
		return fmt.Errorf("%s.mark: must not be negative", field)
	}
	switch value.TProxy {
	case "", TProxyOff, TProxyRedirect, TProxyTProxy:
	default:
		return fmt.Errorf("%s.tproxy: unsupported TProxy mode", field)
	}
	switch value.TCPCongestion {
	case "", "bbr", "cubic", "reno":
	default:
		return fmt.Errorf("%s.tcp_congestion: unsupported congestion control", field)
	}
	for index, option := range value.Custom {
		if option.System != "" && option.System != "linux" {
			return fmt.Errorf("%s.custom[%d].system: only linux is supported", field, index)
		}
		if option.Type != "int" && option.Type != "str" {
			return fmt.Errorf("%s.custom[%d].type: must be int or str", field, index)
		}
		switch option.Network {
		case "", "tcp", "tcp4", "tcp6":
		default:
			return fmt.Errorf("%s.custom[%d].network: must be empty, tcp, tcp4, or tcp6", field, index)
		}
		for name, entry := range map[string]string{"level": option.Level, "opt": option.Opt, "value": option.Value} {
			if strings.TrimSpace(entry) == "" || strings.ContainsAny(entry, "\r\n") {
				return fmt.Errorf("%s.custom[%d].%s: must not be empty or contain newlines", field, index, name)
			}
		}
		for name, entry := range map[string]string{"level": option.Level, "opt": option.Opt} {
			parsed, err := strconv.ParseUint(entry, 10, 31)
			if err != nil || strconv.FormatUint(parsed, 10) != entry {
				return fmt.Errorf("%s.custom[%d].%s: must be a non-negative decimal integer", field, index, name)
			}
		}
		if option.Type == "int" {
			parsed, err := strconv.ParseInt(option.Value, 10, 32)
			if err != nil || strconv.FormatInt(parsed, 10) != option.Value {
				return fmt.Errorf("%s.custom[%d].value: must be a signed decimal integer for type int", field, index)
			}
		}
	}
	return nil
}

func validateVLESSFallbacks(values []VLESSFallback, field string) error {
	for index, value := range values {
		itemField := fmt.Sprintf("%s[%d]", field, index)
		if value.Xver > 2 {
			return fmt.Errorf("%s.xver: must be 0, 1, or 2", itemField)
		}
		if value.Path != "" && !strings.HasPrefix(value.Path, "/") {
			return fmt.Errorf("%s.path: must be empty or start with /", itemField)
		}
		if strings.TrimSpace(value.Dest) == "" || strings.ContainsAny(value.Dest, "\r\n") {
			return fmt.Errorf("%s.dest: is required", itemField)
		}
		if err := validateFallbackDestination(value.Dest); err != nil {
			return fmt.Errorf("%s.dest: %w", itemField, err)
		}
		for name, entry := range map[string]string{"name": value.Name, "alpn": value.ALPN} {
			if strings.ContainsAny(entry, "\r\n") {
				return fmt.Errorf("%s.%s: must not contain newlines", itemField, name)
			}
		}
	}
	return nil
}

func validateFallbackDestination(value string) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("must not contain surrounding whitespace")
	}
	if value == "serve-ws-none" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "@") {
		return nil
	}
	if port, err := strconv.ParseUint(value, 10, 16); err == nil && port != 0 {
		return nil
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("must be a port, host:port, or Unix socket")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return fmt.Errorf("must include a valid port")
	}
	return nil
}

func validateRealityLimitFallback(value *RealityLimitFallback, field string) error {
	if value == nil {
		return nil
	}
	if value.BytesPerSec == 0 && (value.AfterBytes != 0 || value.BurstBytesPerSec != 0) {
		return fmt.Errorf("%s.bytes_per_sec: is required when a fallback limit is configured", field)
	}
	if value.BurstBytesPerSec != 0 && value.BurstBytesPerSec < value.BytesPerSec {
		return fmt.Errorf("%s.burst_bytes_per_sec: must not be lower than bytes_per_sec", field)
	}
	return nil
}

func cloneTCPSettings(value TCPSettings) TCPSettings {
	value.Header.Request = cloneTCPHTTPRequest(value.Header.Request)
	value.Header.Response = cloneTCPHTTPResponse(value.Header.Response)
	return value
}

func cloneTCPHTTPRequest(value *TCPHTTPRequest) *TCPHTTPRequest {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Path = append([]string{}, value.Path...)
	clone.Headers = cloneHTTPHeaders(value.Headers)
	return &clone
}

func cloneTCPHTTPResponse(value *TCPHTTPResponse) *TCPHTTPResponse {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Headers = cloneHTTPHeaders(value.Headers)
	return &clone
}

func cloneHTTPHeaders(value map[string][]string) map[string][]string {
	if value == nil {
		return map[string][]string{}
	}
	clone := make(map[string][]string, len(value))
	for name, entries := range value {
		clone[name] = append([]string{}, entries...)
	}
	return clone
}

func cloneSniffing(value Sniffing) Sniffing {
	value.DestOverride = append([]string{}, value.DestOverride...)
	value.IPsExcluded = append([]string{}, value.IPsExcluded...)
	value.DomainsExcluded = append([]string{}, value.DomainsExcluded...)
	return value
}

func cloneSocketSettings(value *SocketSettings) *SocketSettings {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Custom = append([]CustomSockopt{}, value.Custom...)
	return &clone
}
