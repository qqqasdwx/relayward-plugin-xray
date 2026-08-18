package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	DNSQueryStrategyUseIP   = "use-ip"
	DNSQueryStrategyUseIPv4 = "use-ipv4"
	DNSQueryStrategyUseIPv6 = "use-ipv6"

	DNSTransportSystem = "system"
	DNSTransportUDP    = "udp"
	DNSTransportTCP    = "tcp"
	DNSTransportDoH    = "doh"
)

type DNSConfiguration struct {
	Enabled       bool        `json:"enabled"`
	QueryStrategy string      `json:"query_strategy"`
	Servers       []DNSServer `json:"servers"`
}

type DNSServer struct {
	ServerID    string   `json:"server_id"`
	DisplayName string   `json:"display_name"`
	Enabled     bool     `json:"enabled"`
	Transport   string   `json:"transport"`
	Address     string   `json:"address"`
	Port        uint16   `json:"port"`
	Domains     []string `json:"domains"`
}

func validateDNS(value DNSConfiguration) error {
	if !value.Enabled && value.QueryStrategy == "" && len(value.Servers) == 0 {
		return nil
	}
	switch value.QueryStrategy {
	case DNSQueryStrategyUseIP, DNSQueryStrategyUseIPv4, DNSQueryStrategyUseIPv6:
	default:
		return fmt.Errorf("dns.query_strategy: must be use-ip, use-ipv4, or use-ipv6")
	}
	if len(value.Servers) > MaximumDNSServers {
		return fmt.Errorf("dns.servers: must contain at most %d servers", MaximumDNSServers)
	}
	seenIDs := make(map[string]struct{}, len(value.Servers))
	enabledServers := 0
	for index, server := range value.Servers {
		field := fmt.Sprintf("dns.servers[%d]", index)
		if !serviceIDPattern.MatchString(server.ServerID) {
			return fmt.Errorf("%s.server_id: must match %s", field, serviceIDPattern)
		}
		if _, exists := seenIDs[server.ServerID]; exists {
			return fmt.Errorf("%s.server_id: duplicate server ID", field)
		}
		seenIDs[server.ServerID] = struct{}{}
		if err := validateDisplayName(server.DisplayName); err != nil {
			return fmt.Errorf("%s.display_name: %w", field, err)
		}
		if server.Enabled {
			enabledServers++
		}
		if err := validateDNSServerEndpoint(server, field); err != nil {
			return err
		}
		if err := validateRoutingDomains(server.Domains, field+".domains"); err != nil {
			return err
		}
	}
	if value.Enabled && enabledServers == 0 {
		return fmt.Errorf("dns.servers: must contain at least one enabled server")
	}
	return nil
}

func validateDNSServerEndpoint(server DNSServer, field string) error {
	switch server.Transport {
	case DNSTransportSystem:
		if server.Address != "" || server.Port != 0 {
			return fmt.Errorf("%s: system DNS must not specify address or port", field)
		}
	case DNSTransportUDP, DNSTransportTCP:
		address, err := netip.ParseAddr(server.Address)
		if err != nil || address.String() != server.Address {
			return fmt.Errorf("%s.address: must be a canonical IP address", field)
		}
		if server.Port == 0 {
			return fmt.Errorf("%s.port: must be between 1 and 65535", field)
		}
	case DNSTransportDoH:
		if server.Port != 0 {
			return fmt.Errorf("%s.port: DNS-over-HTTPS port must be part of the URL", field)
		}
		if err := validateDoHURL(server.Address); err != nil {
			return fmt.Errorf("%s.address: %w", field, err)
		}
	default:
		return fmt.Errorf("%s.transport: must be system, udp, tcp, or doh", field)
	}
	return nil
}

func validateDoHURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("must be an HTTPS URL without credentials or a fragment")
	}
	host := parsed.Hostname()
	if address, addressErr := netip.ParseAddr(host); addressErr == nil {
		if address.String() != host {
			return fmt.Errorf("must use a canonical IP address or lowercase domain")
		}
	} else if host != strings.ToLower(host) || !validServerName(host) {
		return fmt.Errorf("must use a canonical IP address or lowercase domain")
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 || strconv.FormatUint(value, 10) != port {
			return fmt.Errorf("contains an invalid port")
		}
	}
	return nil
}

func cloneDNS(value DNSConfiguration) DNSConfiguration {
	value.Servers = append([]DNSServer{}, value.Servers...)
	for index := range value.Servers {
		value.Servers[index].Domains = append([]string{}, value.Servers[index].Domains...)
	}
	return value
}
