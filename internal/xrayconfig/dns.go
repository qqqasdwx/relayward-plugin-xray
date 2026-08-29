package xrayconfig

import (
	"strings"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func renderDNS(value config.DNSConfiguration) map[string]any {
	servers := make([]any, 0, len(value.Servers))
	disableFallbackIfMatch := false
	for _, server := range value.Servers {
		if !server.Enabled {
			continue
		}
		domains := make([]string, len(server.Domains))
		for index, domain := range server.Domains {
			domains[index] = "domain:" + domain
		}
		if len(domains) > 0 {
			disableFallbackIfMatch = true
		}
		item := map[string]any{
			"address":       dnsServerAddress(server),
			"domains":       domains,
			"queryStrategy": xrayDNSQueryStrategy(value.QueryStrategy),
			"skipFallback":  len(domains) > 0,
		}
		if server.Port != 0 {
			item["port"] = server.Port
		}
		servers = append(servers, item)
	}
	return map[string]any{
		"servers":                servers,
		"queryStrategy":          xrayDNSQueryStrategy(value.QueryStrategy),
		"disableFallbackIfMatch": disableFallbackIfMatch,
	}
}

func dnsServerAddress(value config.DNSServer) string {
	switch value.Transport {
	case config.DNSTransportSystem:
		return "localhost"
	case config.DNSTransportTCP:
		if strings.Contains(value.Address, ":") {
			return "tcp+local://[" + value.Address + "]"
		}
		return "tcp+local://" + value.Address
	case config.DNSTransportDoH:
		return "https+local://" + strings.TrimPrefix(value.Address, "https://")
	default:
		return value.Address
	}
}

func xrayDNSQueryStrategy(value string) string {
	switch value {
	case config.DNSQueryStrategyUseIPv4:
		return "UseIPv4"
	case config.DNSQueryStrategyUseIPv6:
		return "UseIPv6"
	default:
		return "UseIP"
	}
}
