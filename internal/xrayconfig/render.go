package xrayconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

const (
	realityTunnelPortStart       = 49152
	realityTunnelPortCount       = 16384
	diagnosticPortStart          = 30000
	diagnosticPortCount          = 10000
	realityMinimumClientVersion  = "1.0.0"
	realityFallbackAfterBytes    = 10 * 1024 * 1024
	realityFallbackBytesPerSec   = 1024 * 1024
	realityFallbackBurstBytesSec = 5 * 1024 * 1024
)

func SupportsServiceType(serviceType string) bool {
	return serviceType == config.ServiceTypeVLESSReality || serviceType == config.ServiceTypeShadowsocks
}

func Render(value config.Configuration) ([]byte, error) {
	if err := config.Validate(value); err != nil {
		return nil, err
	}
	routingRules, err := CompileRoutingRules(value, nil)
	if err != nil {
		return nil, err
	}
	tunnelPorts, err := allocateRealityTunnelPorts(value)
	if err != nil {
		return nil, err
	}
	diagnosticPorts, err := allocateDiagnosticPorts(value)
	if err != nil {
		return nil, err
	}
	inbounds := []any{map[string]any{
		"tag": APIRuleTag, "listen": "127.0.0.1", "port": value.APIPort,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
	}}
	for _, line := range value.EgressLines {
		if !line.Enabled {
			continue
		}
		inbounds = append(inbounds, map[string]any{
			"tag": diagnosticInboundTag(line.LineID), "listen": "127.0.0.1", "port": diagnosticPorts[line.LineID],
			"protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false},
		})
	}
	for _, service := range value.Services {
		if !service.Enabled {
			continue
		}
		serviceInbounds, err := renderService(value, service, tunnelPorts)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, serviceInbounds...)
	}
	outbounds, err := renderOutbounds(value.EgressLines)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": "none"},
		"api":       map[string]any{"tag": APIRuleTag, "services": []string{"HandlerService", "RoutingService", "StatsService", "LoggerService"}},
		"dns":       map[string]any{"servers": []string{"localhost"}, "queryStrategy": "UseIP"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
		}}},
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": renderRoutingRules(routingRules)},
		"stats":   map[string]any{},
	}
	if !value.DisableAccessLog {
		result["log"].(map[string]any)["access"] = "access.log"
	}
	return json.Marshal(result)
}

func renderOutbounds(lines []config.EgressLine) ([]any, error) {
	result := make([]any, 0, len(lines)+2)
	for _, line := range lines {
		if !line.Enabled {
			continue
		}
		outbound, err := renderEgressLine(line)
		if err != nil {
			return nil, err
		}
		result = append(result, outbound)
	}
	result = append(result,
		map[string]any{"tag": SystemDirectOutboundTag, "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs"}},
		map[string]any{"tag": BlockedOutboundTag, "protocol": "blackhole", "settings": map[string]any{}},
	)
	return result, nil
}

func renderEgressLine(line config.EgressLine) (any, error) {
	value := map[string]any{"tag": config.EgressOutboundTag(line.LineID)}
	switch line.Type {
	case config.EgressTypeDirect:
		value["protocol"] = "freedom"
		settings := map[string]any{"domainStrategy": "UseIP"}
		if line.Direct.SendThrough != "" {
			value["sendThrough"] = line.Direct.SendThrough
			address, _ := netip.ParseAddr(line.Direct.SendThrough)
			if address.Is4() {
				settings["domainStrategy"] = "UseIPv4"
			} else {
				settings["domainStrategy"] = "UseIPv6"
			}
		}
		value["settings"] = settings
	case config.EgressTypeSOCKS5:
		value["protocol"] = "socks"
		settings := map[string]any{"address": line.SOCKS5.Address, "port": line.SOCKS5.Port}
		if line.SOCKS5.Username != "" {
			settings["user"] = line.SOCKS5.Username
			settings["pass"] = line.SOCKS5.Password
		}
		value["settings"] = settings
	case config.EgressTypeShadowsocks:
		value["protocol"] = "shadowsocks"
		value["settings"] = map[string]any{
			"address": line.Shadowsocks.Address, "port": line.Shadowsocks.Port,
			"method": line.Shadowsocks.Method, "password": line.Shadowsocks.Password,
		}
	default:
		return nil, fmt.Errorf("unsupported egress type %q", line.Type)
	}
	return value, nil
}

func renderService(configuration config.Configuration, service config.Service, tunnelPorts map[string]uint16) ([]any, error) {
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		return renderVLESSReality(service, tunnelPorts[service.ServiceID])
	case config.ServiceTypeShadowsocks:
		inbound, err := renderShadowsocks(configuration, service)
		if err != nil {
			return nil, err
		}
		return []any{inbound}, nil
	default:
		return nil, fmt.Errorf("unsupported Xray service type %q", service.Type)
	}
}

func renderShadowsocks(configuration config.Configuration, service config.Service) (any, error) {
	settings := service.Shadowsocks
	bootstrapKey, err := config.DeriveShadowsocksPassword(configuration.CredentialSeed, "bootstrap", service.ServiceID, settings.Method)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"tag": service.ServiceID, "port": service.Port, "protocol": "shadowsocks",
		"settings": map[string]any{
			"method": settings.Method, "password": settings.ServerKey, "network": "tcp,udp",
			"clients": []any{map[string]any{"email": config.UserEmail("bootstrap", service.ServiceID), "password": bootstrapKey}},
		},
		"sniffing": managedSniffing(),
	}, nil
}

func renderVLESSReality(service config.Service, tunnelPort uint16) ([]any, error) {
	reality := service.VLESSReality
	targetHost, targetPort, err := splitRealityTarget(reality.Target)
	if err != nil {
		return nil, fmt.Errorf("render VLESS REALITY service %q: %w", service.ServiceID, err)
	}
	streamSettings := map[string]any{
		"method": "raw", "security": "reality",
		"realitySettings": map[string]any{
			"target": net.JoinHostPort("127.0.0.1", strconv.Itoa(int(tunnelPort))), "xver": 2,
			"serverNames": []string{targetHost}, "privateKey": reality.PrivateKey,
			"shortIds": []string{reality.ShortID}, "minClientVer": realityMinimumClientVersion,
			"limitFallbackUpload": realityFallbackLimit(), "limitFallbackDownload": realityFallbackLimit(),
		},
	}
	if service.AcceptProxyProtocol {
		streamSettings["rawSettings"] = map[string]any{"acceptProxyProtocol": true}
	}
	vlessInbound := map[string]any{
		"tag": service.ServiceID, "port": service.Port, "protocol": "vless",
		"settings": map[string]any{"decryption": "none"}, "streamSettings": streamSettings,
		"sniffing": managedSniffing(),
	}
	tunnelInbound := map[string]any{
		"tag": realityTunnelTag(service.ServiceID), "listen": "127.0.0.1", "port": tunnelPort,
		"protocol": "tunnel",
		"settings": map[string]any{"rewriteAddress": targetHost, "rewritePort": targetPort, "allowedNetwork": "tcp"},
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"tls"}, "routeOnly": true},
		"streamSettings": map[string]any{
			"method": "raw", "security": "none", "rawSettings": map[string]any{"acceptProxyProtocol": true},
		},
	}
	return []any{vlessInbound, tunnelInbound}, nil
}

func managedSniffing() map[string]any {
	return map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
}

func realityFallbackLimit() map[string]any {
	return map[string]any{
		"afterBytes": realityFallbackAfterBytes, "bytesPerSec": realityFallbackBytesPerSec,
		"burstBytesPerSec": realityFallbackBurstBytesSec,
	}
}

func splitRealityTarget(target string) (string, uint16, error) {
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid camouflage target")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid camouflage target port")
	}
	return host, uint16(port), nil
}

func realityServerName(service config.Service) string {
	host, _, _ := splitRealityTarget(service.VLESSReality.Target)
	return host
}

func allocateRealityTunnelPorts(configuration config.Configuration) (map[string]uint16, error) {
	used := reservedPorts(configuration)
	return allocatePorts(configuration.CredentialSeed, "reality-tunnel", realityTunnelPortStart, realityTunnelPortCount,
		configuration.Services, func(service config.Service) (string, bool) {
			return service.ServiceID, service.Type == config.ServiceTypeVLESSReality
		}, used)
}

func allocateDiagnosticPorts(configuration config.Configuration) (map[string]uint16, error) {
	used := reservedPorts(configuration)
	values := make([]config.Service, len(configuration.EgressLines))
	for index, line := range configuration.EgressLines {
		values[index] = config.Service{ServiceID: line.LineID, Enabled: line.Enabled}
	}
	return allocatePorts(configuration.CredentialSeed, "egress-probe", diagnosticPortStart, diagnosticPortCount,
		values, func(value config.Service) (string, bool) { return value.ServiceID, value.Enabled }, used)
}

func DiagnosticPort(configuration config.Configuration, lineID string) (uint16, bool, error) {
	ports, err := allocateDiagnosticPorts(configuration)
	if err != nil {
		return 0, false, err
	}
	port, exists := ports[lineID]
	return port, exists, nil
}

func reservedPorts(configuration config.Configuration) map[uint16]struct{} {
	used := map[uint16]struct{}{configuration.APIPort: {}}
	for _, service := range configuration.Services {
		used[service.Port] = struct{}{}
	}
	return used
}

func allocatePorts(seed, namespace string, start, count int, values []config.Service,
	identity func(config.Service) (string, bool), used map[uint16]struct{},
) (map[string]uint16, error) {
	ports := make(map[string]uint16)
	for _, value := range values {
		id, include := identity(value)
		if !include {
			continue
		}
		digest := sha256.Sum256([]byte(seed + "\x00" + namespace + "\x00" + id))
		initial := int(binary.BigEndian.Uint16(digest[:2])) % count
		allocated := false
		for offset := 0; offset < count; offset++ {
			port := uint16(start + (initial+offset)%count)
			if _, exists := used[port]; exists {
				continue
			}
			used[port] = struct{}{}
			ports[id] = port
			allocated = true
			break
		}
		if !allocated {
			return nil, fmt.Errorf("allocate internal port for %q", id)
		}
	}
	return ports, nil
}
