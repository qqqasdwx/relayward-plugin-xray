package xrayconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

const (
	realityTunnelPortStart       = 49152
	realityTunnelPortCount       = 16384
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
	routingNeedsSniffing := NeedsSniffing(value)
	tunnelPorts, err := allocateRealityTunnelPorts(value)
	if err != nil {
		return nil, err
	}
	inbounds := []any{map[string]any{
		"tag": "relayward-api", "listen": "127.0.0.1", "port": value.APIPort,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
	}}
	for _, service := range value.Services {
		if !service.Enabled {
			continue
		}
		serviceInbounds, err := renderService(value, service, routingNeedsSniffing, tunnelPorts)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, serviceInbounds...)
	}
	routing := map[string]any{"rules": renderRoutingRules(routingRules)}
	if value.DNS.Enabled {
		routing["domainStrategy"] = "IPIfNonMatch"
	}
	result := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"api": map[string]any{"tag": "relayward-api", "services": []string{
			"HandlerService", "RoutingService", "StatsService",
		}},
		"inbounds":  inbounds,
		"outbounds": renderOutbounds(value.Outbounds),
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
		}}},
		"routing": routing,
		"stats":   map[string]any{},
	}
	if value.DNS.Enabled {
		result["dns"] = renderDNS(value.DNS)
	}
	return json.Marshal(result)
}

func renderOutbounds(outbounds []config.Outbound) []any {
	result := make([]any, len(outbounds))
	for index, outbound := range outbounds {
		settings := map[string]any{}
		switch outbound.Protocol {
		case config.OutboundProtocolFreedom:
			settings = renderFreedomOutbound(*outbound.Freedom)
		case config.OutboundProtocolBlackhole:
			if outbound.Blackhole.ResponseType != "" {
				settings["response"] = map[string]any{"type": outbound.Blackhole.ResponseType}
			}
		}
		result[index] = map[string]any{
			"tag": outbound.Tag, "protocol": outbound.Protocol, "settings": settings,
		}
	}
	return result
}

func renderFreedomOutbound(value config.FreedomOutboundSettings) map[string]any {
	settings := map[string]any{}
	if value.DomainStrategy != "" {
		settings["domainStrategy"] = value.DomainStrategy
	}
	if value.Redirect != "" {
		settings["redirect"] = value.Redirect
	}
	if value.UserLevel != 0 {
		settings["userLevel"] = value.UserLevel
	}
	if value.ProxyProtocol != 0 {
		settings["proxyProtocol"] = value.ProxyProtocol
	}
	if value.Fragment != nil {
		fragment := map[string]any{}
		for name, item := range map[string]string{
			"packets": value.Fragment.Packets, "length": value.Fragment.Length,
			"interval": value.Fragment.Interval, "maxSplit": value.Fragment.MaxSplit,
		} {
			if item != "" {
				fragment[name] = item
			}
		}
		settings["fragment"] = fragment
	}
	if len(value.Noises) > 0 {
		noises := make([]any, len(value.Noises))
		for index, noise := range value.Noises {
			noises[index] = map[string]any{
				"type": noise.Type, "packet": noise.Packet, "delay": noise.Delay, "applyTo": noise.ApplyTo,
			}
		}
		settings["noises"] = noises
	}
	if len(value.FinalRules) > 0 {
		rules := make([]any, len(value.FinalRules))
		for index, rule := range value.FinalRules {
			item := map[string]any{"action": rule.Action}
			if rule.Network != "" {
				item["network"] = rule.Network
			}
			if rule.Port != "" {
				item["port"] = rule.Port
			}
			if len(rule.IPs) > 0 {
				item["ip"] = rule.IPs
			}
			if rule.BlockDelay != "" {
				item["blockDelay"] = rule.BlockDelay
			}
			rules[index] = item
		}
		settings["finalRules"] = rules
	}
	return settings
}

func renderService(
	configuration config.Configuration,
	service config.Service,
	routingNeedsSniffing bool,
	tunnelPorts map[string]uint16,
) ([]any, error) {
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		inbounds, err := renderVLESSReality(service, tunnelPorts[service.ServiceID])
		return inbounds, err
	case config.ServiceTypeShadowsocks:
		inbound, err := renderShadowsocks(configuration, service, routingNeedsSniffing)
		if err != nil {
			return nil, err
		}
		return []any{inbound}, nil
	default:
		return nil, fmt.Errorf("unsupported Xray service type %q", service.Type)
	}
}

func renderShadowsocks(configuration config.Configuration, service config.Service, routingNeedsSniffing bool) (any, error) {
	shadowsocks := service.Shadowsocks
	settings := map[string]any{
		"clients": []any{},
		"network": shadowsocks.Network,
	}
	if config.IsShadowsocks2022(shadowsocks.Method) {
		bootstrapKey, err := config.DeriveShadowsocksPassword(
			configuration.CredentialSeed, "bootstrap", service.ServiceID, shadowsocks.Method,
		)
		if err != nil {
			return nil, err
		}
		settings["method"] = shadowsocks.Method
		settings["password"] = shadowsocks.ServerKey
		settings["clients"] = []any{map[string]any{
			"email":    "relayward:bootstrap:" + service.ServiceID,
			"password": bootstrapKey,
		}}
	}
	inbound := map[string]any{
		"tag": service.ServiceID, "listen": service.Listen, "port": service.Port,
		"protocol": "shadowsocks", "settings": settings,
	}
	if service.Sockopt != nil {
		inbound["streamSettings"] = map[string]any{"sockopt": renderSocketSettings(*service.Sockopt)}
	}
	if service.Sniffing.Enabled {
		inbound["sniffing"] = renderSniffing(service.Sniffing)
	} else if routingNeedsSniffing {
		inbound["sniffing"] = renderSniffing(config.Sniffing{
			Enabled: true, DestOverride: []string{"http", "tls", "quic"}, RouteOnly: true,
		})
	}
	return inbound, nil
}

func renderVLESSReality(service config.Service, tunnelPort uint16) ([]any, error) {
	reality := service.VLESSReality
	targetHost, targetPort, err := splitRealityTarget(reality.Target)
	if err != nil {
		return nil, fmt.Errorf("render VLESS REALITY service %q: %w", service.ServiceID, err)
	}
	realitySettings := map[string]any{
		"target":      net.JoinHostPort("127.0.0.1", strconv.Itoa(int(tunnelPort))),
		"xver":        reality.Xver,
		"serverNames": []string{targetHost}, "privateKey": reality.PrivateKey,
		"shortIds":              []string{reality.ShortIDs[0]},
		"minClientVer":          realityMinimumClientVersion,
		"limitFallbackUpload":   realityFallbackLimit(),
		"limitFallbackDownload": realityFallbackLimit(),
	}
	streamSettings := map[string]any{
		"method": "raw", "security": "reality", "realitySettings": realitySettings,
	}
	if service.TCP.AcceptProxyProtocol {
		streamSettings["rawSettings"] = map[string]any{"acceptProxyProtocol": true}
	}
	vlessInbound := map[string]any{
		"tag": service.ServiceID, "listen": "0.0.0.0", "port": service.Port, "protocol": "vless",
		"settings":       map[string]any{"decryption": "none"},
		"streamSettings": streamSettings,
		"sniffing": map[string]any{
			"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true,
		},
	}
	tunnelInbound := map[string]any{
		"tag": realityTunnelTag(service.ServiceID), "listen": "127.0.0.1", "port": tunnelPort,
		"protocol": "tunnel",
		"settings": map[string]any{
			"rewriteAddress": targetHost, "rewritePort": targetPort, "allowedNetwork": "tcp",
		},
		"sniffing": map[string]any{
			"enabled": true, "destOverride": []string{"tls"}, "routeOnly": true,
		},
		"streamSettings": map[string]any{
			"method": "raw", "security": "none",
			"rawSettings": map[string]any{"acceptProxyProtocol": true},
		},
	}
	return []any{vlessInbound, tunnelInbound}, nil
}

func realityFallbackLimit() map[string]any {
	return map[string]any{
		"afterBytes":       realityFallbackAfterBytes,
		"bytesPerSec":      realityFallbackBytesPerSec,
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

func allocateRealityTunnelPorts(configuration config.Configuration) (map[string]uint16, error) {
	used := map[uint16]struct{}{configuration.APIPort: {}}
	for _, service := range configuration.Services {
		used[service.Port] = struct{}{}
	}
	ports := make(map[string]uint16)
	for _, service := range configuration.Services {
		if service.Type != config.ServiceTypeVLESSReality {
			continue
		}
		digest := sha256.Sum256([]byte(configuration.CredentialSeed + "\x00" + service.ServiceID))
		start := int(binary.BigEndian.Uint16(digest[:2])) % realityTunnelPortCount
		allocated := false
		for offset := 0; offset < realityTunnelPortCount; offset++ {
			port := uint16(realityTunnelPortStart + (start+offset)%realityTunnelPortCount)
			if _, exists := used[port]; exists {
				continue
			}
			used[port] = struct{}{}
			ports[service.ServiceID] = port
			allocated = true
			break
		}
		if !allocated {
			return nil, fmt.Errorf("allocate REALITY tunnel port for service %q", service.ServiceID)
		}
	}
	return ports, nil
}

func renderSocketSettings(value config.SocketSettings) map[string]any {
	settings := map[string]any{}
	if value.Mark != 0 {
		settings["mark"] = value.Mark
	}
	if value.TCPFastOpen {
		settings["tcpFastOpen"] = true
	}
	if value.TProxy != "" && value.TProxy != config.TProxyOff {
		settings["tproxy"] = value.TProxy
	}
	if value.AcceptProxyProtocol {
		settings["acceptProxyProtocol"] = true
	}
	if value.TCPMPTCP {
		settings["tcpMptcp"] = true
	}
	for key, item := range map[string]uint32{
		"tcpKeepAliveInterval": value.TCPKeepAliveInterval,
		"tcpKeepAliveIdle":     value.TCPKeepAliveIdle,
		"tcpMaxSeg":            value.TCPMaxSeg,
		"tcpUserTimeout":       value.TCPUserTimeout,
		"tcpWindowClamp":       value.TCPWindowClamp,
	} {
		if item != 0 {
			settings[key] = item
		}
	}
	if value.TCPCongestion != "" {
		settings["tcpCongestion"] = value.TCPCongestion
	}
	if value.V6Only {
		settings["v6only"] = true
	}
	if len(value.Custom) != 0 {
		custom := make([]any, len(value.Custom))
		for index, option := range value.Custom {
			custom[index] = map[string]any{
				"system": option.System, "network": option.Network,
				"level": option.Level, "opt": option.Opt,
				"type": option.Type, "value": option.Value,
			}
		}
		settings["customSockopt"] = custom
	}
	return settings
}

func renderTCPSettings(value config.TCPSettings) map[string]any {
	settings := map[string]any{
		"acceptProxyProtocol": value.AcceptProxyProtocol,
		"header":              map[string]any{"type": value.Header.Type},
	}
	if value.Header.Type != config.TCPHeaderHTTP {
		return settings
	}
	settings["header"] = map[string]any{
		"type": "http",
		"request": map[string]any{
			"version": value.Header.Request.Version, "method": value.Header.Request.Method,
			"path": value.Header.Request.Path, "headers": value.Header.Request.Headers,
		},
		"response": map[string]any{
			"version": value.Header.Response.Version, "status": value.Header.Response.Status,
			"reason": value.Header.Response.Reason, "headers": value.Header.Response.Headers,
		},
	}
	return settings
}

func renderSniffing(value config.Sniffing) map[string]any {
	return map[string]any{
		"enabled": value.Enabled, "destOverride": value.DestOverride,
		"metadataOnly": value.MetadataOnly, "routeOnly": value.RouteOnly,
		"ipsExcluded": value.IPsExcluded, "domainsExcluded": value.DomainsExcluded,
	}
}
