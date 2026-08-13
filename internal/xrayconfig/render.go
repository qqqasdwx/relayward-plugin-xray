package xrayconfig

import (
	"encoding/json"
	"fmt"

	"github.com/Relayward/relayward-plugin-xray/internal/config"
)

func SupportsServiceType(serviceType string) bool {
	return serviceType == config.ServiceTypeVLESSReality
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
	inbounds := []any{map[string]any{
		"tag": "relayward-api", "listen": "127.0.0.1", "port": value.APIPort,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
	}}
	for _, service := range value.Services {
		if !service.Enabled {
			continue
		}
		inbound, err := renderService(service, routingNeedsSniffing)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, inbound)
	}
	directSettings := map[string]any{}
	routing := map[string]any{"rules": renderRoutingRules(routingRules)}
	if value.DNS.Enabled {
		directSettings["domainStrategy"] = xrayDNSQueryStrategy(value.DNS.QueryStrategy)
		routing["domainStrategy"] = "IPIfNonMatch"
	}
	result := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"api": map[string]any{"tag": "relayward-api", "services": []string{
			"HandlerService", "RoutingService", "StatsService",
		}},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": directSettings},
			map[string]any{"tag": "blocked", "protocol": "blackhole", "settings": map[string]any{}},
		},
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

func renderService(service config.Service, routingNeedsSniffing bool) (any, error) {
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		return renderVLESSReality(service, routingNeedsSniffing), nil
	default:
		return nil, fmt.Errorf("unsupported Xray service type %q", service.Type)
	}
}

func renderVLESSReality(service config.Service, routingNeedsSniffing bool) any {
	reality := service.VLESSReality
	realitySettings := map[string]any{
		"show": reality.Show, "target": reality.Target, "xver": reality.Xver,
		"serverNames": reality.ServerNames, "privateKey": reality.PrivateKey,
		"shortIds": reality.ShortIDs,
	}
	if reality.MLDSA65Seed != "" {
		realitySettings["mldsa65Seed"] = reality.MLDSA65Seed
	}
	if reality.MasterKeyLog != "" {
		realitySettings["masterKeyLog"] = reality.MasterKeyLog
	}
	if reality.LimitFallbackUpload != nil {
		realitySettings["limitFallbackUpload"] = renderRealityLimitFallback(*reality.LimitFallbackUpload)
	}
	if reality.LimitFallbackDownload != nil {
		realitySettings["limitFallbackDownload"] = renderRealityLimitFallback(*reality.LimitFallbackDownload)
	}
	if reality.MinClientVersion != "" {
		realitySettings["minClientVer"] = reality.MinClientVersion
	}
	if reality.MaxClientVersion != "" {
		realitySettings["maxClientVer"] = reality.MaxClientVersion
	}
	if reality.MaxTimeDiff != 0 {
		realitySettings["maxTimeDiff"] = reality.MaxTimeDiff
	}
	settings := map[string]any{"clients": []any{}, "decryption": reality.Decryption}
	if len(reality.Fallbacks) != 0 {
		fallbacks := make([]any, len(reality.Fallbacks))
		for index, fallback := range reality.Fallbacks {
			fallbacks[index] = map[string]any{
				"name": fallback.Name, "alpn": fallback.ALPN, "path": fallback.Path,
				"dest": fallback.Dest, "xver": fallback.Xver,
			}
		}
		settings["fallbacks"] = fallbacks
	}
	if len(reality.TestSeed) != 0 {
		settings["testseed"] = reality.TestSeed
	}
	inbound := map[string]any{
		"tag": service.ServiceID, "listen": service.Listen, "port": service.Port, "protocol": "vless",
		"settings": settings,
		"streamSettings": map[string]any{
			"network": "tcp", "security": "reality",
			"tcpSettings": renderTCPSettings(service.TCP), "realitySettings": realitySettings,
		},
	}
	if service.Sockopt != nil {
		inbound["streamSettings"].(map[string]any)["sockopt"] = renderSocketSettings(*service.Sockopt)
	}
	if service.Sniffing.Enabled {
		inbound["sniffing"] = renderSniffing(service.Sniffing)
	} else if routingNeedsSniffing {
		inbound["sniffing"] = renderSniffing(config.Sniffing{
			Enabled: true, DestOverride: []string{"http", "tls", "quic"}, RouteOnly: true,
		})
	}
	return inbound
}

func renderRealityLimitFallback(value config.RealityLimitFallback) map[string]any {
	return map[string]any{
		"afterBytes": value.AfterBytes, "bytesPerSec": value.BytesPerSec,
		"burstBytesPerSec": value.BurstBytesPerSec,
	}
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
