package subscription

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func SupportsServiceType(serviceType string) bool {
	return serviceType == config.ServiceTypeVLESSReality || serviceType == config.ServiceTypeShadowsocks
}

func SupportedFormats(serviceType string) []string {
	if !SupportsServiceType(serviceType) {
		return nil
	}
	return []string{"base64", "mihomo", "sing-box"}
}

func Render(configuration config.Configuration, request *centerpluginv1.RenderSubscriptionRequest) (*centerpluginv1.RenderSubscriptionResponse, error) {
	if err := centerpluginv1.ValidateRenderSubscriptionRequest(request); err != nil {
		return nil, err
	}
	if err := config.Validate(configuration); err != nil {
		return nil, errors.New("stored Xray configuration is invalid")
	}
	if len(request.Endpoints) == 0 {
		return nil, errors.New("subscription has no available node endpoints")
	}
	response := &centerpluginv1.RenderSubscriptionResponse{
		Services: make([]*centerpluginv1.SubscriptionServiceContribution, len(request.Services)),
	}
	for index, binding := range request.Services {
		service, exists := configuration.FindService(binding.ServiceId)
		if !exists {
			return nil, errors.New("subscription requests an unsupported Xray service")
		}
		if !service.Enabled {
			return nil, errors.New("subscription requests a disabled Xray service")
		}
		contribution := &centerpluginv1.SubscriptionServiceContribution{
			ServiceId: binding.ServiceId, DisplayName: binding.DisplayName,
		}
		lines := []config.EgressLine{{LineID: config.DefaultEgressLineID, DisplayName: "Default", Enabled: true}}
		if service.Type == config.ServiceTypeVLESSReality {
			lines = enabledEgressLines(configuration)
		}
		for _, endpoint := range request.Endpoints {
			for _, line := range lines {
				fragment, err := renderService(configuration, service, binding, request.AuthorizationId, endpoint, line)
				if err != nil {
					return nil, err
				}
				contribution.Uris = append(contribution.Uris, fragment.Uris...)
				contribution.MihomoProxiesJson = append(contribution.MihomoProxiesJson, fragment.MihomoProxiesJson...)
				contribution.SingBoxOutboundsJson = append(contribution.SingBoxOutboundsJson, fragment.SingBoxOutboundsJson...)
			}
		}
		sort.Strings(contribution.Uris)
		response.Services[index] = contribution
	}
	if err := centerpluginv1.ValidateRenderSubscriptionResponse(request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func renderService(configuration config.Configuration, service config.Service,
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string, endpoint *centerpluginv1.SubscriptionEndpoint,
	line config.EgressLine,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		return renderVLESSReality(configuration, service, binding, authorizationID, endpoint, line)
	case config.ServiceTypeShadowsocks:
		return renderShadowsocks(configuration, service, binding, authorizationID, endpoint)
	default:
		return nil, errors.New("subscription requests an unsupported Xray service type")
	}
}

func renderShadowsocks(configuration config.Configuration, service config.Service,
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string, endpoint *centerpluginv1.SubscriptionEndpoint,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	settings := service.Shadowsocks
	userPassword, err := config.DeriveShadowsocksPassword(
		configuration.CredentialSeed, authorizationID, binding.ServiceId, settings.Method,
	)
	if err != nil {
		return nil, err
	}
	password := config.ShadowsocksClientPassword(*settings, userPassword)
	host := endpoint.Address
	port := effectivePublicPort(endpoint, service)
	displayName := endpointDisplayName(binding.DisplayName, endpoint.DisplayName)
	contribution := &centerpluginv1.SubscriptionServiceContribution{
		ServiceId: binding.ServiceId, DisplayName: displayName,
		Uris: []string{shadowsocksURI(host, port, settings.Method, settings.ServerKey, userPassword, displayName)},
	}
	mihomo, err := json.Marshal(map[string]any{
		"name": displayName, "type": "ss", "server": host, "port": port,
		"cipher": settings.Method, "password": password, "udp": true,
	})
	if err != nil {
		return nil, err
	}
	contribution.MihomoProxiesJson = [][]byte{mihomo}
	singBox, err := json.Marshal(map[string]any{
		"type": "shadowsocks", "tag": displayName, "server": host,
		"server_port": port, "method": settings.Method, "password": password,
	})
	if err != nil {
		return nil, err
	}
	contribution.SingBoxOutboundsJson = [][]byte{singBox}
	return contribution, nil
}

func shadowsocksURI(host string, port uint16, method, serverKey, userPassword, displayName string) string {
	var userInfo string
	if config.IsShadowsocks2022(method) {
		userInfo = strings.Join([]string{
			url.QueryEscape(method), url.QueryEscape(serverKey), url.QueryEscape(userPassword),
		}, ":")
	} else {
		userInfo = base64.RawURLEncoding.EncodeToString([]byte(method + ":" + userPassword))
	}
	return "ss://" + userInfo + "@" + net.JoinHostPort(host, strconv.Itoa(int(port))) + "#" + url.PathEscape(displayName)
}

func renderVLESSReality(configuration config.Configuration, service config.Service,
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string, endpoint *centerpluginv1.SubscriptionEndpoint,
	line config.EgressLine,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	reality := service.VLESSReality
	publicKey, err := config.RealityPublicKey(reality.PrivateKey)
	if err != nil {
		return nil, err
	}
	serverName := realityServerName(reality.Target)
	shortID := reality.ShortID
	credential, err := config.DeriveCredential(configuration.CredentialSeed, authorizationID, binding.ServiceId)
	if err != nil {
		return nil, err
	}
	credential, err = config.CredentialForVLESSRoute(credential, line.VLESSRoute)
	if err != nil {
		return nil, err
	}
	host := endpoint.Address
	port := effectivePublicPort(endpoint, service)
	displayName := egressDisplayName(endpointDisplayName(binding.DisplayName, endpoint.DisplayName), line)
	uri := vlessURI(host, port, credential, displayName, serverName, publicKey, shortID)
	contribution := &centerpluginv1.SubscriptionServiceContribution{
		ServiceId: binding.ServiceId, DisplayName: displayName, Uris: []string{uri},
	}
	mihomoValue := map[string]any{
		"name": displayName, "type": "vless", "server": host, "port": port,
		"uuid": credential, "network": "tcp", "tls": true, "udp": true, "flow": config.VLESSVisionFlow,
		"servername": serverName, "client-fingerprint": "chrome",
		"reality-opts": map[string]any{"public-key": publicKey, "short-id": shortID},
	}
	mihomo, err := json.Marshal(mihomoValue)
	if err != nil {
		return nil, err
	}
	contribution.MihomoProxiesJson = [][]byte{mihomo}
	singBoxValue := map[string]any{
		"type": "vless", "tag": displayName, "server": host, "server_port": port,
		"uuid": credential, "flow": config.VLESSVisionFlow,
		"tls": map[string]any{
			"enabled": true, "server_name": serverName,
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": publicKey, "short_id": shortID},
		},
	}
	singBox, err := json.Marshal(singBoxValue)
	if err != nil {
		return nil, err
	}
	contribution.SingBoxOutboundsJson = [][]byte{singBox}
	return contribution, nil
}

func effectivePublicPort(endpoint *centerpluginv1.SubscriptionEndpoint, service config.Service) uint16 {
	if port, exists := endpoint.PublicPortOverrides[service.ServiceID]; exists {
		return uint16(port)
	}
	return service.Port
}

func endpointDisplayName(serviceName, endpointName string) string {
	value := serviceName + " / " + endpointName
	if utf8.RuneCountInString(value) <= 100 {
		return value
	}
	return truncateRunes(serviceName, 49) + " / " + truncateRunes(endpointName, 48)
}

func egressDisplayName(base string, line config.EgressLine) string {
	if line.LineID == config.DefaultEgressLineID {
		return base
	}
	return truncateRunes(base, 65) + " / " + truncateRunes(line.DisplayName, 32)
}

func enabledEgressLines(configuration config.Configuration) []config.EgressLine {
	result := make([]config.EgressLine, 0, len(configuration.EgressLines))
	for _, line := range configuration.EgressLines {
		if line.Enabled {
			result = append(result, line)
		}
	}
	return result
}

func realityServerName(target string) string {
	host, _, _ := net.SplitHostPort(target)
	return host
}

func truncateRunes(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}

func vlessURI(host string, port uint16, credential, displayName, serverName, publicKey, shortID string) string {
	value := &url.URL{
		Scheme: "vless", User: url.User(credential), Host: net.JoinHostPort(host, strconv.Itoa(int(port))),
		Fragment: displayName,
	}
	query := url.Values{
		"encryption": {"none"}, "flow": {config.VLESSVisionFlow}, "fp": {"chrome"}, "pbk": {publicKey},
		"security": {"reality"}, "sid": {shortID}, "sni": {serverName}, "type": {"tcp"},
	}
	value.RawQuery = query.Encode()
	return value.String()
}
