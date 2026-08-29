package subscription

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

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
		contribution, err := renderService(configuration, service, binding, request.AuthorizationId)
		if err != nil {
			return nil, err
		}
		response.Services[index] = contribution
	}
	if err := centerpluginv1.ValidateRenderSubscriptionResponse(request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func renderService(configuration config.Configuration, service config.Service,
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		return renderVLESSReality(configuration, service, binding, authorizationID)
	case config.ServiceTypeShadowsocks:
		return renderShadowsocks(configuration, service, binding, authorizationID)
	default:
		return nil, errors.New("subscription requests an unsupported Xray service type")
	}
}

func renderShadowsocks(configuration config.Configuration, service config.Service,
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	settings := service.Shadowsocks
	userPassword, err := config.DeriveShadowsocksPassword(
		configuration.CredentialSeed, authorizationID, binding.ServiceId, settings.Method,
	)
	if err != nil {
		return nil, err
	}
	password := config.ShadowsocksClientPassword(*settings, userPassword)
	contribution := &centerpluginv1.SubscriptionServiceContribution{
		ServiceId: binding.ServiceId, DisplayName: binding.DisplayName,
		Uris: []string{shadowsocksURI(service.PublicHost, service.PublicPort, settings.Method, settings.ServerKey, userPassword, binding.DisplayName)},
	}
	mihomo, err := json.Marshal(map[string]any{
		"name": binding.DisplayName, "type": "ss", "server": service.PublicHost, "port": service.PublicPort,
		"cipher": settings.Method, "password": password, "udp": settings.Network != config.ShadowsocksNetworkTCP,
	})
	if err != nil {
		return nil, err
	}
	contribution.MihomoProxiesJson = [][]byte{mihomo}
	singBox, err := json.Marshal(map[string]any{
		"type": "shadowsocks", "tag": binding.DisplayName, "server": service.PublicHost,
		"server_port": service.PublicPort, "method": settings.Method, "password": password,
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
	binding *centerpluginv1.SubscriptionServiceBinding, authorizationID string,
) (*centerpluginv1.SubscriptionServiceContribution, error) {
	reality := service.VLESSReality
	publicKey, err := config.RealityPublicKey(reality.PrivateKey)
	if err != nil {
		return nil, err
	}
	serverName := reality.ServerNames[0]
	shortID := reality.ShortIDs[0]
	credential, err := config.DeriveCredential(configuration.CredentialSeed, authorizationID, binding.ServiceId)
	if err != nil {
		return nil, err
	}
	uri := vlessURI(service.PublicHost, service.PublicPort, credential, binding.DisplayName, reality.Flow,
		reality.Fingerprint, serverName, publicKey, shortID, reality.SpiderX, reality.Encryption,
		reality.MLDSA65Verify, service.TCP)
	contribution := &centerpluginv1.SubscriptionServiceContribution{
		ServiceId: binding.ServiceId, DisplayName: binding.DisplayName, Uris: []string{uri},
	}
	if service.TCP.Header.Type == config.TCPHeaderHTTP || reality.MLDSA65Verify != "" {
		return contribution, nil
	}
	mihomoValue := map[string]any{
		"name": binding.DisplayName, "type": "vless", "server": service.PublicHost, "port": service.PublicPort,
		"uuid": credential, "network": "tcp", "tls": true, "udp": true, "flow": reality.Flow,
		"servername": serverName, "client-fingerprint": reality.Fingerprint,
		"reality-opts": map[string]any{"public-key": publicKey, "short-id": shortID},
	}
	if reality.Encryption != "none" {
		mihomoValue["encryption"] = reality.Encryption
	}
	if reality.Flow == "" {
		delete(mihomoValue, "flow")
	}
	mihomo, err := json.Marshal(mihomoValue)
	if err != nil {
		return nil, err
	}
	contribution.MihomoProxiesJson = [][]byte{mihomo}
	if reality.Encryption != "none" {
		return contribution, nil
	}
	singBoxValue := map[string]any{
		"type": "vless", "tag": binding.DisplayName, "server": service.PublicHost, "server_port": service.PublicPort,
		"uuid": credential, "flow": reality.Flow,
		"tls": map[string]any{
			"enabled": true, "server_name": serverName,
			"utls":    map[string]any{"enabled": true, "fingerprint": reality.Fingerprint},
			"reality": map[string]any{"enabled": true, "public_key": publicKey, "short_id": shortID},
		},
	}
	if reality.Flow == "" {
		delete(singBoxValue, "flow")
	}
	singBox, err := json.Marshal(singBoxValue)
	if err != nil {
		return nil, err
	}
	contribution.SingBoxOutboundsJson = [][]byte{singBox}
	return contribution, nil
}

func vlessURI(host string, port uint16, credential, displayName, flow, fingerprint, serverName, publicKey, shortID, spiderX, encryption, mldsa65Verify string, tcp config.TCPSettings) string {
	value := &url.URL{
		Scheme: "vless", User: url.User(credential), Host: net.JoinHostPort(host, strconv.Itoa(int(port))),
		Fragment: displayName,
	}
	query := url.Values{
		"encryption": {encryption}, "fp": {fingerprint}, "pbk": {publicKey},
		"security": {"reality"}, "sid": {shortID}, "sni": {serverName}, "type": {"tcp"},
	}
	if flow != "" {
		query.Set("flow", flow)
	}
	if spiderX != "" && spiderX != "/" {
		query.Set("spx", spiderX)
	}
	if mldsa65Verify != "" {
		query.Set("pqv", mldsa65Verify)
	}
	if tcp.Header.Type == config.TCPHeaderHTTP && tcp.Header.Request != nil {
		query.Set("headerType", "http")
		query.Set("path", strings.Join(tcp.Header.Request.Path, ","))
		if hosts := tcp.Header.Request.Headers["Host"]; len(hosts) > 0 {
			query.Set("host", strings.Join(hosts, ","))
		}
	}
	value.RawQuery = query.Encode()
	return value.String()
}
