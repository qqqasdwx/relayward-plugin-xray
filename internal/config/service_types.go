package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var domainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)

type Service struct {
	Type                string        `json:"type"`
	Enabled             bool          `json:"enabled"`
	ServiceID           string        `json:"service_id"`
	DisplayName         string        `json:"display_name"`
	Port                uint16        `json:"port"`
	AcceptProxyProtocol bool          `json:"accept_proxy_protocol"`
	VLESSReality        *VLESSReality `json:"vless_reality,omitempty"`
	Shadowsocks         *Shadowsocks  `json:"shadowsocks,omitempty"`
}

type EditableService struct {
	Type                string                `json:"type"`
	Enabled             bool                  `json:"enabled"`
	ServiceID           string                `json:"service_id"`
	DisplayName         string                `json:"display_name"`
	Port                uint16                `json:"port"`
	AcceptProxyProtocol bool                  `json:"accept_proxy_protocol"`
	VLESSReality        *EditableVLESSReality `json:"vless_reality,omitempty"`
	Shadowsocks         *EditableShadowsocks  `json:"shadowsocks,omitempty"`
}

type VLESSReality struct {
	Target     string `json:"target"`
	PrivateKey string `json:"private_key"`
	ShortID    string `json:"short_id"`
}

type EditableVLESSReality struct {
	Target string `json:"target"`
}

const (
	ShadowsocksMethod2022AES128 = "2022-blake3-aes-128-gcm"
	ShadowsocksMethod2022AES256 = "2022-blake3-aes-256-gcm"
)

type Shadowsocks struct {
	Method    string `json:"method"`
	ServerKey string `json:"server_key"`
}

type EditableShadowsocks struct {
	Method string `json:"method"`
}

type ServiceTypeDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

var serviceTypeDefinitions = []ServiceTypeDefinition{
	{ID: ServiceTypeVLESSReality, DisplayName: "VLESS + RAW + REALITY + Vision"},
	{ID: ServiceTypeShadowsocks, DisplayName: "Shadowsocks 2022"},
}

func SupportedServiceTypes() []ServiceTypeDefinition {
	return append([]ServiceTypeDefinition(nil), serviceTypeDefinitions...)
}

func ServiceTypeDefinitionByID(id string) (ServiceTypeDefinition, bool) {
	for _, definition := range serviceTypeDefinitions {
		if definition.ID == id {
			return definition, true
		}
	}
	return ServiceTypeDefinition{}, false
}

func editableService(value Service) EditableService {
	result := EditableService{
		Type: value.Type, Enabled: value.Enabled, ServiceID: value.ServiceID,
		DisplayName: value.DisplayName, Port: value.Port,
		AcceptProxyProtocol: value.AcceptProxyProtocol,
	}
	if value.VLESSReality != nil {
		result.VLESSReality = &EditableVLESSReality{Target: value.VLESSReality.Target}
	}
	if value.Shadowsocks != nil {
		result.Shadowsocks = &EditableShadowsocks{Method: value.Shadowsocks.Method}
	}
	return result
}

func mergeService(existing Service, sameType bool, editable EditableService) (Service, error) {
	if _, exists := ServiceTypeDefinitionByID(editable.Type); !exists {
		return Service{}, fmt.Errorf("unsupported service type %q", editable.Type)
	}
	result := Service{
		Type: editable.Type, Enabled: editable.Enabled, ServiceID: editable.ServiceID,
		DisplayName: editable.DisplayName, Port: editable.Port,
		AcceptProxyProtocol: editable.AcceptProxyProtocol,
	}
	switch editable.Type {
	case ServiceTypeVLESSReality:
		if editable.VLESSReality == nil || editable.Shadowsocks != nil {
			return Service{}, fmt.Errorf("vless_reality: configuration is required")
		}
		if _, _, err := parseRealityTarget(editable.VLESSReality.Target); err != nil {
			return Service{}, fmt.Errorf("vless_reality.target: %w", err)
		}
		if sameType && existing.VLESSReality != nil {
			result.VLESSReality = cloneVLESSReality(existing.VLESSReality)
			result.VLESSReality.Target = editable.VLESSReality.Target
			return result, nil
		}
		privateKey, shortID, err := newVLESSRealitySecrets()
		if err != nil {
			return Service{}, err
		}
		result.VLESSReality = &VLESSReality{Target: editable.VLESSReality.Target, PrivateKey: privateKey, ShortID: shortID}
	case ServiceTypeShadowsocks:
		if editable.Shadowsocks == nil || editable.VLESSReality != nil {
			return Service{}, fmt.Errorf("shadowsocks: configuration is required")
		}
		method := editable.Shadowsocks.Method
		if method == "" {
			method = ShadowsocksMethod2022AES256
		}
		serverKey := ""
		if sameType && existing.Shadowsocks != nil && existing.Shadowsocks.Method == method {
			serverKey = existing.Shadowsocks.ServerKey
		}
		if !validShadowsocksKey(serverKey, ShadowsocksKeyBytes(method)) {
			var err error
			serverKey, err = newShadowsocksKey(ShadowsocksKeyBytes(method))
			if err != nil {
				return Service{}, err
			}
		}
		result.Shadowsocks = &Shadowsocks{Method: method, ServerKey: serverKey}
	}
	return result, nil
}

func validateServiceType(service Service, field string) error {
	switch service.Type {
	case ServiceTypeVLESSReality:
		if service.VLESSReality == nil || service.Shadowsocks != nil {
			return fmt.Errorf("%s.vless_reality: configuration is required", field)
		}
		return validateVLESSReality(*service.VLESSReality, field+".vless_reality")
	case ServiceTypeShadowsocks:
		if service.Shadowsocks == nil || service.VLESSReality != nil {
			return fmt.Errorf("%s.shadowsocks: configuration is required", field)
		}
		return validateShadowsocks(*service.Shadowsocks, field+".shadowsocks")
	default:
		return fmt.Errorf("%s.type: unsupported service type", field)
	}
}

func validateVLESSReality(value VLESSReality, field string) error {
	if _, _, err := parseRealityTarget(value.Target); err != nil {
		return fmt.Errorf("%s.target: %w", field, err)
	}
	if _, err := RealityPublicKey(value.PrivateKey); err != nil {
		return fmt.Errorf("%s.private_key: %w", field, err)
	}
	decoded, err := hex.DecodeString(value.ShortID)
	if err != nil || len(decoded) != 8 || value.ShortID != strings.ToLower(value.ShortID) {
		return fmt.Errorf("%s.short_id: must contain 16 lowercase hexadecimal characters", field)
	}
	return nil
}

func validateShadowsocks(value Shadowsocks, field string) error {
	if !IsShadowsocksMethod(value.Method) {
		return fmt.Errorf("%s.method: unsupported Shadowsocks method", field)
	}
	if !validShadowsocksKey(value.ServerKey, ShadowsocksKeyBytes(value.Method)) {
		return fmt.Errorf("%s.server_key: must be a %d-byte padded base64 key", field, ShadowsocksKeyBytes(value.Method))
	}
	return nil
}

func IsShadowsocksMethod(method string) bool {
	return method == ShadowsocksMethod2022AES128 || method == ShadowsocksMethod2022AES256
}

func IsShadowsocks2022(method string) bool { return IsShadowsocksMethod(method) }

func ShadowsocksKeyBytes(method string) int {
	if method == ShadowsocksMethod2022AES128 {
		return 16
	}
	if method == ShadowsocksMethod2022AES256 {
		return 32
	}
	return 0
}

func ShadowsocksClientPassword(value Shadowsocks, userPassword string) string {
	return value.ServerKey + ":" + userPassword
}

func parseRealityTarget(value string) (string, uint16, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return "", 0, fmt.Errorf("is required")
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("must be a lowercase domain and port")
	}
	parsedPort, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != rawPort {
		return "", 0, fmt.Errorf("must include a canonical port")
	}
	if host != strings.ToLower(host) || !validServerName(host) {
		return "", 0, fmt.Errorf("must use a lowercase domain name")
	}
	return host, uint16(parsedPort), nil
}

func RealityPublicKey(privateKey string) (string, error) {
	raw, err := decodeKey("private key", privateKey)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid X25519 private key")
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func newVLESSRealitySecrets() (string, string, error) {
	privateKey := make([]byte, 32)
	shortID := make([]byte, 8)
	for _, value := range [][]byte{privateKey, shortID} {
		if _, err := rand.Read(value); err != nil {
			return "", "", fmt.Errorf("generate configuration secret: %w", err)
		}
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	return base64.RawURLEncoding.EncodeToString(privateKey), hex.EncodeToString(shortID), nil
}

func newShadowsocksKey(size int) (string, error) {
	if size == 0 {
		return "", fmt.Errorf("unsupported Shadowsocks method")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate Shadowsocks server key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(value), nil
}

func validShadowsocksKey(value string, size int) bool {
	if size == 0 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == size && base64.StdEncoding.EncodeToString(raw) == value
}

func cloneVLESSReality(value *VLESSReality) *VLESSReality {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneShadowsocks(value *Shadowsocks) *Shadowsocks {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func validServerName(value string) bool {
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	return len(value) <= 253 && domainPattern.MatchString(value)
}
