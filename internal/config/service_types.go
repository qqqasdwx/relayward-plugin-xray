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

const realityTunnelProxyProtocolVersion uint8 = 2

type VLESSReality struct {
	Decryption            string                `json:"decryption"`
	Encryption            string                `json:"encryption"`
	TestSeed              []uint32              `json:"test_seed"`
	Fallbacks             []VLESSFallback       `json:"fallbacks"`
	Show                  bool                  `json:"show"`
	Xver                  uint8                 `json:"xver"`
	Target                string                `json:"target"`
	ServerNames           []string              `json:"server_names"`
	PrivateKey            string                `json:"private_key"`
	ShortIDs              []string              `json:"short_ids"`
	MinClientVersion      string                `json:"min_client_version"`
	MaxClientVersion      string                `json:"max_client_version"`
	MaxTimeDiff           uint64                `json:"max_time_diff"`
	MLDSA65Seed           string                `json:"mldsa65_seed"`
	MLDSA65Verify         string                `json:"mldsa65_verify"`
	MasterKeyLog          string                `json:"master_key_log"`
	LimitFallbackUpload   *RealityLimitFallback `json:"limit_fallback_upload,omitempty"`
	LimitFallbackDownload *RealityLimitFallback `json:"limit_fallback_download,omitempty"`
	Flow                  string                `json:"flow"`
	Fingerprint           string                `json:"fingerprint"`
	SpiderX               string                `json:"spider_x"`
}

type EditableVLESSReality struct {
	Target string `json:"target"`
}

const (
	ShadowsocksMethod2022AES128 = "2022-blake3-aes-128-gcm"
	ShadowsocksMethod2022AES256 = "2022-blake3-aes-256-gcm"
	ShadowsocksMethodAES128     = "aes-128-gcm"
	ShadowsocksMethodAES256     = "aes-256-gcm"
	ShadowsocksMethodChaCha20   = "chacha20-ietf-poly1305"
	ShadowsocksMethodXChaCha20  = "xchacha20-ietf-poly1305"
	ShadowsocksNetworkTCP       = "tcp"
	ShadowsocksNetworkUDP       = "udp"
	ShadowsocksNetworkTCPUDP    = "tcp,udp"
)

type Shadowsocks struct {
	Method    string `json:"method"`
	Network   string `json:"network"`
	ServerKey string `json:"server_key"`
	IVCheck   bool   `json:"iv_check"`
}

type EditableShadowsocks struct {
	Method    string `json:"method"`
	Network   string `json:"network"`
	ServerKey string `json:"server_key"`
	IVCheck   bool   `json:"iv_check"`
}

type ServiceTypeCapabilities struct {
	XrayInbound         bool     `json:"xray_inbound"`
	ServiceControl      bool     `json:"service_control"`
	TrafficCounters     bool     `json:"traffic_counters"`
	RecentActivity      bool     `json:"recent_activity"`
	DynamicBlocking     bool     `json:"dynamic_blocking"`
	SubscriptionFormats []string `json:"subscription_formats"`
}

type ServiceTypeDefinition struct {
	ID           string                  `json:"id"`
	DisplayName  string                  `json:"display_name"`
	Capabilities ServiceTypeCapabilities `json:"capabilities"`
}

var serviceTypeDefinitions = []ServiceTypeDefinition{
	{
		ID: ServiceTypeVLESSReality, DisplayName: "VLESS REALITY",
		Capabilities: ServiceTypeCapabilities{
			XrayInbound: true, ServiceControl: true, TrafficCounters: true,
			RecentActivity: true, DynamicBlocking: true,
			SubscriptionFormats: []string{"base64", "mihomo", "sing-box"},
		},
	},
	{
		ID: ServiceTypeShadowsocks, DisplayName: "Shadowsocks",
		Capabilities: ServiceTypeCapabilities{
			XrayInbound: true, ServiceControl: true, TrafficCounters: true,
			RecentActivity: true, DynamicBlocking: true,
			SubscriptionFormats: []string{"base64", "mihomo", "sing-box"},
		},
	},
}

func SupportedServiceTypes() []ServiceTypeDefinition {
	values := make([]ServiceTypeDefinition, len(serviceTypeDefinitions))
	copy(values, serviceTypeDefinitions)
	for index := range values {
		values[index].Capabilities.SubscriptionFormats = append(
			[]string(nil), values[index].Capabilities.SubscriptionFormats...,
		)
	}
	return values
}

func ServiceTypeDefinitionByID(id string) (ServiceTypeDefinition, bool) {
	for _, definition := range serviceTypeDefinitions {
		if definition.ID == id {
			definition.Capabilities.SubscriptionFormats = append(
				[]string(nil), definition.Capabilities.SubscriptionFormats...,
			)
			return definition, true
		}
	}
	return ServiceTypeDefinition{}, false
}

func editableVLESSReality(value *VLESSReality) *EditableVLESSReality {
	if value == nil {
		return nil
	}
	return &EditableVLESSReality{Target: value.Target}
}

func editableShadowsocks(value *Shadowsocks) *EditableShadowsocks {
	if value == nil {
		return nil
	}
	return &EditableShadowsocks{
		Method: value.Method, Network: value.Network, ServerKey: value.ServerKey, IVCheck: value.IVCheck,
	}
}

func mergeServiceType(existing Service, sameType bool, editable EditableService) (Service, error) {
	if _, exists := ServiceTypeDefinitionByID(editable.Type); !exists {
		return Service{}, fmt.Errorf("unsupported service type %q", editable.Type)
	}
	switch editable.Type {
	case ServiceTypeVLESSReality:
		if editable.VLESSReality == nil {
			return Service{}, fmt.Errorf("vless_reality: configuration is required")
		}
		targetHost, _, err := parseRealityTarget(editable.VLESSReality.Target)
		if err != nil {
			return Service{}, fmt.Errorf("vless_reality.target: %w", err)
		}
		privateKey := ""
		var shortIDs []string
		if sameType && existing.VLESSReality != nil {
			privateKey = existing.VLESSReality.PrivateKey
			shortIDs = append([]string(nil), existing.VLESSReality.ShortIDs...)
		}
		if privateKey == "" || len(shortIDs) != 1 {
			privateKey, shortIDs, err = newVLESSRealitySecrets()
			if err != nil {
				return Service{}, err
			}
		}
		existing.VLESSReality = &VLESSReality{
			Decryption: "none", Encryption: "none",
			Xver:        realityTunnelProxyProtocolVersion,
			Target:      editable.VLESSReality.Target,
			ServerNames: []string{targetHost},
			PrivateKey:  privateKey, ShortIDs: shortIDs,
			MinClientVersion: "1.0.0",
			Flow:             VLESSVisionFlow,
			Fingerprint:      "chrome", SpiderX: "/",
		}
		existing.Shadowsocks = nil
		return existing, nil
	case ServiceTypeShadowsocks:
		if editable.Shadowsocks == nil {
			return Service{}, fmt.Errorf("shadowsocks: configuration is required")
		}
		method := editable.Shadowsocks.Method
		if method == "" {
			method = ShadowsocksMethod2022AES256
		}
		network := editable.Shadowsocks.Network
		if network == "" {
			network = ShadowsocksNetworkTCPUDP
		}
		serverKey := editable.Shadowsocks.ServerKey
		if IsShadowsocks2022(method) && !validShadowsocksKey(serverKey, ShadowsocksKeyBytes(method)) {
			var err error
			serverKey, err = newShadowsocksKey(ShadowsocksKeyBytes(method))
			if err != nil {
				return Service{}, err
			}
		}
		if !IsShadowsocks2022(method) {
			serverKey = ""
		}
		existing.VLESSReality = nil
		existing.Shadowsocks = &Shadowsocks{
			Method: method, Network: network, ServerKey: serverKey, IVCheck: editable.Shadowsocks.IVCheck,
		}
		return existing, nil
	default:
		return Service{}, fmt.Errorf("unsupported service type %q", editable.Type)
	}
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

func validateShadowsocks(value Shadowsocks, field string) error {
	if !IsShadowsocksMethod(value.Method) {
		return fmt.Errorf("%s.method: unsupported Shadowsocks method", field)
	}
	switch value.Network {
	case ShadowsocksNetworkTCP, ShadowsocksNetworkUDP, ShadowsocksNetworkTCPUDP:
	default:
		return fmt.Errorf("%s.network: must be tcp, udp, or tcp,udp", field)
	}
	if IsShadowsocks2022(value.Method) {
		if !validShadowsocksKey(value.ServerKey, ShadowsocksKeyBytes(value.Method)) {
			return fmt.Errorf("%s.server_key: must be a %d-byte padded base64 key", field, ShadowsocksKeyBytes(value.Method))
		}
	} else if value.ServerKey != "" {
		return fmt.Errorf("%s.server_key: only Shadowsocks 2022 uses a server key", field)
	}
	return nil
}

func IsShadowsocksMethod(method string) bool {
	switch method {
	case ShadowsocksMethod2022AES128, ShadowsocksMethod2022AES256,
		ShadowsocksMethodAES128, ShadowsocksMethodAES256,
		ShadowsocksMethodChaCha20, ShadowsocksMethodXChaCha20:
		return true
	default:
		return false
	}
}

func IsShadowsocks2022(method string) bool {
	return method == ShadowsocksMethod2022AES128 || method == ShadowsocksMethod2022AES256
}

func ShadowsocksKeyBytes(method string) int {
	if method == ShadowsocksMethod2022AES128 {
		return 16
	}
	if method == ShadowsocksMethod2022AES256 {
		return 32
	}
	return 0
}

func ShadowsocksCipherType(method string) (int32, bool) {
	switch method {
	case ShadowsocksMethodAES128:
		return 5, true
	case ShadowsocksMethodAES256:
		return 6, true
	case ShadowsocksMethodChaCha20:
		return 7, true
	case ShadowsocksMethodXChaCha20:
		return 8, true
	default:
		return 0, false
	}
}

func ShadowsocksClientPassword(value Shadowsocks, userPassword string) string {
	if IsShadowsocks2022(value.Method) {
		return value.ServerKey + ":" + userPassword
	}
	return userPassword
}

func validShadowsocksKey(value string, size int) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) == size && base64.StdEncoding.EncodeToString(raw) == value
}

func newShadowsocksKey(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate Shadowsocks server key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(value), nil
}

func validateVLESSReality(value VLESSReality, field string) error {
	targetHost, _, err := parseRealityTarget(value.Target)
	if err != nil {
		return fmt.Errorf("%s.target: %w", field, err)
	}
	if len(value.ServerNames) != 1 || value.ServerNames[0] != targetHost {
		return fmt.Errorf("%s.server_names: must contain only the camouflage target domain", field)
	}
	if _, err := RealityPublicKey(value.PrivateKey); err != nil {
		return fmt.Errorf("%s.private_key: %w", field, err)
	}
	if len(value.ShortIDs) != 1 {
		return fmt.Errorf("%s.short_ids: must contain exactly one value", field)
	}
	decodedShortID, err := hex.DecodeString(value.ShortIDs[0])
	if err != nil || len(decodedShortID) != 8 || value.ShortIDs[0] != strings.ToLower(value.ShortIDs[0]) {
		return fmt.Errorf("%s.short_ids[0]: must contain 16 lowercase hexadecimal characters", field)
	}
	if value.Decryption != "none" || value.Encryption != "none" {
		return fmt.Errorf("%s.decryption and encryption: must both be none", field)
	}
	if len(value.TestSeed) != 0 {
		return fmt.Errorf("%s.test_seed: is managed by Xray", field)
	}
	if len(value.Fallbacks) != 0 {
		return fmt.Errorf("%s.fallbacks: are not supported", field)
	}
	if value.Show || value.Xver != realityTunnelProxyProtocolVersion {
		return fmt.Errorf("%s.show and xver: are fixed to false and PROXY Protocol v2", field)
	}
	if value.MinClientVersion != "1.0.0" || value.MaxClientVersion != "" || value.MaxTimeDiff != 0 {
		return fmt.Errorf("%s: REALITY client version and time limits are managed by the plugin", field)
	}
	if value.MLDSA65Seed != "" || value.MLDSA65Verify != "" || value.MasterKeyLog != "" {
		return fmt.Errorf("%s: ML-DSA-65 and master key logging are not supported", field)
	}
	if value.LimitFallbackUpload != nil || value.LimitFallbackDownload != nil {
		return fmt.Errorf("%s: fallback limits are managed by the plugin", field)
	}
	if value.Flow != "" && value.Flow != VLESSVisionFlow {
		return fmt.Errorf("%s.flow: unsupported flow", field)
	}
	switch value.Fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe":
	default:
		return fmt.Errorf("%s.fingerprint: unsupported fingerprint", field)
	}
	if value.SpiderX == "" || !strings.HasPrefix(value.SpiderX, "/") || strings.ContainsAny(value.SpiderX, "\r\n") {
		return fmt.Errorf("%s.spider_x: must start with /", field)
	}
	return nil
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

func newVLESSRealitySecrets() (string, []string, error) {
	privateKey := make([]byte, 32)
	shortID := make([]byte, 8)
	for _, value := range [][]byte{privateKey, shortID} {
		if _, err := rand.Read(value); err != nil {
			return "", nil, fmt.Errorf("generate configuration secret: %w", err)
		}
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	return base64.RawURLEncoding.EncodeToString(privateKey), []string{hex.EncodeToString(shortID)}, nil
}

func cloneVLESSReality(value *VLESSReality) *VLESSReality {
	if value == nil {
		return nil
	}
	clone := *value
	clone.ServerNames = append([]string(nil), value.ServerNames...)
	clone.ShortIDs = append([]string(nil), value.ShortIDs...)
	clone.TestSeed = append([]uint32(nil), value.TestSeed...)
	clone.Fallbacks = append([]VLESSFallback(nil), value.Fallbacks...)
	clone.LimitFallbackUpload = cloneRealityLimitFallback(value.LimitFallbackUpload)
	clone.LimitFallbackDownload = cloneRealityLimitFallback(value.LimitFallbackDownload)
	return &clone
}

func cloneShadowsocks(value *Shadowsocks) *Shadowsocks {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneRealityLimitFallback(value *RealityLimitFallback) *RealityLimitFallback {
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
