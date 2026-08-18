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
	Decryption            string                `json:"decryption"`
	Encryption            string                `json:"encryption"`
	TestSeed              []uint32              `json:"test_seed"`
	Fallbacks             []VLESSFallback       `json:"fallbacks"`
	Show                  bool                  `json:"show"`
	Xver                  uint8                 `json:"xver"`
	Target                string                `json:"target"`
	ServerNames           []string              `json:"server_names"`
	PrivateKey            string                `json:"private_key"`
	PublicKey             string                `json:"public_key"`
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

var serviceTypeDefinitions = []ServiceTypeDefinition{{
	ID: ServiceTypeVLESSReality, DisplayName: "VLESS REALITY",
	Capabilities: ServiceTypeCapabilities{
		XrayInbound: true, ServiceControl: true, TrafficCounters: true,
		RecentActivity: true, DynamicBlocking: true,
		SubscriptionFormats: []string{"base64", "mihomo", "sing-box"},
	},
}}

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
	publicKey, _ := RealityPublicKey(value.PrivateKey)
	return &EditableVLESSReality{
		Decryption: value.Decryption, Encryption: value.Encryption,
		TestSeed: append([]uint32{}, value.TestSeed...), Fallbacks: append([]VLESSFallback{}, value.Fallbacks...),
		Show: value.Show, Xver: value.Xver, Target: value.Target,
		ServerNames: append([]string{}, value.ServerNames...), PrivateKey: value.PrivateKey, PublicKey: publicKey,
		ShortIDs: append([]string{}, value.ShortIDs...), MinClientVersion: value.MinClientVersion,
		MaxClientVersion: value.MaxClientVersion, MaxTimeDiff: value.MaxTimeDiff,
		MLDSA65Seed: value.MLDSA65Seed, MLDSA65Verify: value.MLDSA65Verify, MasterKeyLog: value.MasterKeyLog,
		LimitFallbackUpload:   cloneRealityLimitFallback(value.LimitFallbackUpload),
		LimitFallbackDownload: cloneRealityLimitFallback(value.LimitFallbackDownload),
		Flow:                  value.Flow, Fingerprint: value.Fingerprint, SpiderX: value.SpiderX,
	}
}

func mergeServiceType(existing Service, _ bool, editable EditableService) (Service, error) {
	if _, exists := ServiceTypeDefinitionByID(editable.Type); !exists {
		return Service{}, fmt.Errorf("unsupported service type %q", editable.Type)
	}
	switch editable.Type {
	case ServiceTypeVLESSReality:
		if editable.VLESSReality == nil {
			return Service{}, fmt.Errorf("vless_reality: configuration is required")
		}
		serverNames := append([]string(nil), editable.VLESSReality.ServerNames...)
		decryption := editable.VLESSReality.Decryption
		if decryption == "" {
			decryption = "none"
		}
		encryption := editable.VLESSReality.Encryption
		if encryption == "" {
			encryption = "none"
		}
		privateKey := editable.VLESSReality.PrivateKey
		shortIDs := append([]string(nil), editable.VLESSReality.ShortIDs...)
		if privateKey == "" || len(shortIDs) == 0 {
			var err error
			generatedKey, generatedShortIDs, err := newVLESSRealitySecrets()
			if err != nil {
				return Service{}, err
			}
			if privateKey == "" {
				privateKey = generatedKey
			}
			if len(shortIDs) == 0 {
				shortIDs = generatedShortIDs
			}
		}
		spiderX := editable.VLESSReality.SpiderX
		if spiderX == "" {
			spiderX = "/"
		}
		existing.VLESSReality = &VLESSReality{
			Decryption: decryption, Encryption: encryption,
			TestSeed:  append([]uint32(nil), editable.VLESSReality.TestSeed...),
			Fallbacks: append([]VLESSFallback(nil), editable.VLESSReality.Fallbacks...),
			Show:      editable.VLESSReality.Show, Xver: editable.VLESSReality.Xver,
			Target:      editable.VLESSReality.Target,
			ServerNames: serverNames,
			PrivateKey:  privateKey, ShortIDs: shortIDs,
			MinClientVersion: editable.VLESSReality.MinClientVersion,
			MaxClientVersion: editable.VLESSReality.MaxClientVersion,
			MaxTimeDiff:      editable.VLESSReality.MaxTimeDiff,
			MLDSA65Seed:      editable.VLESSReality.MLDSA65Seed, MLDSA65Verify: editable.VLESSReality.MLDSA65Verify,
			MasterKeyLog:          editable.VLESSReality.MasterKeyLog,
			LimitFallbackUpload:   cloneRealityLimitFallback(editable.VLESSReality.LimitFallbackUpload),
			LimitFallbackDownload: cloneRealityLimitFallback(editable.VLESSReality.LimitFallbackDownload),
			Flow:                  editable.VLESSReality.Flow,
			Fingerprint:           editable.VLESSReality.Fingerprint, SpiderX: spiderX,
		}
		return existing, nil
	default:
		return Service{}, fmt.Errorf("unsupported service type %q", editable.Type)
	}
}

func validateServiceType(service Service, field string) error {
	switch service.Type {
	case ServiceTypeVLESSReality:
		if service.VLESSReality == nil {
			return fmt.Errorf("%s.vless_reality: configuration is required", field)
		}
		return validateVLESSReality(*service.VLESSReality, field+".vless_reality")
	default:
		return fmt.Errorf("%s.type: unsupported service type", field)
	}
}

func validateVLESSReality(value VLESSReality, field string) error {
	if err := validateRealityTarget(value.Target); err != nil {
		return fmt.Errorf("%s.target: %w", field, err)
	}
	if len(value.ServerNames) == 0 || len(value.ServerNames) > 16 {
		return fmt.Errorf("%s.server_names: must contain 1 to 16 values", field)
	}
	seenNames := make(map[string]struct{}, len(value.ServerNames))
	for index, name := range value.ServerNames {
		if !validServerName(name) {
			return fmt.Errorf("%s.server_names[%d]: invalid server name", field, index)
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("%s.server_names[%d]: duplicate server name", field, index)
		}
		seenNames[name] = struct{}{}
	}
	if _, err := RealityPublicKey(value.PrivateKey); err != nil {
		return fmt.Errorf("%s.private_key: %w", field, err)
	}
	if len(value.ShortIDs) == 0 || len(value.ShortIDs) > 16 {
		return fmt.Errorf("%s.short_ids: must contain 1 to 16 values", field)
	}
	seenShortIDs := make(map[string]struct{}, len(value.ShortIDs))
	for index, shortID := range value.ShortIDs {
		decoded, err := hex.DecodeString(shortID)
		if err != nil || len(decoded) < 1 || len(decoded) > 8 {
			return fmt.Errorf("%s.short_ids[%d]: must contain 2 to 16 lowercase hexadecimal characters", field, index)
		}
		if shortID != strings.ToLower(shortID) {
			return fmt.Errorf("%s.short_ids[%d]: must use lowercase hexadecimal", field, index)
		}
		if _, exists := seenShortIDs[shortID]; exists {
			return fmt.Errorf("%s.short_ids[%d]: duplicate short ID", field, index)
		}
		seenShortIDs[shortID] = struct{}{}
	}
	if value.Xver > 2 {
		return fmt.Errorf("%s.xver: must be 0, 1, or 2", field)
	}
	if err := validateVLESSEncryptionPair(value.Decryption, value.Encryption, field); err != nil {
		return err
	}
	if len(value.TestSeed) != 0 && len(value.TestSeed) != 4 {
		return fmt.Errorf("%s.test_seed: must contain exactly four values", field)
	}
	for index, item := range value.TestSeed {
		if item == 0 {
			return fmt.Errorf("%s.test_seed[%d]: must be greater than zero", field, index)
		}
	}
	if err := validateVLESSFallbacks(value.Fallbacks, field+".fallbacks"); err != nil {
		return err
	}
	if value.Decryption != "none" && len(value.Fallbacks) != 0 {
		return fmt.Errorf("%s.fallbacks: cannot be used with VLESS Encryption", field)
	}
	if err := validateClientVersion(value.MinClientVersion); err != nil {
		return fmt.Errorf("%s.min_client_version: %w", field, err)
	}
	if err := validateClientVersion(value.MaxClientVersion); err != nil {
		return fmt.Errorf("%s.max_client_version: %w", field, err)
	}
	if value.MinClientVersion != "" && value.MaxClientVersion != "" && compareClientVersions(value.MinClientVersion, value.MaxClientVersion) > 0 {
		return fmt.Errorf("%s.max_client_version: must not be lower than min_client_version", field)
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
	if err := validateOptionalBase64URL(value.MLDSA65Seed, 32, field+".mldsa65_seed"); err != nil {
		return err
	}
	if err := validateOptionalBase64URL(value.MLDSA65Verify, 1952, field+".mldsa65_verify"); err != nil {
		return err
	}
	if (value.MLDSA65Seed == "") != (value.MLDSA65Verify == "") {
		return fmt.Errorf("%s.mldsa65_seed and mldsa65_verify: must both be set or both be empty", field)
	}
	if strings.ContainsAny(value.MasterKeyLog, "\r\n\x00") {
		return fmt.Errorf("%s.master_key_log: invalid path", field)
	}
	if err := validateRealityLimitFallback(value.LimitFallbackUpload, field+".limit_fallback_upload"); err != nil {
		return err
	}
	if err := validateRealityLimitFallback(value.LimitFallbackDownload, field+".limit_fallback_download"); err != nil {
		return err
	}
	return nil
}

func validateVLESSEncryptionPair(decryption, encryption, field string) error {
	if decryption == "none" && encryption == "none" {
		return nil
	}
	if decryption == "" || encryption == "" || decryption == "none" || encryption == "none" {
		return fmt.Errorf("%s.decryption and encryption: must both be none or a VLESS Encryption pair", field)
	}
	decryptionMode, decryptionKeys, err := parseVLESSEncryptionValue(decryption, true)
	if err != nil {
		return fmt.Errorf("%s.decryption: %w", field, err)
	}
	encryptionMode, encryptionKeys, err := parseVLESSEncryptionValue(encryption, false)
	if err != nil {
		return fmt.Errorf("%s.encryption: %w", field, err)
	}
	if decryptionMode != encryptionMode || len(decryptionKeys) != len(encryptionKeys) {
		return fmt.Errorf("%s.decryption and encryption: authentication modes do not match", field)
	}
	for index := range decryptionKeys {
		if !((decryptionKeys[index] == 32 && encryptionKeys[index] == 32) ||
			(decryptionKeys[index] == 64 && encryptionKeys[index] == 1184)) {
			return fmt.Errorf("%s.decryption and encryption: authentication key types do not match", field)
		}
	}
	return nil
}

func parseVLESSEncryptionValue(value string, server bool) (string, []int, error) {
	if len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
		return "", nil, fmt.Errorf("invalid VLESS Encryption value")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return "", nil, fmt.Errorf("unsupported VLESS Encryption value")
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return "", nil, fmt.Errorf("unsupported authentication mode")
	}
	if server {
		seconds := strings.TrimSuffix(parts[2], "s")
		if !strings.HasSuffix(parts[2], "s") {
			return "", nil, fmt.Errorf("invalid server time range")
		}
		rangeParts := strings.Split(seconds, "-")
		if len(rangeParts) < 1 || len(rangeParts) > 2 {
			return "", nil, fmt.Errorf("invalid server time range")
		}
		for _, part := range rangeParts {
			parsed, err := strconv.ParseUint(part, 10, 63)
			if err != nil || strconv.FormatUint(parsed, 10) != part {
				return "", nil, fmt.Errorf("invalid server time range")
			}
		}
	} else if parts[2] != "0rtt" && parts[2] != "1rtt" {
		return "", nil, fmt.Errorf("invalid client handshake mode")
	}
	keySizes := make([]int, 0, len(parts)-3)
	for _, part := range parts[3:] {
		if part == "" {
			return "", nil, fmt.Errorf("empty VLESS Encryption segment")
		}
		if len(part) < 20 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != part {
			return "", nil, fmt.Errorf("invalid authentication key")
		}
		if server && len(raw) != 32 && len(raw) != 64 {
			return "", nil, fmt.Errorf("invalid server authentication key")
		}
		if !server && len(raw) != 32 && len(raw) != 1184 {
			return "", nil, fmt.Errorf("invalid client authentication key")
		}
		keySizes = append(keySizes, len(raw))
	}
	if len(keySizes) == 0 {
		return "", nil, fmt.Errorf("authentication key is required")
	}
	return parts[1], keySizes, nil
}

func validateRealityTarget(value string) error {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("is required")
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "@") {
		return nil
	}
	if port, err := strconv.ParseUint(value, 10, 16); err == nil && port != 0 {
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return fmt.Errorf("must include a valid port")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return fmt.Errorf("must include a valid port")
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsUnspecified() {
		return fmt.Errorf("must not use an unspecified address")
	}
	return nil
}

func validateOptionalBase64URL(value string, size int, field string) error {
	if value == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return fmt.Errorf("%s: must be %d bytes of unpadded base64url", field, size)
	}
	return nil
}

func validateClientVersion(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ".")
	if len(parts) > 3 {
		return fmt.Errorf("must contain at most three numeric parts")
	}
	for _, part := range parts {
		parsed, err := strconv.ParseUint(part, 10, 8)
		if err != nil || strconv.FormatUint(parsed, 10) != part {
			return fmt.Errorf("must contain numeric parts between 0 and 255")
		}
	}
	return nil
}

func compareClientVersions(first, second string) int {
	firstParts := strings.Split(first, ".")
	secondParts := strings.Split(second, ".")
	for index := 0; index < 3; index++ {
		var firstValue, secondValue uint64
		if index < len(firstParts) {
			firstValue, _ = strconv.ParseUint(firstParts[index], 10, 8)
		}
		if index < len(secondParts) {
			secondValue, _ = strconv.ParseUint(secondParts[index], 10, 8)
		}
		if firstValue < secondValue {
			return -1
		}
		if firstValue > secondValue {
			return 1
		}
	}
	return 0
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
