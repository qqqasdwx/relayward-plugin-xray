// Package config owns the structured Xray configuration managed by this plugin.
package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Relayward/relayward-sdk/contract"
)

const (
	ServiceTypeVLESSReality        = "vless-reality"
	ServiceTypeShadowsocks         = "shadowsocks"
	VLESSVisionFlow                = "xtls-rprx-vision"
	MinimumVLESSXrayVersion        = "26.7.11"
	ManagedAPIPort          uint16 = 10085
	MaximumServices                = 64
	MaximumEgressLines             = 64
	MaximumAccessRules             = 128
	MaximumRoutingValues           = 64
)

var serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type Configuration struct {
	XrayVersion    string       `json:"xray_version"`
	APIPort        uint16       `json:"api_port"`
	CredentialSeed string       `json:"credential_seed"`
	Services       []Service    `json:"services"`
	EgressLines    []EgressLine `json:"egress_lines"`
	AccessRules    []AccessRule `json:"access_rules"`
}

type EditableConfiguration struct {
	XrayVersion string               `json:"xray_version"`
	Services    []EditableService    `json:"services"`
	EgressLines []EditableEgressLine `json:"egress_lines"`
	AccessRules []AccessRule         `json:"access_rules"`
}

func Editable(value Configuration) EditableConfiguration {
	services := make([]EditableService, len(value.Services))
	for index, service := range value.Services {
		services[index] = editableService(service)
	}
	lines := make([]EditableEgressLine, len(value.EgressLines))
	for index, line := range value.EgressLines {
		lines[index] = editableEgressLine(line)
	}
	return EditableConfiguration{
		XrayVersion: value.XrayVersion,
		Services:    services,
		EgressLines: lines,
		AccessRules: cloneAccessRules(value.AccessRules),
	}
}

func NewConfiguration(xrayVersion string, services []EditableService) (Configuration, error) {
	return NewFromEditable(EditableConfiguration{
		XrayVersion: xrayVersion,
		Services:    services,
		EgressLines: []EditableEgressLine{DefaultEgressLine()},
	})
}

func NewFromEditable(value EditableConfiguration) (Configuration, error) {
	seed, err := randomKey()
	if err != nil {
		return Configuration{}, err
	}
	return MergeEditable(Configuration{APIPort: ManagedAPIPort, CredentialSeed: seed}, value)
}

func MergeEditable(configuration Configuration, value EditableConfiguration) (Configuration, error) {
	existingServices := make(map[string]Service, len(configuration.Services))
	for _, service := range configuration.Services {
		existingServices[service.ServiceID] = service
	}
	services := make([]Service, len(value.Services))
	for index, editable := range value.Services {
		service, exists := existingServices[editable.ServiceID]
		merged, err := mergeService(service, exists && service.Type == editable.Type, editable)
		if err != nil {
			return Configuration{}, err
		}
		services[index] = merged
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })

	existingLines := make(map[string]EgressLine, len(configuration.EgressLines))
	for _, line := range configuration.EgressLines {
		existingLines[line.LineID] = line
	}
	lines := make([]EgressLine, len(value.EgressLines))
	for index, editable := range value.EgressLines {
		line, exists := existingLines[editable.LineID]
		merged, err := mergeEgressLine(line, exists && line.Type == editable.Type, editable)
		if err != nil {
			return Configuration{}, err
		}
		lines[index] = merged
	}

	configuration.XrayVersion = value.XrayVersion
	configuration.APIPort = ManagedAPIPort
	configuration.Services = services
	configuration.EgressLines = lines
	configuration.AccessRules = cloneAccessRules(value.AccessRules)
	if err := Validate(configuration); err != nil {
		return Configuration{}, err
	}
	return clone(configuration), nil
}

func Decode(raw []byte) (Configuration, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value Configuration
	if err := decoder.Decode(&value); err != nil {
		return Configuration{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Configuration{}, err
	}
	if err := Validate(value); err != nil {
		return Configuration{}, err
	}
	return clone(value), nil
}

func Encode(value Configuration) ([]byte, error) {
	if err := Validate(value); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode configuration: %w", err)
	}
	return raw, nil
}

func Validate(value Configuration) error {
	if err := contract.ValidateSemanticVersion(value.XrayVersion); err != nil {
		return fmt.Errorf("xray_version: %w", err)
	}
	if strings.ContainsAny(value.XrayVersion, "-+") {
		return fmt.Errorf("xray_version: pre-release and build versions are not supported")
	}
	if value.APIPort != ManagedAPIPort {
		return fmt.Errorf("api_port: must be managed by the plugin")
	}
	if _, err := decodeKey("credential_seed", value.CredentialSeed); err != nil {
		return err
	}
	if len(value.Services) > MaximumServices {
		return fmt.Errorf("services: must contain at most %d services", MaximumServices)
	}
	seenIDs := make(map[string]struct{}, len(value.Services))
	seenPorts := map[uint16]struct{}{value.APIPort: {}}
	for index, service := range value.Services {
		field := fmt.Sprintf("services[%d]", index)
		if index > 0 && value.Services[index-1].ServiceID > service.ServiceID {
			return fmt.Errorf("%s.service_id: services must be sorted by service ID", field)
		}
		if !serviceIDPattern.MatchString(service.ServiceID) {
			return fmt.Errorf("%s.service_id: must match %s", field, serviceIDPattern)
		}
		if _, exists := seenIDs[service.ServiceID]; exists {
			return fmt.Errorf("%s.service_id: duplicate service ID", field)
		}
		seenIDs[service.ServiceID] = struct{}{}
		if err := validateDisplayName(service.DisplayName); err != nil {
			return fmt.Errorf("%s.display_name: %w", field, err)
		}
		if service.Port == 0 {
			return fmt.Errorf("%s.port: must be between 1 and 65535", field)
		}
		if _, exists := seenPorts[service.Port]; exists {
			return fmt.Errorf("%s.port: conflicts with another managed listener", field)
		}
		seenPorts[service.Port] = struct{}{}
		if service.Type == ServiceTypeVLESSReality && compareVersions(value.XrayVersion, MinimumVLESSXrayVersion) < 0 {
			return fmt.Errorf("%s: VLESS REALITY requires Xray %s or newer", field, MinimumVLESSXrayVersion)
		}
		if err := validateServiceType(service, field); err != nil {
			return err
		}
	}
	if err := validateEgressLines(value.EgressLines); err != nil {
		return err
	}
	if err := validateAccessRules(value.AccessRules, value.Services, value.EgressLines, value.XrayVersion); err != nil {
		return err
	}
	return nil
}

func (value Configuration) FindService(serviceID string) (Service, bool) {
	for _, service := range value.Services {
		if service.ServiceID == serviceID {
			return service, true
		}
	}
	return Service{}, false
}

func (value Configuration) FindEgressLine(lineID string) (EgressLine, bool) {
	for _, line := range value.EgressLines {
		if line.LineID == lineID {
			return line, true
		}
	}
	return EgressLine{}, false
}

func DeriveCredential(seed, authorizationID, serviceID string) (string, error) {
	key, err := decodeKey("credential_seed", seed)
	if err != nil {
		return "", err
	}
	if authorizationID == "" || serviceID == "" || strings.ContainsRune(authorizationID, 0) || strings.ContainsRune(serviceID, 0) {
		return "", fmt.Errorf("authorization and service IDs are required")
	}
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(authorizationID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(serviceID))
	value := hash.Sum(nil)[:16]
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

// CredentialForVLESSRoute encodes Xray's per-request VLESS route in UUID
// bytes 7 and 8. Xray clears these bytes before matching the configured user.
func CredentialForVLESSRoute(credential string, route uint16) (string, error) {
	compact := strings.ReplaceAll(credential, "-", "")
	value, err := hex.DecodeString(compact)
	if err != nil || len(value) != 16 || fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]) != credential {
		return "", fmt.Errorf("credential: must be a canonical UUID")
	}
	value[6] = byte(route >> 8)
	value[7] = byte(route)
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func DeriveShadowsocksPassword(seed, authorizationID, serviceID, method string) (string, error) {
	if !IsShadowsocksMethod(method) {
		return "", fmt.Errorf("unsupported Shadowsocks method %q", method)
	}
	key, err := decodeKey("credential_seed", seed)
	if err != nil {
		return "", err
	}
	if authorizationID == "" || serviceID == "" || strings.ContainsRune(authorizationID, 0) || strings.ContainsRune(serviceID, 0) {
		return "", fmt.Errorf("authorization and service IDs are required")
	}
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte("shadowsocks-2022"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(authorizationID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(serviceID))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)[:ShadowsocksKeyBytes(method)]), nil
}

func UserEmail(authorizationID, serviceID string) string {
	return "relayward:" + authorizationID + ":" + serviceID
}

func compareVersions(first, second string) int {
	firstParts := strings.Split(first, ".")
	secondParts := strings.Split(second, ".")
	count := max(len(firstParts), len(secondParts))
	for index := 0; index < count; index++ {
		var firstValue, secondValue uint64
		if index < len(firstParts) {
			firstValue, _ = strconv.ParseUint(firstParts[index], 10, 64)
		}
		if index < len(secondParts) {
			secondValue, _ = strconv.ParseUint(secondParts[index], 10, 64)
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

func randomKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate configuration secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeKey(field, value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s: must be 32 bytes of unpadded base64url", field)
	}
	return raw, nil
}

func validateDisplayName(value string) error {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 100 {
		return fmt.Errorf("must contain 1 to 100 trimmed characters")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

func clone(value Configuration) Configuration {
	value.Services = append([]Service(nil), value.Services...)
	for index := range value.Services {
		value.Services[index].VLESSReality = cloneVLESSReality(value.Services[index].VLESSReality)
		value.Services[index].Shadowsocks = cloneShadowsocks(value.Services[index].Shadowsocks)
	}
	value.EgressLines = cloneEgressLines(value.EgressLines)
	value.AccessRules = cloneAccessRules(value.AccessRules)
	return value
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("configuration contains a trailing JSON value")
		}
		return fmt.Errorf("decode trailing configuration: %w", err)
	}
	return nil
}
