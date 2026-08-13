// Package config owns the structured Xray configuration understood by the official Relayward plugin.
package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Relayward/relayward-sdk/contract"
)

const (
	ServiceTypeVLESSReality = "vless-reality"
	VLESSVisionFlow         = "xtls-rprx-vision"
	MaximumServices         = 64
	MaximumRoutingRules     = 128
	MaximumRoutingValues    = 64
	MaximumDNSServers       = 16
)

var (
	serviceIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	publicDomainPattern = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$`)
)

type Configuration struct {
	XrayVersion    string               `json:"xray_version"`
	APIPort        uint16               `json:"api_port"`
	CredentialSeed string               `json:"credential_seed"`
	Services       []Service            `json:"services"`
	Routing        RoutingConfiguration `json:"routing"`
	DNS            DNSConfiguration     `json:"dns"`
}

type Service struct {
	Type         string          `json:"type"`
	Enabled      bool            `json:"enabled"`
	ServiceID    string          `json:"service_id"`
	DisplayName  string          `json:"display_name"`
	Listen       string          `json:"listen"`
	Port         uint16          `json:"port"`
	PublicHost   string          `json:"public_host"`
	PublicPort   uint16          `json:"public_port"`
	TCP          TCPSettings     `json:"tcp"`
	Sockopt      *SocketSettings `json:"sockopt,omitempty"`
	Sniffing     Sniffing        `json:"sniffing"`
	VLESSReality *VLESSReality   `json:"vless_reality,omitempty"`
}

type EditableConfiguration struct {
	XrayVersion string               `json:"xray_version"`
	APIPort     uint16               `json:"api_port"`
	Services    []EditableService    `json:"services"`
	Routing     RoutingConfiguration `json:"routing"`
	DNS         DNSConfiguration     `json:"dns"`
}

type EditableService struct {
	Type         string                `json:"type"`
	Enabled      bool                  `json:"enabled"`
	ServiceID    string                `json:"service_id"`
	DisplayName  string                `json:"display_name"`
	Listen       string                `json:"listen"`
	Port         uint16                `json:"port"`
	PublicHost   string                `json:"public_host"`
	PublicPort   uint16                `json:"public_port"`
	TCP          TCPSettings           `json:"tcp"`
	Sockopt      *SocketSettings       `json:"sockopt,omitempty"`
	Sniffing     Sniffing              `json:"sniffing"`
	VLESSReality *EditableVLESSReality `json:"vless_reality,omitempty"`
}

func Editable(value Configuration) EditableConfiguration {
	services := make([]EditableService, len(value.Services))
	for index, service := range value.Services {
		services[index] = EditableService{
			Type: service.Type, Enabled: service.Enabled, ServiceID: service.ServiceID,
			DisplayName: service.DisplayName, Listen: service.Listen, Port: service.Port,
			PublicHost: service.PublicHost, PublicPort: service.PublicPort,
			TCP: cloneTCPSettings(service.TCP), Sockopt: cloneSocketSettings(service.Sockopt),
			Sniffing:     cloneSniffing(service.Sniffing),
			VLESSReality: editableVLESSReality(service.VLESSReality),
		}
	}
	return EditableConfiguration{
		XrayVersion: value.XrayVersion, APIPort: value.APIPort, Services: services,
		Routing: cloneRouting(value.Routing), DNS: cloneDNS(value.DNS),
	}
}

func NewConfiguration(xrayVersion string, apiPort uint16, services []EditableService) (Configuration, error) {
	return NewFromEditable(EditableConfiguration{XrayVersion: xrayVersion, APIPort: apiPort, Services: services})
}

func NewFromEditable(value EditableConfiguration) (Configuration, error) {
	seed, err := randomKey()
	if err != nil {
		return Configuration{}, err
	}
	configuration := Configuration{CredentialSeed: seed}
	return MergeEditable(configuration, value)
}

func MergeEditable(configuration Configuration, value EditableConfiguration) (Configuration, error) {
	existing := make(map[string]Service, len(configuration.Services))
	for _, service := range configuration.Services {
		existing[service.ServiceID] = service
	}
	services := make([]Service, len(value.Services))
	for index, editable := range value.Services {
		service, exists := existing[editable.ServiceID]
		var err error
		service, err = mergeServiceType(service, exists && service.Type == editable.Type, editable)
		if err != nil {
			return Configuration{}, err
		}
		service.Type = editable.Type
		service.Enabled = editable.Enabled
		service.ServiceID = editable.ServiceID
		service.DisplayName = editable.DisplayName
		service.Listen = editable.Listen
		service.Port = editable.Port
		publicHost, err := normalizePublicHost(editable.PublicHost)
		if err != nil {
			return Configuration{}, fmt.Errorf("services[%d].public_host: %w", index, err)
		}
		service.PublicHost = publicHost
		service.PublicPort = editable.PublicPort
		if editable.TCP.Header.Type == "" {
			editable.TCP.Header.Type = TCPHeaderNone
		}
		service.TCP = cloneTCPSettings(editable.TCP)
		service.Sockopt = cloneSocketSettings(editable.Sockopt)
		service.Sniffing = cloneSniffing(editable.Sniffing)
		services[index] = service
	}
	configuration.XrayVersion = value.XrayVersion
	configuration.APIPort = value.APIPort
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
	configuration.Services = services
	configuration.Routing = cloneRouting(value.Routing)
	configuration.DNS = cloneDNS(value.DNS)
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

func Validate(value Configuration) error {
	if err := contract.ValidateSemanticVersion(value.XrayVersion); err != nil {
		return fmt.Errorf("xray_version: %w", err)
	}
	if strings.ContainsAny(value.XrayVersion, "-+") {
		return fmt.Errorf("xray_version: pre-release and build versions are not supported")
	}
	if value.APIPort < 1024 {
		return fmt.Errorf("api_port: must be between 1024 and 65535")
	}
	if _, err := decodeKey("credential_seed", value.CredentialSeed); err != nil {
		return err
	}
	if len(value.Services) > MaximumServices {
		return fmt.Errorf("services: must contain at most %d services", MaximumServices)
	}
	seenIDs := make(map[string]struct{}, len(value.Services))
	for index, service := range value.Services {
		field := fmt.Sprintf("services[%d]", index)
		if _, exists := ServiceTypeDefinitionByID(service.Type); !exists {
			return fmt.Errorf("%s.type: unsupported service type", field)
		}
		if !serviceIDPattern.MatchString(service.ServiceID) {
			return fmt.Errorf("%s.service_id: must match %s", field, serviceIDPattern)
		}
		if _, exists := seenIDs[service.ServiceID]; exists {
			return fmt.Errorf("%s.service_id: duplicate service ID", field)
		}
		seenIDs[service.ServiceID] = struct{}{}
		if index > 0 && value.Services[index-1].ServiceID > service.ServiceID {
			return fmt.Errorf("%s.service_id: services must be sorted by service ID", field)
		}
		if err := validateCommonService(value.APIPort, service, field); err != nil {
			return err
		}
		if err := validateTCPSettings(service.TCP, field+".tcp"); err != nil {
			return err
		}
		if err := validateSocketSettings(service.Sockopt, field+".sockopt"); err != nil {
			return err
		}
		if err := validateSniffing(service.Sniffing, field+".sniffing"); err != nil {
			return err
		}
		if err := validateServiceType(service, field); err != nil {
			return err
		}
		for previousIndex := 0; previousIndex < index; previousIndex++ {
			previous := value.Services[previousIndex]
			if service.Port == previous.Port && listenersOverlap(service.Listen, previous.Listen) {
				return fmt.Errorf("%s.port: conflicts with services[%d]", field, previousIndex)
			}
		}
	}
	if err := validateRouting(value.Routing); err != nil {
		return err
	}
	if err := validateDNS(value.DNS); err != nil {
		return err
	}
	return nil
}

func validateCommonService(apiPort uint16, service Service, field string) error {
	if err := validateDisplayName(service.DisplayName); err != nil {
		return fmt.Errorf("%s.display_name: %w", field, err)
	}
	listen, err := netip.ParseAddr(service.Listen)
	if err != nil || listen.String() != service.Listen {
		return fmt.Errorf("%s.listen: must be a canonical IP address", field)
	}
	if service.Port == 0 || service.PublicPort == 0 {
		return fmt.Errorf("%s.port and public_port: must be between 1 and 65535", field)
	}
	publicHost, err := normalizePublicHost(service.PublicHost)
	if err != nil {
		return fmt.Errorf("%s.public_host: %w", field, err)
	}
	if publicHost != service.PublicHost {
		return fmt.Errorf("%s.public_host: must use its canonical lowercase form", field)
	}
	if service.Port == apiPort && (listen.IsLoopback() || listen.IsUnspecified()) {
		return fmt.Errorf("%s.port: conflicts with the local API port", field)
	}
	return nil
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

func (value Configuration) FindService(serviceID string) (Service, bool) {
	for _, service := range value.Services {
		if service.ServiceID == serviceID {
			return service, true
		}
	}
	return Service{}, false
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

func UserEmail(authorizationID, serviceID string) string {
	return "relayward:" + authorizationID + ":" + serviceID
}

func randomKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate configuration secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func clone(value Configuration) Configuration {
	value.Services = append([]Service(nil), value.Services...)
	for index := range value.Services {
		value.Services[index].TCP = cloneTCPSettings(value.Services[index].TCP)
		value.Services[index].Sockopt = cloneSocketSettings(value.Services[index].Sockopt)
		value.Services[index].Sniffing = cloneSniffing(value.Services[index].Sniffing)
		value.Services[index].VLESSReality = cloneVLESSReality(value.Services[index].VLESSReality)
	}
	value.Routing = cloneRouting(value.Routing)
	value.DNS = cloneDNS(value.DNS)
	return value
}

func listenersOverlap(first, second string) bool {
	firstAddress, firstErr := netip.ParseAddr(first)
	secondAddress, secondErr := netip.ParseAddr(second)
	if firstErr != nil || secondErr != nil {
		return false
	}
	return firstAddress == secondAddress || firstAddress.IsUnspecified() || secondAddress.IsUnspecified()
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

func normalizePublicHost(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("is required")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.String() != value || address.IsUnspecified() {
			return "", fmt.Errorf("must be a canonical IP other than an unspecified address")
		}
		return value, nil
	}
	if len(value) > 253 || !publicDomainPattern.MatchString(value) {
		return "", fmt.Errorf("must be a domain or canonical IP without a port")
	}
	return strings.ToLower(value), nil
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
