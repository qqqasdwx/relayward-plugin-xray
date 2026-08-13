package subscription

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/Relayward/relayward-plugin-xray/internal/config"
)

func TestRenderMultipleServicesInAllFormatsWithStableCredentials(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Services: []*centerpluginv1.SubscriptionServiceBinding{
			{ServiceId: "reality-backup", DisplayName: "Edge Backup"},
			{ServiceId: "reality-main", DisplayName: "Edge Main"},
		},
	}
	first, err := Render(configuration, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(configuration, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := centerpluginv1.ValidateRenderSubscriptionResponse(request, first); err != nil {
		t.Fatal(err)
	}
	if len(first.Services) != 2 || len(first.Services[0].Uris) != 1 || len(first.Services[1].Uris) != 1 ||
		first.Services[0].Uris[0] != second.Services[0].Uris[0] ||
		first.Services[0].Uris[0] == first.Services[1].Uris[0] {
		t.Fatalf("rendered subscription = %+v", first)
	}
	if !bytes.Contains(first.Services[0].MihomoProxiesJson[0], []byte(`"server":"backup.example.com"`)) ||
		!bytes.Contains(first.Services[1].MihomoProxiesJson[0], []byte(`"server":"edge.example.com"`)) ||
		!bytes.Contains(first.Services[0].SingBoxOutboundsJson[0], []byte(`"server_port":9443`)) ||
		!bytes.Contains(first.Services[1].SingBoxOutboundsJson[0], []byte(`"server_port":8443`)) {
		t.Fatalf("rendered fragments = %+v", first.Services)
	}
}

func TestRenderRejectsUnknownService(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Services: []*centerpluginv1.SubscriptionServiceBinding{{
			ServiceId: "reality-main", DisplayName: "Edge VLESS",
		}},
	}
	request.Services[0].ServiceId = "unknown"
	if _, err := Render(configuration, request); err == nil {
		t.Fatal("Render() accepted an unknown service")
	}
}

func TestRenderSubscriptionCompatibilityForAdvancedInboundSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		mutate      func(*config.Service)
		wantURI     map[string]string
		wantMihomo  int
		wantSingBox int
	}{
		{
			name: "RAW HTTP header",
			mutate: func(service *config.Service) {
				service.TCP = config.TCPSettings{Header: config.TCPHeader{Type: config.TCPHeaderHTTP,
					Request:  &config.TCPHTTPRequest{Version: "1.1", Method: "GET", Path: []string{"/edge"}, Headers: map[string][]string{"Host": {"addons.mozilla.org"}}},
					Response: &config.TCPHTTPResponse{Version: "1.1", Status: "200", Reason: "OK", Headers: map[string][]string{}},
				}}
			},
			wantURI: map[string]string{"headerType": "http", "path": "/edge", "host": "addons.mozilla.org"},
		},
		{
			name: "ML-DSA",
			mutate: func(service *config.Service) {
				service.VLESSReality.MLDSA65Seed = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
				service.VLESSReality.MLDSA65Verify = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("v", 1952)))
			},
			wantURI: map[string]string{"pqv": base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("v", 1952)))},
		},
		{
			name: "VLESS Encryption",
			mutate: func(service *config.Service) {
				serverKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
				clientKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
				service.VLESSReality.Decryption = "mlkem768x25519plus.native.600s." + serverKey
				service.VLESSReality.Encryption = "mlkem768x25519plus.native.0rtt." + clientKey
			},
			wantURI:    map[string]string{"encryption": "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))},
			wantMihomo: 1,
		},
		{
			name: "empty Flow",
			mutate: func(service *config.Service) {
				service.VLESSReality.Flow = ""
			},
			wantURI: map[string]string{"encryption": "none"}, wantMihomo: 1, wantSingBox: 1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			configuration := testConfiguration(t)
			service, _ := configuration.FindService("reality-main")
			test.mutate(&service)
			for index := range configuration.Services {
				if configuration.Services[index].ServiceID == service.ServiceID {
					configuration.Services[index] = service
				}
			}
			response, err := Render(configuration, &centerpluginv1.RenderSubscriptionRequest{
				AuthorizationId: "10000000-0000-4000-8000-000000000001",
				NodeId:          "20000000-0000-4000-8000-000000000002",
				Services:        []*centerpluginv1.SubscriptionServiceBinding{{ServiceId: "reality-main", DisplayName: "Edge Main"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			contribution := response.Services[0]
			parsed, err := url.Parse(contribution.Uris[0])
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range test.wantURI {
				if got := parsed.Query().Get(key); got != want {
					t.Fatalf("URI query %s = %q, want %q", key, got, want)
				}
			}
			if len(contribution.MihomoProxiesJson) != test.wantMihomo || len(contribution.SingBoxOutboundsJson) != test.wantSingBox {
				t.Fatalf("subscription formats = URI %d, Mihomo %d, sing-box %d", len(contribution.Uris), len(contribution.MihomoProxiesJson), len(contribution.SingBoxOutboundsJson))
			}
		})
	}
}

func TestSupportedFormatsMatchVLESSRealityRenderer(t *testing.T) {
	t.Parallel()
	formats := SupportedFormats(config.ServiceTypeVLESSReality)
	if !SupportsServiceType(config.ServiceTypeVLESSReality) || len(formats) != 3 ||
		formats[0] != "base64" || formats[1] != "mihomo" || formats[2] != "sing-box" ||
		SupportsServiceType("unknown") || SupportedFormats("unknown") != nil {
		t.Fatalf("supported formats = %v", formats)
	}
}

func testConfiguration(t *testing.T) config.Configuration {
	t.Helper()
	value, err := config.NewConfiguration("26.3.27", 10085, []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "0.0.0.0", Port: 443, PublicHost: "edge.example.com", PublicPort: 8443,
			VLESSReality: &config.EditableVLESSReality{
				Target: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"}, Fingerprint: "chrome",
			},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "0.0.0.0", Port: 444, PublicHost: "backup.example.com", PublicPort: 9443,
			VLESSReality: &config.EditableVLESSReality{
				Target: "www.cloudflare.com:443", ServerNames: []string{"www.cloudflare.com"}, Fingerprint: "chrome",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
