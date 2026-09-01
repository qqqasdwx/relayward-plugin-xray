package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestRenderMultipleServicesInAllFormatsWithStableCredentials(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
			EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat",
			Address: "edge.example.com", PublicPortOverrides: map[string]uint32{"reality-backup": 9443},
		}},
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
	if !bytes.Contains(first.Services[0].MihomoProxiesJson[0], []byte(`"server":"edge.example.com"`)) ||
		!bytes.Contains(first.Services[1].MihomoProxiesJson[0], []byte(`"server":"edge.example.com"`)) ||
		!bytes.Contains(first.Services[0].SingBoxOutboundsJson[0], []byte(`"server_port":9443`)) ||
		!bytes.Contains(first.Services[1].SingBoxOutboundsJson[0], []byte(`"server_port":443`)) {
		t.Fatalf("rendered fragments = %+v", first.Services)
	}
}

func TestRenderRejectsUnknownService(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
			EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat", Address: "edge.example.com",
		}},
		Services: []*centerpluginv1.SubscriptionServiceBinding{{
			ServiceId: "reality-main", DisplayName: "Edge VLESS",
		}},
	}
	request.Services[0].ServiceId = "unknown"
	if _, err := Render(configuration, request); err == nil {
		t.Fatal("Render() accepted an unknown service")
	}
}

func TestRenderShadowsocks2022AndStandardSubscriptions(t *testing.T) {
	t.Parallel()
	for _, method := range []string{config.ShadowsocksMethod2022AES256, config.ShadowsocksMethodChaCha20} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			configuration, err := config.NewConfiguration("26.7.28", 10085, []config.EditableService{{
				Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main", DisplayName: "Shadowsocks Main",
				Listen: "0.0.0.0", Port: 8388,
				Shadowsocks: &config.EditableShadowsocks{Method: method, Network: config.ShadowsocksNetworkTCPUDP},
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := &centerpluginv1.RenderSubscriptionRequest{
				AuthorizationId: "10000000-0000-4000-8000-000000000001",
				NodeId:          "20000000-0000-4000-8000-000000000002",
				Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
					EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat", Address: "ss.example.com",
				}},
				Services: []*centerpluginv1.SubscriptionServiceBinding{{
					ServiceId: "shadowsocks-main", DisplayName: "Edge SS",
				}},
			}
			rendered, err := Render(configuration, request)
			if err != nil {
				t.Fatal(err)
			}
			service := configuration.Services[0]
			userPassword, _ := config.DeriveShadowsocksPassword(
				configuration.CredentialSeed, request.AuthorizationId, service.ServiceID, method,
			)
			password := config.ShadowsocksClientPassword(*service.Shadowsocks, userPassword)
			contribution := rendered.Services[0]
			if len(contribution.Uris) != 1 || len(contribution.MihomoProxiesJson) != 1 || len(contribution.SingBoxOutboundsJson) != 1 {
				t.Fatalf("Shadowsocks contribution = %+v", contribution)
			}
			var mihomo map[string]any
			var singBox map[string]any
			if err := json.Unmarshal(contribution.MihomoProxiesJson[0], &mihomo); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(contribution.SingBoxOutboundsJson[0], &singBox); err != nil {
				t.Fatal(err)
			}
			if mihomo["cipher"] != method || mihomo["password"] != password || mihomo["udp"] != true ||
				singBox["method"] != method || singBox["password"] != password {
				t.Fatalf("Shadowsocks fragments = %s, %s", contribution.MihomoProxiesJson[0], contribution.SingBoxOutboundsJson[0])
			}
			if config.IsShadowsocks2022(method) {
				if !strings.Contains(contribution.Uris[0], method+":"+url.QueryEscape(service.Shadowsocks.ServerKey)+":"+url.QueryEscape(userPassword)) {
					t.Fatalf("Shadowsocks 2022 URI = %q", contribution.Uris[0])
				}
			} else {
				parsed, err := url.Parse(contribution.Uris[0])
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := base64.RawURLEncoding.DecodeString(parsed.User.Username())
				if err != nil || string(decoded) != method+":"+userPassword {
					t.Fatalf("Shadowsocks URI userinfo = %q, %v", decoded, err)
				}
			}
		})
	}
}

func TestRenderSubscriptionWithoutVisionFlow(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	for index := range configuration.Services {
		if configuration.Services[index].ServiceID == "reality-main" {
			configuration.Services[index].VLESSReality.Flow = ""
		}
	}
	response, err := Render(configuration, &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
			EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat", Address: "edge.example.com",
		}},
		Services: []*centerpluginv1.SubscriptionServiceBinding{{ServiceId: "reality-main", DisplayName: "Edge Main"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	contribution := response.Services[0]
	parsed, err := url.Parse(contribution.Uris[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("encryption") != "none" || parsed.Query().Get("flow") != "" ||
		len(contribution.MihomoProxiesJson) != 1 || len(contribution.SingBoxOutboundsJson) != 1 {
		t.Fatalf("subscription contribution = %+v", contribution)
	}
}

func TestRenderExpandsEachServiceAcrossEndpoints(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Services:        []*centerpluginv1.SubscriptionServiceBinding{{ServiceId: "reality-main", DisplayName: "Edge Main"}},
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{
			{
				EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "IPv4", Kind: "direct",
				Address: "203.0.113.10", PublicPortOverrides: map[string]uint32{"reality-main": 8443},
			},
			{
				EndpointId: "40000000-0000-4000-8000-000000000004", DisplayName: "IPv6", Kind: "direct",
				Address: "2001:db8::10",
			},
		},
	}
	response, err := Render(configuration, request)
	if err != nil {
		t.Fatal(err)
	}
	contribution := response.Services[0]
	if len(contribution.Uris) != 2 || len(contribution.MihomoProxiesJson) != 2 || len(contribution.SingBoxOutboundsJson) != 2 {
		t.Fatalf("expanded contribution = %+v", contribution)
	}
	joined := strings.Join(contribution.Uris, "\n")
	if !strings.Contains(joined, "203.0.113.10:8443") || !strings.Contains(joined, "[2001:db8::10]:443") ||
		!strings.Contains(joined, "Edge%20Main%20/%20IPv4") || !strings.Contains(joined, "Edge%20Main%20/%20IPv6") {
		t.Fatalf("expanded URIs = %q", contribution.Uris)
	}
	if !bytes.Contains(contribution.MihomoProxiesJson[0], []byte(`"name":"Edge Main / `)) ||
		!bytes.Contains(contribution.SingBoxOutboundsJson[0], []byte(`"tag":"Edge Main / `)) {
		t.Fatalf("expanded fragments = %+v", contribution)
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
	value, err := config.NewConfiguration("26.7.28", 10085, []config.EditableService{
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "0.0.0.0", Port: 443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.microsoft.com:443"},
		},
		{
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-backup", DisplayName: "Reality Backup",
			Listen: "0.0.0.0", Port: 444,
			VLESSReality: &config.EditableVLESSReality{Target: "www.cloudflare.com:443"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
