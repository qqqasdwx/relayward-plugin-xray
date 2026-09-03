package subscription

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

func TestRenderExpandsVLESSAcrossEndpointsAndEnabledEgressLines(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := testRequest()
	response, err := Render(configuration, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := centerpluginv1.ValidateRenderSubscriptionResponse(request, response); err != nil {
		t.Fatal(err)
	}
	vless := response.Services[0]
	if len(vless.Uris) != 4 || len(vless.MihomoProxiesJson) != 4 || len(vless.SingBoxOutboundsJson) != 4 {
		t.Fatalf("VLESS contribution = %+v", vless)
	}
	routes := map[uint16]int{}
	joined := strings.Join(vless.Uris, "\n")
	for _, rawURI := range vless.Uris {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatal(err)
		}
		credential, err := hex.DecodeString(strings.ReplaceAll(parsed.User.Username(), "-", ""))
		if err != nil || len(credential) != 16 {
			t.Fatalf("VLESS credential = %q, %v", parsed.User.Username(), err)
		}
		routes[uint16(credential[6])<<8|uint16(credential[7])]++
		if parsed.Query().Get("flow") != config.VLESSVisionFlow || parsed.Query().Get("sni") != "www.tesla.com" {
			t.Fatalf("VLESS URI = %q", rawURI)
		}
	}
	if routes[0] != 2 || routes[6] != 2 || len(routes) != 2 ||
		!strings.Contains(joined, "203.0.113.10:34443") || !strings.Contains(joined, "[2001:db8::10]:24443") ||
		!strings.Contains(joined, "Pinned%20IPv6") {
		t.Fatalf("expanded VLESS URIs = %q, routes = %+v", vless.Uris, routes)
	}
	for _, raw := range append(append([][]byte{}, vless.MihomoProxiesJson...), vless.SingBoxOutboundsJson...) {
		if !json.Valid(raw) {
			t.Fatalf("invalid subscription JSON = %s", raw)
		}
	}
}

func TestRenderShadowsocksUsesEndpointsButNotVLESSLines(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := testRequest()
	response, err := Render(configuration, request)
	if err != nil {
		t.Fatal(err)
	}
	shadowsocks := response.Services[1]
	if len(shadowsocks.Uris) != 2 || len(shadowsocks.MihomoProxiesJson) != 2 || len(shadowsocks.SingBoxOutboundsJson) != 2 {
		t.Fatalf("Shadowsocks contribution = %+v", shadowsocks)
	}
	joined := strings.Join(shadowsocks.Uris, "\n")
	if !strings.Contains(joined, "203.0.113.10:38443") || !strings.Contains(joined, "[2001:db8::10]:28443") ||
		strings.Contains(joined, "Pinned%20IPv6") {
		t.Fatalf("expanded Shadowsocks URIs = %q", shadowsocks.Uris)
	}
}

func TestRenderRejectsUnknownOrUnavailableService(t *testing.T) {
	t.Parallel()
	configuration := testConfiguration(t)
	request := testRequest()
	request.Services = request.Services[:1]
	request.Services[0].ServiceId = "missing"
	if _, err := Render(configuration, request); err == nil {
		t.Fatal("Render() accepted an unknown service")
	}
	request = testRequest()
	request.Services = request.Services[:1]
	configuration.Services[0].Enabled = false
	if _, err := Render(configuration, request); err == nil {
		t.Fatal("Render() accepted a disabled service")
	}
}

func testConfiguration(t *testing.T) config.Configuration {
	t.Helper()
	value, err := config.NewFromEditable(config.EditableConfiguration{
		XrayVersion: "26.7.28",
		Services: []config.EditableService{
			{
				Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main",
				DisplayName: "Reality Main", Port: 24443,
				VLESSReality: &config.EditableVLESSReality{Target: "www.tesla.com:443"},
			},
			{
				Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main",
				DisplayName: "Shadowsocks Main", Port: 28443,
				Shadowsocks: &config.EditableShadowsocks{Method: config.ShadowsocksMethod2022AES256},
			},
		},
		EgressLines: []config.EditableEgressLine{
			config.DefaultEgressLine(),
			{
				LineID: "ipv6", DisplayName: "Pinned IPv6", Enabled: true, VLESSRoute: 6,
				Type: config.EgressTypeDirect, Direct: &config.DirectEgress{SendThrough: "2001:db8::10"},
			},
			{
				LineID: "disabled", DisplayName: "Disabled", Enabled: false, VLESSRoute: 7,
				Type: config.EgressTypeDirect, Direct: &config.DirectEgress{},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testRequest() *centerpluginv1.RenderSubscriptionRequest {
	return &centerpluginv1.RenderSubscriptionRequest{
		AuthorizationId: "10000000-0000-4000-8000-000000000001",
		NodeId:          "20000000-0000-4000-8000-000000000002",
		Services: []*centerpluginv1.SubscriptionServiceBinding{
			{ServiceId: "reality-main", DisplayName: "Edge VLESS"},
			{ServiceId: "shadowsocks-main", DisplayName: "Edge SS"},
		},
		Endpoints: []*centerpluginv1.SubscriptionEndpoint{
			{
				EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "IPv4", Kind: "nat",
				Address: "203.0.113.10", PublicPortOverrides: map[string]uint32{"reality-main": 34443, "shadowsocks-main": 38443},
			},
			{
				EndpointId: "40000000-0000-4000-8000-000000000004", DisplayName: "IPv6", Kind: "direct",
				Address: "2001:db8::10",
			},
		},
	}
}
