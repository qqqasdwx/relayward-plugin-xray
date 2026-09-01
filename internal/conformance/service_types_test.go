package conformance

import (
	"reflect"
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/subscription"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

func TestRegisteredServiceTypesImplementDeclaredCapabilities(t *testing.T) {
	t.Parallel()
	fixtures := map[string]config.EditableService{
		config.ServiceTypeVLESSReality: {
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main", DisplayName: "Reality Main",
			Listen: "127.0.0.1", Port: 8443,
			VLESSReality: &config.EditableVLESSReality{Target: "addons.mozilla.org:443"},
		},
		config.ServiceTypeShadowsocks: {
			Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main", DisplayName: "Shadowsocks Main",
			Listen: "127.0.0.1", Port: 8388,
			Shadowsocks: &config.EditableShadowsocks{
				Method: config.ShadowsocksMethod2022AES256, Network: config.ShadowsocksNetworkTCPUDP,
			},
		},
	}
	definitions := config.SupportedServiceTypes()
	if len(definitions) != len(fixtures) {
		t.Fatalf("registered definitions = %d, fixtures = %d", len(definitions), len(fixtures))
	}
	for _, definition := range definitions {
		definition := definition
		t.Run(definition.ID, func(t *testing.T) {
			t.Parallel()
			fixture, exists := fixtures[definition.ID]
			if !exists {
				t.Fatal("registered service type has no conformance fixture")
			}
			configuration, err := config.NewConfiguration("26.7.28", 10085, []config.EditableService{fixture})
			if err != nil {
				t.Fatalf("build typed configuration: %v", err)
			}
			if definition.Capabilities.XrayInbound != xrayconfig.SupportsServiceType(definition.ID) {
				t.Fatal("Xray inbound capability does not match renderer support")
			}
			if definition.Capabilities.XrayInbound {
				if raw, err := xrayconfig.Render(configuration); err != nil || len(raw) == 0 {
					t.Fatalf("render Xray configuration: %v", err)
				}
			}
			runtimeCapabilities := definition.Capabilities.ServiceControl || definition.Capabilities.TrafficCounters ||
				definition.Capabilities.RecentActivity || definition.Capabilities.DynamicBlocking
			if runtimeCapabilities != xrayruntime.SupportsServiceType(definition.ID) {
				t.Fatal("runtime capability declaration does not match runtime support")
			}
			if !reflect.DeepEqual(definition.Capabilities.SubscriptionFormats, subscription.SupportedFormats(definition.ID)) {
				t.Fatalf("subscription formats = %v, declared = %v",
					subscription.SupportedFormats(definition.ID), definition.Capabilities.SubscriptionFormats)
			}
			if len(definition.Capabilities.SubscriptionFormats) > 0 {
				request := &centerpluginv1.RenderSubscriptionRequest{
					AuthorizationId: "10000000-0000-4000-8000-000000000001",
					NodeId:          "20000000-0000-4000-8000-000000000002",
					Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
						EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public", Kind: "nat", Address: "edge.example.com",
					}},
					Services: []*centerpluginv1.SubscriptionServiceBinding{{
						ServiceId: fixture.ServiceID, DisplayName: fixture.DisplayName,
					}},
				}
				rendered, err := subscription.Render(configuration, request)
				if err != nil || len(rendered.Services) != 1 || len(rendered.Services[0].Uris) == 0 ||
					len(rendered.Services[0].MihomoProxiesJson) == 0 || len(rendered.Services[0].SingBoxOutboundsJson) == 0 {
					t.Fatalf("render subscription contributions: %+v, %v", rendered, err)
				}
			}
		})
	}
}
