package conformance

import (
	"testing"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/subscription"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

func TestRegisteredServiceTypesHaveCompleteImplementations(t *testing.T) {
	t.Parallel()
	fixtures := map[string]config.EditableService{
		config.ServiceTypeVLESSReality: {
			Type: config.ServiceTypeVLESSReality, Enabled: true, ServiceID: "reality-main",
			DisplayName: "Reality Main", Port: 24443,
			VLESSReality: &config.EditableVLESSReality{Target: "www.tesla.com:443"},
		},
		config.ServiceTypeShadowsocks: {
			Type: config.ServiceTypeShadowsocks, Enabled: true, ServiceID: "shadowsocks-main",
			DisplayName: "Shadowsocks Main", Port: 28443,
			Shadowsocks: &config.EditableShadowsocks{Method: config.ShadowsocksMethod2022AES256},
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
				t.Fatal("registered service type has no fixture")
			}
			configuration, err := config.NewConfiguration("26.7.28", []config.EditableService{fixture})
			if err != nil {
				t.Fatal(err)
			}
			if !xrayconfig.SupportsServiceType(definition.ID) || !xrayruntime.SupportsServiceType(definition.ID) ||
				!subscription.SupportsServiceType(definition.ID) || len(subscription.SupportedFormats(definition.ID)) != 3 {
				t.Fatal("service type support is incomplete")
			}
			if raw, err := xrayconfig.Render(configuration); err != nil || len(raw) == 0 {
				t.Fatalf("render Xray configuration: %v", err)
			}
			request := &centerpluginv1.RenderSubscriptionRequest{
				AuthorizationId: "10000000-0000-4000-8000-000000000001",
				NodeId:          "20000000-0000-4000-8000-000000000002",
				Services: []*centerpluginv1.SubscriptionServiceBinding{{
					ServiceId: fixture.ServiceID, DisplayName: fixture.DisplayName,
				}},
				Endpoints: []*centerpluginv1.SubscriptionEndpoint{{
					EndpointId: "30000000-0000-4000-8000-000000000003", DisplayName: "Public",
					Kind: "nat", Address: "edge.example.com",
				}},
			}
			rendered, err := subscription.Render(configuration, request)
			if err != nil || len(rendered.Services) != 1 || len(rendered.Services[0].Uris) == 0 ||
				len(rendered.Services[0].MihomoProxiesJson) == 0 || len(rendered.Services[0].SingBoxOutboundsJson) == 0 {
				t.Fatalf("render subscription = %+v, %v", rendered, err)
			}
		})
	}
}
