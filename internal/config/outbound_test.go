package config

import "testing"

func TestOutboundsAcceptManagedAndCustomFreedomAndBlackhole(t *testing.T) {
	t.Parallel()
	value, err := NewConfiguration("26.7.28", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	value.Outbounds = append(value.Outbounds,
		Outbound{
			Tag: "IPv4", Protocol: OutboundProtocolFreedom,
			Freedom: &FreedomOutboundSettings{
				DomainStrategy: "UseIPv4", Redirect: "127.0.0.1:1080", UserLevel: 1, ProxyProtocol: 2,
				Fragment:   &FreedomFragment{Packets: "tlshello", Length: "100-200", Interval: "10-20", MaxSplit: "300-400"},
				Noises:     []FreedomNoise{{Type: "rand", Packet: "10-20", Delay: "10-16", ApplyTo: "ipv4"}},
				FinalRules: []FreedomFinalRule{{Action: "block", Network: "tcp", Port: "443", IPs: []string{"geoip:private"}, BlockDelay: "5000-10000"}},
			},
		},
		Outbound{Tag: "pt_blocked", Protocol: OutboundProtocolBlackhole, Blackhole: &BlackholeOutboundSettings{ResponseType: "none"}},
	)
	value.Routing = RoutingConfiguration{Rules: []RoutingRule{{
		RuleID: "force-ipv4", DisplayName: "Force IPv4", Enabled: true,
		Domains: []string{"geosite:google"}, OutboundTag: "IPv4",
	}}}
	if err := Validate(value); err != nil {
		t.Fatalf("Validate() rejected supported outbounds: %v", err)
	}
	value.Outbounds[0].Freedom.DomainStrategy = ""
	value.Outbounds[0].Freedom.Fragment = &FreedomFragment{Packets: "1-3", Interval: "10-20"}
	if err := Validate(value); err != nil {
		t.Fatalf("Validate() rejected optional domain strategy or partial fragment: %v", err)
	}
	cloned := clone(value)
	cloned.Outbounds[2].Freedom.FinalRules[0].IPs[0] = "geoip:cn"
	if value.Outbounds[2].Freedom.FinalRules[0].IPs[0] != "geoip:private" {
		t.Fatal("clone() aliased outbound settings")
	}
}

func TestOutboundValidationRejectsInvalidDefinitionsAndReferences(t *testing.T) {
	t.Parallel()
	valid, err := NewConfiguration("26.7.28", 10085, testEditableServices()[:1])
	if err != nil {
		t.Fatal(err)
	}
	valid.Routing = RoutingConfiguration{Rules: []RoutingRule{{
		RuleID: "block-private", DisplayName: "Block private", Enabled: true,
		DestinationIPs: []string{"geoip:private"}, OutboundTag: OutboundTagBlocked,
	}}}
	tests := map[string]func(*Configuration){
		"missing system outbound": func(value *Configuration) { value.Outbounds = value.Outbounds[:1] },
		"duplicate tag":           func(value *Configuration) { value.Outbounds[1].Tag = OutboundTagDirect },
		"reserved tag":            func(value *Configuration) { value.Outbounds[0].Tag = "relayward-api" },
		"wrong direct protocol": func(value *Configuration) {
			value.Outbounds[0] = Outbound{Tag: OutboundTagDirect, Protocol: OutboundProtocolBlackhole, Blackhole: &BlackholeOutboundSettings{}}
		},
		"missing settings":        func(value *Configuration) { value.Outbounds[0].Freedom = nil },
		"invalid domain strategy": func(value *Configuration) { value.Outbounds[0].Freedom.DomainStrategy = "PreferIPv4" },
		"invalid fragment": func(value *Configuration) {
			value.Outbounds[0].Freedom.Fragment = &FreedomFragment{Packets: "bad", Length: "1-2", Interval: "1-2", MaxSplit: "1-2"}
		},
		"invalid final rule":       func(value *Configuration) { value.Outbounds[0].Freedom.FinalRules[0].Action = "reject" },
		"unknown routing outbound": func(value *Configuration) { value.Routing.Rules[0].OutboundTag = "missing" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() unexpectedly succeeded")
			}
		})
	}
}
