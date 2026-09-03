package xrayruntime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
)

type testAddress string

func (value testAddress) Network() string { return "ip" }
func (value testAddress) String() string  { return string(value) }

func TestNetworkAddressesFiltersDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	defer closeManager(t, manager)
	manager.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 1, Name: "down0"},
			{Index: 2, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			{Index: 3, Name: "eth1", Flags: net.FlagUp},
			{Index: 4, Name: "eth0", Flags: net.FlagUp},
		}, nil
	}
	manager.addresses = func(networkInterface net.Interface) ([]net.Addr, error) {
		switch networkInterface.Name {
		case "eth1":
			return []net.Addr{testAddress("2001:db8::2/64"), testAddress("169.254.1.1/16"), testAddress("invalid")}, nil
		case "eth0":
			return []net.Addr{
				testAddress("203.0.113.10/24"), testAddress("2001:db8::1/64"),
				testAddress("2001:db8::2/64"), testAddress("fe80::1/64"),
			}, nil
		default:
			return nil, nil
		}
	}
	addresses, err := manager.NetworkAddresses()
	if err != nil {
		t.Fatal(err)
	}
	want := []NetworkAddress{
		{Address: "203.0.113.10", Family: "ipv4", Interface: "eth0"},
		{Address: "2001:db8::1", Family: "ipv6", Interface: "eth0"},
		{Address: "2001:db8::2", Family: "ipv6", Interface: "eth1"},
	}
	if len(addresses) != len(want) {
		t.Fatalf("NetworkAddresses() = %+v", addresses)
	}
	for index := range want {
		if addresses[index] != want[index] {
			t.Fatalf("NetworkAddresses()[%d] = %+v, want %+v", index, addresses[index], want[index])
		}
	}
}

func TestProbeEgressUsesLineDiagnosticInbound(t *testing.T) {
	t.Parallel()
	manager := testManager(t)
	configuration := testConfigurationValue(t, "0.0.0.0")
	if err := manager.Apply(context.Background(), 1, digestA, configuration); err != nil {
		t.Fatal(err)
	}
	var proxyAddress string
	manager.probe = func(_ context.Context, address string) (EgressProbe, error) {
		proxyAddress = address
		return EgressProbe{Address: "203.0.113.10", ObservedAtUnixNano: 1, ElapsedMillis: 2}, nil
	}
	probe, err := manager.ProbeEgress(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	port, exists, err := xrayconfig.DiagnosticPort(configuration, "default")
	if err != nil || !exists {
		t.Fatal(err)
	}
	if probe.LineID != "default" || proxyAddress != net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))) {
		t.Fatalf("ProbeEgress() = %+v via %q", probe, proxyAddress)
	}
	if _, err := manager.ProbeEgress(context.Background(), "missing"); !errors.Is(err, ErrEgressLineUnavailable) {
		t.Fatalf("ProbeEgress(missing) error = %v", err)
	}
	closeManager(t, manager)
}

func TestParseCloudflareTrace(t *testing.T) {
	t.Parallel()
	fields := parseTrace([]byte("fl=1\nip=2001:db8::10\nloc=US\ncolo=SJC\nwarp=off\n"))
	if fields["ip"] != "2001:db8::10" || fields["loc"] != "US" || fields["colo"] != "SJC" || len(fields) != 3 {
		t.Fatalf("parseTrace() = %+v", fields)
	}
	if fields := parseTrace([]byte(strings.Repeat("ignored=value\n", 4))); len(fields) != 0 {
		t.Fatalf("parseTrace(unrelated) = %+v", fields)
	}
}

func closeManager(t *testing.T, manager *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
