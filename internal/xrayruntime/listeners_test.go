package xrayruntime

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseProcSocketTableFiltersTCPListeners(t *testing.T) {
	value := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:50A0 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1
   1: 0100007F:01BB 0100007F:C350 01 00000000:00000000 00:00000000 00000000 0 0 2
`
	entries, err := parseProcSocketTable(strings.NewReader(value), "tcp", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].address.String() != "0.0.0.0" || entries[0].port != 20640 {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseProcIPv6Address(t *testing.T) {
	address, port, err := parseProcAddress("00000000000000000000000001000000:01BB", true)
	if err != nil {
		t.Fatal(err)
	}
	if address.String() != "::1" || port != 443 {
		t.Fatalf("address = %s, port = %d", address, port)
	}
}

func TestListenerAddressMatchesDualStackWildcard(t *testing.T) {
	t.Parallel()
	if !listenerAddressMatches(netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::")) {
		t.Fatal("IPv4 wildcard did not match Xray's dual-stack wildcard listener")
	}
	if listenerAddressMatches(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::")) {
		t.Fatal("specific IPv4 address unexpectedly matched an IPv6 wildcard listener")
	}
}
