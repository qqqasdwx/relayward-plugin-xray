package xrayruntime

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
)

const (
	ListenerUnknown      = "unknown"
	ListenerListening    = "listening"
	ListenerNotListening = "not_listening"
)

type ListenerStatus struct {
	ServiceID     string
	Network       string
	ListenAddress string
	Port          uint16
	State         string
}

type socketEntry struct {
	network string
	address netip.Addr
	port    uint16
}

func inspectListeners(configuration config.Configuration) []ListenerStatus {
	listeners := configuredListeners(configuration)
	entries, err := readProcSockets()
	for index := range listeners {
		listeners[index].State = ListenerUnknown
		if err != nil {
			continue
		}
		listeners[index].State = ListenerNotListening
		address, parseErr := netip.ParseAddr(listeners[index].ListenAddress)
		if parseErr != nil {
			continue
		}
		for _, entry := range entries {
			if entry.network == listeners[index].Network && entry.port == listeners[index].Port &&
				listenerAddressMatches(address, entry.address) {
				listeners[index].State = ListenerListening
				break
			}
		}
	}
	return listeners
}

func listenerAddressMatches(configured, observed netip.Addr) bool {
	return configured == observed || configured.IsUnspecified() && observed.IsUnspecified()
}

func configuredListeners(configuration config.Configuration) []ListenerStatus {
	result := make([]ListenerStatus, 0, len(configuration.Services)*2)
	for _, service := range configuration.Services {
		if !service.Enabled {
			continue
		}
		networks := []string{"tcp"}
		if service.Type == config.ServiceTypeShadowsocks {
			networks = []string{"tcp", "udp"}
		}
		for _, network := range networks {
			result = append(result, ListenerStatus{
				ServiceID: service.ServiceID, Network: network, ListenAddress: "0.0.0.0", Port: service.Port,
			})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ServiceID != result[j].ServiceID {
			return result[i].ServiceID < result[j].ServiceID
		}
		return result[i].Network < result[j].Network
	})
	return result
}

func readProcSockets() ([]socketEntry, error) {
	result := make([]socketEntry, 0)
	for _, table := range []struct {
		path    string
		network string
		ipv6    bool
	}{
		{path: "/proc/net/tcp", network: "tcp"},
		{path: "/proc/net/tcp6", network: "tcp", ipv6: true},
		{path: "/proc/net/udp", network: "udp"},
		{path: "/proc/net/udp6", network: "udp", ipv6: true},
	} {
		file, err := os.Open(table.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", table.path, err)
		}
		entries, parseErr := parseProcSocketTable(file, table.network, table.ipv6)
		closeErr := file.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s: %w", table.path, parseErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", table.path, closeErr)
		}
		result = append(result, entries...)
	}
	return result, nil
}

func parseProcSocketTable(reader io.Reader, network string, ipv6 bool) ([]socketEntry, error) {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("socket table header is missing")
	}
	result := make([]socketEntry, 0)
	line := 1
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			return nil, fmt.Errorf("line %d has too few fields", line)
		}
		if network == "tcp" && fields[3] != "0A" {
			continue
		}
		if network == "udp" && fields[3] != "07" {
			continue
		}
		address, port, err := parseProcAddress(fields[1], ipv6)
		if err != nil {
			return nil, fmt.Errorf("line %d local address: %w", line, err)
		}
		result = append(result, socketEntry{network: network, address: address, port: port})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func parseProcAddress(value string, ipv6 bool) (netip.Addr, uint16, error) {
	addressHex, portHex, exists := strings.Cut(value, ":")
	if !exists {
		return netip.Addr{}, 0, errors.New("missing port separator")
	}
	wantBytes := 4
	if ipv6 {
		wantBytes = 16
	}
	raw, err := hex.DecodeString(addressHex)
	if err != nil || len(raw) != wantBytes {
		return netip.Addr{}, 0, errors.New("invalid hexadecimal address")
	}
	for start := 0; start < len(raw); start += 4 {
		raw[start], raw[start+3] = raw[start+3], raw[start]
		raw[start+1], raw[start+2] = raw[start+2], raw[start+1]
	}
	var address netip.Addr
	if ipv6 {
		value := [16]byte(raw)
		address = netip.AddrFrom16(value)
	} else {
		value := [4]byte(raw)
		address = netip.AddrFrom4(value)
	}
	parsedPort, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || parsedPort == 0 {
		return netip.Addr{}, 0, errors.New("invalid hexadecimal port")
	}
	return address, uint16(parsedPort), nil
}
