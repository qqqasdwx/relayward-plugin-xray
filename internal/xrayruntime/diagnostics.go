package xrayruntime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
)

const (
	egressProbeURL      = "https://www.cloudflare.com/cdn-cgi/trace"
	egressProbeTimeout  = 10 * time.Second
	egressProbeBodySize = 8 << 10
)

var ErrEgressLineUnavailable = errors.New("Xray egress line is unavailable")

type NetworkAddress struct {
	Address   string `json:"address"`
	Family    string `json:"family"`
	Interface string `json:"interface"`
}

type EgressProbe struct {
	LineID             string `json:"line_id"`
	Address            string `json:"address,omitempty"`
	Country            string `json:"country,omitempty"`
	Colocation         string `json:"colocation,omitempty"`
	ObservedAtUnixNano int64  `json:"observed_at_unix_nano"`
	ElapsedMillis      int64  `json:"elapsed_millis"`
}

func (manager *Manager) NetworkAddresses() ([]NetworkAddress, error) {
	interfaces, err := manager.interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	result := make([]NetworkAddress, 0)
	seen := make(map[string]struct{})
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := manager.addresses(networkInterface)
		if err != nil {
			return nil, fmt.Errorf("list addresses for interface %q: %w", networkInterface.Name, err)
		}
		for _, value := range addresses {
			raw, _, _ := strings.Cut(value.String(), "/")
			address, err := netip.ParseAddr(raw)
			if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
				continue
			}
			canonical := address.String()
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			family := "ipv6"
			if address.Is4() {
				family = "ipv4"
			}
			result = append(result, NetworkAddress{Address: canonical, Family: family, Interface: networkInterface.Name})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		if result[i].Interface != result[j].Interface {
			return result[i].Interface < result[j].Interface
		}
		return result[i].Address < result[j].Address
	})
	return result, nil
}

func (manager *Manager) ProbeEgress(ctx context.Context, lineID string) (EgressProbe, error) {
	manager.state.Lock()
	spec := manager.running
	process := manager.process
	manager.state.Unlock()
	if spec == nil || process == nil || process.exited() {
		return EgressProbe{}, ErrRuntimeUnavailable
	}
	line, exists := spec.configuration.FindEgressLine(lineID)
	if !exists || !line.Enabled {
		return EgressProbe{}, ErrEgressLineUnavailable
	}
	port, exists, err := xrayconfig.DiagnosticPort(spec.configuration, lineID)
	if err != nil {
		return EgressProbe{}, err
	}
	if !exists {
		return EgressProbe{}, ErrEgressLineUnavailable
	}
	result, err := manager.probe(ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		return EgressProbe{}, err
	}
	result.LineID = line.LineID
	return result, nil
}

func probeCloudflareTrace(parent context.Context, proxyAddress string) (EgressProbe, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddress, nil, proxy.Direct)
	if err != nil {
		return EgressProbe{}, errors.New("create Xray egress probe")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return EgressProbe{}, errors.New("Xray egress probe does not support cancellation")
	}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       contextDialer.DialContext,
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: egressProbeTimeout}
	ctx, cancel := context.WithTimeout(parent, egressProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, egressProbeURL, nil)
	if err != nil {
		return EgressProbe{}, errors.New("create Xray egress probe request")
	}
	request.Header.Set("Accept", "text/plain")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return EgressProbe{}, errors.New("send Xray egress probe")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return EgressProbe{}, fmt.Errorf("Xray egress probe returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, egressProbeBodySize+1))
	if err != nil || len(raw) > egressProbeBodySize {
		return EgressProbe{}, errors.New("read Xray egress probe response")
	}
	fields := parseTrace(raw)
	address, err := netip.ParseAddr(fields["ip"])
	if err != nil || address.String() != fields["ip"] || !address.IsGlobalUnicast() {
		return EgressProbe{}, errors.New("Xray egress probe returned an invalid address")
	}
	return EgressProbe{
		Address: address.String(), Country: fields["loc"], Colocation: fields["colo"],
		ObservedAtUnixNano: time.Now().UTC().UnixNano(), ElapsedMillis: time.Since(started).Milliseconds(),
	}, nil
}

func parseTrace(raw []byte) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		key, value, exists := strings.Cut(scanner.Text(), "=")
		if exists && (key == "ip" || key == "loc" || key == "colo") {
			result[key] = value
		}
	}
	return result
}
