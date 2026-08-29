package xrayruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
)

const xrayAPITimeout = 3 * time.Second

var (
	ErrRuntimeUnavailable   = errors.New("Xray runtime is unavailable")
	ErrUnsupportedService   = errors.New("Xray service is unsupported")
	ErrServiceDisabled      = errors.New("Xray service is disabled")
	ErrServiceStateConflict = errors.New("Xray service state revision conflicts with current state")
	ErrDynamicBlockConflict = errors.New("Xray dynamic block revision conflicts with current state")
)

type TrafficCounter struct {
	AuthorizationID string
	ServiceID       string
	CounterEpoch    string
	UploadBytes     uint64
	DownloadBytes   uint64
}

type DynamicBlock struct {
	AuthorizationID   string
	ServiceID         string
	SourceIP          string
	ExpiresAtUnixNano int64
}

type xrayAPI struct {
	connection *grpc.ClientConn
}

type runtimeAPI interface {
	addUser(context.Context, string, runtimeCredential) error
	removeUser(context.Context, string, string) error
	queryStats(context.Context) ([]trafficStat, error)
	queryOnlineIPs(context.Context, string) (map[string]int64, error)
	replaceRoutingRules(context.Context, string, []xrayconfig.CompiledRoutingRule) error
	close()
}

func SupportsServiceType(serviceType string) bool {
	return serviceType == config.ServiceTypeVLESSReality || serviceType == config.ServiceTypeShadowsocks
}

func connectXrayAPI(parent context.Context, configuration config.Configuration) (*xrayAPI, error) {
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	connection, err := grpc.DialContext(ctx, apiAddress(configuration),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, errors.New("connect to Xray API")
	}
	return &xrayAPI{connection: connection}, nil
}

func (api *xrayAPI) close() {
	if api != nil && api.connection != nil {
		_ = api.connection.Close()
	}
}

func (manager *Manager) ApplyServiceState(ctx context.Context, policyGeneration, stateRevision uint64,
	authorizationID, serviceID string, enabled bool,
) error {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	manager.state.Lock()
	spec := manager.running
	process := manager.process
	manager.state.Unlock()
	if spec == nil || process == nil || process.exited() || process.api == nil {
		return ErrRuntimeUnavailable
	}
	key := serviceKey(authorizationID, serviceID)
	current := manager.services[key]
	service, exists := spec.configuration.FindService(serviceID)
	if !exists && enabled {
		return ErrUnsupportedService
	}
	if enabled && !service.Enabled {
		return ErrServiceDisabled
	}
	if current != nil && (stateRevision < current.stateRevision ||
		(stateRevision == current.stateRevision && (policyGeneration != current.policyGeneration || enabled != current.enabled))) {
		return ErrServiceStateConflict
	}
	if current != nil && current.policyGeneration == policyGeneration && current.stateRevision == stateRevision && current.enabled == enabled {
		return nil
	}
	if current != nil && !enabled && current.enabled {
		if err := manager.refreshTraffic(ctx, process); err != nil {
			return err
		}
	}
	if current == nil || current.enabled != enabled {
		if enabled {
			credential, err := credentialFor(spec.configuration, authorizationID, serviceID)
			if err != nil {
				return err
			}
			if err := process.api.addUser(ctx, service.ServiceID, credential); err != nil {
				return err
			}
		} else if exists && current != nil && current.enabled {
			if err := process.api.removeUser(ctx, service.ServiceID,
				config.UserEmail(authorizationID, serviceID)); err != nil {
				return err
			}
		}
	}
	if current == nil {
		current = &serviceState{authorizationID: authorizationID, serviceID: serviceID}
		manager.services[key] = current
	}
	current.enabled = enabled
	current.policyGeneration = policyGeneration
	current.stateRevision = stateRevision
	return nil
}

func (manager *Manager) CollectTraffic(ctx context.Context) ([]TrafficCounter, error) {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	manager.state.Lock()
	process := manager.process
	manager.state.Unlock()
	if process == nil || process.exited() || process.api == nil || manager.epoch == "" {
		return nil, ErrRuntimeUnavailable
	}
	if err := manager.refreshTraffic(ctx, process); err != nil {
		return nil, err
	}
	values := make([]TrafficCounter, 0, len(manager.services))
	for _, state := range manager.services {
		upload, err := addCounter(state.uploadBase, state.uploadRaw)
		if err != nil {
			return nil, err
		}
		download, err := addCounter(state.downloadBase, state.downloadRaw)
		if err != nil {
			return nil, err
		}
		values = append(values, TrafficCounter{
			AuthorizationID: state.authorizationID,
			ServiceID:       state.serviceID,
			CounterEpoch:    manager.epoch,
			UploadBytes:     upload,
			DownloadBytes:   download,
		})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].AuthorizationID != values[j].AuthorizationID {
			return values[i].AuthorizationID < values[j].AuthorizationID
		}
		return values[i].ServiceID < values[j].ServiceID
	})
	return values, nil
}

func (manager *Manager) TelemetryStreamID() string {
	return manager.telemetry.streamID()
}

func (manager *Manager) CollectActivity(ctx context.Context, after uint64, maximum uint32) (ActivityPage, error) {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	manager.state.Lock()
	spec := manager.running
	process := manager.process
	manager.state.Unlock()
	if spec == nil || process == nil || process.exited() || process.api == nil {
		return ActivityPage{}, ErrRuntimeUnavailable
	}
	active := make(map[string]ActivitySource)
	for _, service := range manager.services {
		configured, exists := spec.configuration.FindService(service.serviceID)
		if !service.enabled || !exists || !configured.Enabled {
			continue
		}
		email := config.UserEmail(service.authorizationID, service.serviceID)
		values, err := process.api.queryOnlineIPs(ctx, email)
		if err != nil {
			return ActivityPage{}, err
		}
		for sourceIP := range values {
			key := serviceKey(service.authorizationID, service.serviceID) + "\x00" + sourceIP
			active[key] = ActivitySource{
				AuthorizationID: service.authorizationID, ServiceID: service.serviceID, SourceIP: sourceIP,
			}
		}
	}
	return manager.telemetry.appendSnapshot(after, maximum, active, time.Now().UTC())
}

func (manager *Manager) ApplyDynamicBlocks(ctx context.Context, policyGeneration, blockRevision uint64, blocks []DynamicBlock) error {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	manager.state.Lock()
	spec := manager.running
	process := manager.process
	manager.state.Unlock()
	if spec == nil || process == nil || process.exited() || process.api == nil {
		return ErrRuntimeUnavailable
	}
	for _, block := range blocks {
		service, exists := spec.configuration.FindService(block.ServiceID)
		if !exists {
			return ErrUnsupportedService
		}
		if !service.Enabled {
			return ErrServiceDisabled
		}
		ip := net.ParseIP(block.SourceIP)
		if ip == nil || ip.String() != block.SourceIP || block.ExpiresAtUnixNano <= 0 {
			return errors.New("invalid Xray dynamic block")
		}
	}
	if manager.blockRevision != 0 {
		if blockRevision < manager.blockRevision || policyGeneration < manager.blockPolicyGeneration ||
			(blockRevision == manager.blockRevision &&
				(policyGeneration != manager.blockPolicyGeneration || !sameDynamicBlocks(blocks, manager.blocks))) {
			return ErrDynamicBlockConflict
		}
		if blockRevision == manager.blockRevision {
			return nil
		}
	}
	rules, err := xrayconfig.CompileRoutingRules(spec.configuration, runtimeBlockRules(blocks))
	if err != nil {
		return err
	}
	if err := process.api.replaceRoutingRules(ctx, spec.configuration.XrayVersion, rules); err != nil {
		return err
	}
	manager.blocks = append([]DynamicBlock(nil), blocks...)
	manager.blockPolicyGeneration = policyGeneration
	manager.blockRevision = blockRevision
	return nil
}

func (manager *Manager) restoreBlockRules(ctx context.Context, configuration config.Configuration, api runtimeAPI) error {
	if len(manager.blocks) == 0 {
		return nil
	}
	blocks := make([]DynamicBlock, 0, len(manager.blocks))
	for _, block := range manager.blocks {
		service, exists := configuration.FindService(block.ServiceID)
		if exists && service.Enabled {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		return nil
	}
	rules, err := xrayconfig.CompileRoutingRules(configuration, runtimeBlockRules(blocks))
	if err != nil {
		return err
	}
	return api.replaceRoutingRules(ctx, configuration.XrayVersion, rules)
}

func runtimeBlockRules(blocks []DynamicBlock) []xrayconfig.DynamicBlockRule {
	values := make([]xrayconfig.DynamicBlockRule, len(blocks))
	for index, block := range blocks {
		values[index] = xrayconfig.DynamicBlockRule{
			UserEmail:  config.UserEmail(block.AuthorizationID, block.ServiceID),
			InboundTag: block.ServiceID, SourceIP: block.SourceIP,
		}
	}
	return values
}

func sameDynamicBlocks(first, second []DynamicBlock) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (manager *Manager) restoreServices(ctx context.Context, spec *runtimeSpec, api runtimeAPI) error {
	type serviceCredential struct {
		inboundTag string
		credential runtimeCredential
	}
	credentials := make([]serviceCredential, 0, len(manager.services))
	for _, state := range manager.services {
		service, exists := spec.configuration.FindService(state.serviceID)
		if !state.enabled || !exists || !service.Enabled {
			continue
		}
		credential, err := credentialFor(spec.configuration, state.authorizationID, state.serviceID)
		if err != nil {
			return err
		}
		credentials = append(credentials, serviceCredential{inboundTag: service.ServiceID, credential: credential})
	}
	sort.Slice(credentials, func(i, j int) bool {
		if credentials[i].inboundTag != credentials[j].inboundTag {
			return credentials[i].inboundTag < credentials[j].inboundTag
		}
		return credentials[i].credential.email < credentials[j].credential.email
	})
	for _, value := range credentials {
		if err := api.addUser(ctx, value.inboundTag, value.credential); err != nil {
			return err
		}
	}
	return nil
}

func credentialFor(configuration config.Configuration, authorizationID, serviceID string) (runtimeCredential, error) {
	service, exists := configuration.FindService(serviceID)
	if !exists {
		return runtimeCredential{}, ErrUnsupportedService
	}
	switch service.Type {
	case config.ServiceTypeVLESSReality:
		id, err := config.DeriveCredential(configuration.CredentialSeed, authorizationID, serviceID)
		if err != nil {
			return runtimeCredential{}, err
		}
		return runtimeCredential{
			serviceType: service.Type, id: id, email: config.UserEmail(authorizationID, serviceID), flow: service.VLESSReality.Flow,
			testSeed: append([]uint32(nil), service.VLESSReality.TestSeed...),
		}, nil
	case config.ServiceTypeShadowsocks:
		password, err := config.DeriveShadowsocksPassword(
			configuration.CredentialSeed, authorizationID, serviceID, service.Shadowsocks.Method,
		)
		if err != nil {
			return runtimeCredential{}, err
		}
		return runtimeCredential{
			serviceType: service.Type, email: config.UserEmail(authorizationID, serviceID),
			password: password, method: service.Shadowsocks.Method, ivCheck: service.Shadowsocks.IVCheck,
		}, nil
	default:
		return runtimeCredential{}, ErrUnsupportedService
	}
}

type runtimeCredential struct {
	serviceType string
	id          string
	email       string
	flow        string
	testSeed    []uint32
	password    string
	method      string
	ivCheck     bool
}

func (manager *Manager) refreshTraffic(ctx context.Context, process *managedProcess) error {
	if process == nil || process.api == nil || len(manager.services) == 0 {
		return nil
	}
	stats, err := process.api.queryStats(ctx)
	if err != nil {
		return err
	}
	byEmail := make(map[string]*serviceState, len(manager.services))
	for _, state := range manager.services {
		byEmail[config.UserEmail(state.authorizationID, state.serviceID)] = state
	}
	for _, stat := range stats {
		state := byEmail[stat.email]
		if state == nil || stat.value < 0 {
			continue
		}
		switch stat.direction {
		case "uplink":
			if err := advanceRawCounter(&state.uploadBase, &state.uploadRaw, uint64(stat.value)); err != nil {
				return err
			}
		case "downlink":
			if err := advanceRawCounter(&state.downloadBase, &state.downloadRaw, uint64(stat.value)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (manager *Manager) rollTrafficForward() error {
	for _, state := range manager.services {
		var err error
		state.uploadBase, err = addCounter(state.uploadBase, state.uploadRaw)
		if err != nil {
			return err
		}
		state.downloadBase, err = addCounter(state.downloadBase, state.downloadRaw)
		if err != nil {
			return err
		}
		state.uploadRaw = 0
		state.downloadRaw = 0
	}
	return nil
}

func advanceRawCounter(base, current *uint64, next uint64) error {
	if next < *current {
		value, err := addCounter(*base, *current)
		if err != nil {
			return err
		}
		*base = value
	}
	*current = next
	return nil
}

func addCounter(first, second uint64) (uint64, error) {
	if first > math.MaxInt64 || second > math.MaxInt64 || first > math.MaxInt64-second {
		return 0, errors.New("Xray traffic counter exceeds the supported range")
	}
	return first + second, nil
}

func apiAddress(configuration config.Configuration) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(configuration.APIPort)))
}

func (api *xrayAPI) addUser(parent context.Context, inboundTag string, credential runtimeCredential) error {
	accountType, account, err := marshalRuntimeAccount(credential)
	if err != nil {
		return err
	}
	operation, err := marshalLegacy(&addUserOperation{User: &protocolUser{
		Email: credential.email, Account: &typedMessage{Type: accountType, Value: account},
	}})
	if err != nil {
		return errors.New("encode Xray user operation")
	}
	request := &alterInboundRequest{
		Tag: inboundTag, Operation: &typedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: operation},
	}
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	if err := api.connection.Invoke(ctx, "/xray.app.proxyman.command.HandlerService/AlterInbound", request, &emptyMessage{}); err != nil {
		return fmt.Errorf("add Xray user: %w", err)
	}
	return nil
}

func marshalRuntimeAccount(credential runtimeCredential) (string, []byte, error) {
	switch credential.serviceType {
	case config.ServiceTypeVLESSReality:
		raw, err := marshalLegacy(&vlessAccount{
			ID: credential.id, Flow: credential.flow, Encryption: "none", TestSeed: credential.testSeed,
		})
		if err != nil {
			return "", nil, errors.New("encode Xray VLESS account")
		}
		return "xray.proxy.vless.Account", raw, nil
	case config.ServiceTypeShadowsocks:
		if config.IsShadowsocks2022(credential.method) {
			raw, err := marshalLegacy(&shadowsocks2022Account{Key: credential.password})
			if err != nil {
				return "", nil, errors.New("encode Xray Shadowsocks 2022 account")
			}
			return "xray.proxy.shadowsocks_2022.Account", raw, nil
		}
		cipherType, exists := config.ShadowsocksCipherType(credential.method)
		if !exists {
			return "", nil, errors.New("unsupported Xray Shadowsocks method")
		}
		raw, err := marshalLegacy(&shadowsocksAccount{
			Password: credential.password, CipherType: cipherType, IVCheck: credential.ivCheck,
		})
		if err != nil {
			return "", nil, errors.New("encode Xray Shadowsocks account")
		}
		return "xray.proxy.shadowsocks.Account", raw, nil
	default:
		return "", nil, ErrUnsupportedService
	}
}

func (api *xrayAPI) removeUser(parent context.Context, inboundTag, email string) error {
	operation, err := marshalLegacy(&removeUserOperation{Email: email})
	if err != nil {
		return errors.New("encode Xray user removal")
	}
	request := &alterInboundRequest{
		Tag: inboundTag, Operation: &typedMessage{Type: "xray.app.proxyman.command.RemoveUserOperation", Value: operation},
	}
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	if err := api.connection.Invoke(ctx, "/xray.app.proxyman.command.HandlerService/AlterInbound", request, &emptyMessage{}); err != nil {
		return errors.New("remove Xray user")
	}
	return nil
}

type trafficStat struct {
	email     string
	direction string
	value     int64
}

func (api *xrayAPI) queryStats(parent context.Context) ([]trafficStat, error) {
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	response := &queryStatsResponse{}
	if err := api.connection.Invoke(ctx, "/xray.app.stats.command.StatsService/QueryStats",
		&queryStatsRequest{Pattern: "user>>>"}, response); err != nil {
		return nil, errors.New("query Xray traffic counters")
	}
	values := make([]trafficStat, 0, len(response.Stats))
	for _, stat := range response.Stats {
		parts := strings.Split(stat.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		values = append(values, trafficStat{email: parts[1], direction: parts[3], value: stat.Value})
	}
	return values, nil
}

func (api *xrayAPI) queryOnlineIPs(parent context.Context, email string) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	response := &getStatsOnlineIPListResponse{}
	err := api.connection.Invoke(ctx, "/xray.app.stats.command.StatsService/GetStatsOnlineIpList",
		&getStatsRequest{Name: "user>>>" + email + ">>>online"}, response)
	if status.Code(err) == codes.NotFound {
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, errors.New("query Xray online IPs")
	}
	values := make(map[string]int64, len(response.IPs))
	for rawIP, lastSeen := range response.IPs {
		ip := net.ParseIP(rawIP)
		if ip == nil || lastSeen <= 0 {
			return nil, errors.New("Xray returned invalid online IP activity")
		}
		values[ip.String()] = lastSeen
	}
	return values, nil
}

func (api *xrayAPI) replaceRoutingRules(parent context.Context, version string, rules []xrayconfig.CompiledRoutingRule) error {
	encoded, err := marshalRoutingRules(version, rules)
	if err != nil {
		return errors.New("encode Xray routing rules")
	}
	request := &addRuleRequest{
		Config: &typedMessage{Type: "xray.app.router.Config", Value: encoded}, ShouldAppend: false,
	}
	ctx, cancel := context.WithTimeout(parent, xrayAPITimeout)
	defer cancel()
	if err := api.connection.Invoke(ctx, "/xray.app.router.command.RoutingService/AddRule", request, &emptyMessage{}); err != nil {
		return errors.New("replace Xray routing rules")
	}
	return nil
}

func marshalRoutingRules(version string, rules []xrayconfig.CompiledRoutingRule) ([]byte, error) {
	if usesGeodataRoutingRules(version) {
		values := make([]*geodataRoutingRule, len(rules))
		for index, rule := range rules {
			values[index] = newGeodataRoutingRule(rule)
		}
		return marshalLegacy(&geodataRouterConfig{Rules: values})
	}
	values := make([]*routingRule, len(rules))
	for index, rule := range rules {
		values[index] = newLegacyRoutingRule(rule)
	}
	return marshalLegacy(&routerConfig{Rules: values})
}

func usesGeodataRoutingRules(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	values := [3]int{}
	for index, part := range parts {
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		values[index] = parsed
	}
	cutoff := [3]int{26, 7, 11}
	for index := range values {
		if values[index] != cutoff[index] {
			return values[index] > cutoff[index]
		}
	}
	return true
}

func newLegacyRoutingRule(rule xrayconfig.CompiledRoutingRule) *routingRule {
	value := &routingRule{
		Tag: rule.OutboundTag, RuleTag: rule.RuleTag,
		UserEmail: append([]string(nil), rule.UserEmails...), InboundTag: append([]string(nil), rule.InboundTags...),
		Protocol: append([]string(nil), rule.Protocols...),
	}
	for _, domain := range rule.Domains {
		value.Domain = append(value.Domain, &routingDomain{Type: 2, Value: domain})
	}
	value.GeoIP = legacyGeoIPs(rule.DestinationCIDRs)
	value.SourceGeoIP = legacyGeoIPs(rule.SourceCIDRs)
	return value
}

func newGeodataRoutingRule(rule xrayconfig.CompiledRoutingRule) *geodataRoutingRule {
	value := &geodataRoutingRule{
		Tag: rule.OutboundTag, RuleTag: rule.RuleTag,
		UserEmail: append([]string(nil), rule.UserEmails...), InboundTag: append([]string(nil), rule.InboundTags...),
		Protocol: append([]string(nil), rule.Protocols...),
	}
	for _, domain := range rule.Domains {
		value.Domain = append(value.Domain, &domainRule{Custom: &routingDomain{Type: 2, Value: domain}})
	}
	value.IP = geodataIPRules(rule.DestinationCIDRs)
	value.SourceIP = geodataIPRules(rule.SourceCIDRs)
	return value
}

func legacyGeoIPs(prefixes []netip.Prefix) []*geoIP {
	if len(prefixes) == 0 {
		return nil
	}
	value := &geoIP{CIDR: make([]*cidr, len(prefixes))}
	for index, prefix := range prefixes {
		value.CIDR[index] = routingCIDR(prefix)
	}
	return []*geoIP{value}
}

func geodataIPRules(prefixes []netip.Prefix) []*ipRule {
	values := make([]*ipRule, len(prefixes))
	for index, prefix := range prefixes {
		values[index] = &ipRule{Custom: &cidrRule{CIDR: routingCIDR(prefix)}}
	}
	return values
}

func routingCIDR(prefix netip.Prefix) *cidr {
	return &cidr{IP: append([]byte(nil), prefix.Addr().AsSlice()...), Prefix: uint32(prefix.Bits())}
}

func marshalLegacy(message protoadapt.MessageV1) ([]byte, error) {
	return proto.Marshal(protoadapt.MessageV2Of(message))
}

type typedMessage struct {
	Type  string `protobuf:"bytes,1,opt,name=type,proto3"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3"`
}

type protocolUser struct {
	Level   uint32        `protobuf:"varint,1,opt,name=level,proto3"`
	Email   string        `protobuf:"bytes,2,opt,name=email,proto3"`
	Account *typedMessage `protobuf:"bytes,3,opt,name=account,proto3"`
}

type vlessAccount struct {
	ID         string   `protobuf:"bytes,1,opt,name=id,proto3"`
	Flow       string   `protobuf:"bytes,2,opt,name=flow,proto3"`
	Encryption string   `protobuf:"bytes,3,opt,name=encryption,proto3"`
	TestSeed   []uint32 `protobuf:"varint,9,rep,packed,name=testseed,proto3"`
}

type shadowsocksAccount struct {
	Password   string `protobuf:"bytes,1,opt,name=password,proto3"`
	CipherType int32  `protobuf:"varint,2,opt,name=cipher_type,json=cipherType,proto3"`
	IVCheck    bool   `protobuf:"varint,3,opt,name=iv_check,json=ivCheck,proto3"`
}

type shadowsocks2022Account struct {
	Key string `protobuf:"bytes,1,opt,name=key,proto3"`
}

type addUserOperation struct {
	User *protocolUser `protobuf:"bytes,1,opt,name=user,proto3"`
}

type removeUserOperation struct {
	Email string `protobuf:"bytes,1,opt,name=email,proto3"`
}

type alterInboundRequest struct {
	Tag       string        `protobuf:"bytes,1,opt,name=tag,proto3"`
	Operation *typedMessage `protobuf:"bytes,2,opt,name=operation,proto3"`
}

type queryStatsRequest struct {
	Pattern string `protobuf:"bytes,1,opt,name=pattern,proto3"`
	Reset_  bool   `protobuf:"varint,2,opt,name=reset,proto3"`
}

type queryStatsResponse struct {
	Stats []*statMessage `protobuf:"bytes,1,rep,name=stat,proto3"`
}

type statMessage struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3"`
}

type getStatsRequest struct {
	Name   string `protobuf:"bytes,1,opt,name=name,proto3"`
	Reset_ bool   `protobuf:"varint,2,opt,name=reset,proto3"`
}

type getStatsOnlineIPListResponse struct {
	Name string           `protobuf:"bytes,1,opt,name=name,proto3"`
	IPs  map[string]int64 `protobuf:"bytes,2,rep,name=ips,proto3" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

type routerConfig struct {
	Rules []*routingRule `protobuf:"bytes,2,rep,name=rule,proto3"`
}

type routingRule struct {
	Tag         string           `protobuf:"bytes,1,opt,name=tag,proto3"`
	Domain      []*routingDomain `protobuf:"bytes,2,rep,name=domain,proto3"`
	UserEmail   []string         `protobuf:"bytes,7,rep,name=user_email,json=userEmail,proto3"`
	InboundTag  []string         `protobuf:"bytes,8,rep,name=inbound_tag,json=inboundTag,proto3"`
	Protocol    []string         `protobuf:"bytes,9,rep,name=protocol,proto3"`
	GeoIP       []*geoIP         `protobuf:"bytes,10,rep,name=geoip,proto3"`
	SourceGeoIP []*geoIP         `protobuf:"bytes,11,rep,name=source_geoip,json=sourceGeoip,proto3"`
	RuleTag     string           `protobuf:"bytes,19,opt,name=rule_tag,json=ruleTag,proto3"`
}

type geodataRouterConfig struct {
	Rules []*geodataRoutingRule `protobuf:"bytes,2,rep,name=rule,proto3"`
}

type geodataRoutingRule struct {
	Tag        string        `protobuf:"bytes,1,opt,name=tag,proto3"`
	Domain     []*domainRule `protobuf:"bytes,2,rep,name=domain,proto3"`
	UserEmail  []string      `protobuf:"bytes,7,rep,name=user_email,json=userEmail,proto3"`
	InboundTag []string      `protobuf:"bytes,8,rep,name=inbound_tag,json=inboundTag,proto3"`
	Protocol   []string      `protobuf:"bytes,9,rep,name=protocol,proto3"`
	IP         []*ipRule     `protobuf:"bytes,10,rep,name=ip,proto3"`
	SourceIP   []*ipRule     `protobuf:"bytes,11,rep,name=source_ip,json=sourceIp,proto3"`
	RuleTag    string        `protobuf:"bytes,19,opt,name=rule_tag,json=ruleTag,proto3"`
}

type routingDomain struct {
	Type  int32  `protobuf:"varint,1,opt,name=type,proto3"`
	Value string `protobuf:"bytes,2,opt,name=value,proto3"`
}

type domainRule struct {
	Custom *routingDomain `protobuf:"bytes,2,opt,name=custom,proto3"`
}

type ipRule struct {
	Custom *cidrRule `protobuf:"bytes,2,opt,name=custom,proto3"`
}

type cidrRule struct {
	CIDR *cidr `protobuf:"bytes,1,opt,name=cidr,proto3"`
}

type geoIP struct {
	CountryCode string  `protobuf:"bytes,1,opt,name=country_code,json=countryCode,proto3"`
	CIDR        []*cidr `protobuf:"bytes,2,rep,name=cidr,proto3"`
	Reverse     bool    `protobuf:"varint,3,opt,name=reverse_match,json=reverseMatch,proto3"`
}

type cidr struct {
	IP     []byte `protobuf:"bytes,1,opt,name=ip,proto3"`
	Prefix uint32 `protobuf:"varint,2,opt,name=prefix,proto3"`
}

type addRuleRequest struct {
	Config       *typedMessage `protobuf:"bytes,1,opt,name=config,proto3"`
	ShouldAppend bool          `protobuf:"varint,2,opt,name=shouldAppend,proto3"`
}

type emptyMessage struct{}

func (value *typedMessage) Reset()             { *value = typedMessage{} }
func (*typedMessage) String() string           { return "" }
func (*typedMessage) ProtoMessage()            {}
func (value *protocolUser) Reset()             { *value = protocolUser{} }
func (*protocolUser) String() string           { return "" }
func (*protocolUser) ProtoMessage()            {}
func (value *vlessAccount) Reset()             { *value = vlessAccount{} }
func (*vlessAccount) String() string           { return "" }
func (*vlessAccount) ProtoMessage()            {}
func (value *shadowsocksAccount) Reset()       { *value = shadowsocksAccount{} }
func (*shadowsocksAccount) String() string     { return "" }
func (*shadowsocksAccount) ProtoMessage()      {}
func (value *shadowsocks2022Account) Reset()   { *value = shadowsocks2022Account{} }
func (*shadowsocks2022Account) String() string { return "" }
func (*shadowsocks2022Account) ProtoMessage()  {}
func (value *addUserOperation) Reset()         { *value = addUserOperation{} }
func (*addUserOperation) String() string       { return "" }
func (*addUserOperation) ProtoMessage()        {}
func (value *removeUserOperation) Reset()      { *value = removeUserOperation{} }
func (*removeUserOperation) String() string    { return "" }
func (*removeUserOperation) ProtoMessage()     {}
func (value *alterInboundRequest) Reset()      { *value = alterInboundRequest{} }
func (*alterInboundRequest) String() string    { return "" }
func (*alterInboundRequest) ProtoMessage()     {}
func (value *queryStatsRequest) Reset()        { *value = queryStatsRequest{} }
func (*queryStatsRequest) String() string      { return "" }
func (*queryStatsRequest) ProtoMessage()       {}
func (value *queryStatsResponse) Reset()       { *value = queryStatsResponse{} }
func (*queryStatsResponse) String() string     { return "" }
func (*queryStatsResponse) ProtoMessage()      {}
func (value *statMessage) Reset()              { *value = statMessage{} }
func (*statMessage) String() string            { return "" }
func (*statMessage) ProtoMessage()             {}
func (value *getStatsRequest) Reset()          { *value = getStatsRequest{} }
func (*getStatsRequest) String() string        { return "" }
func (*getStatsRequest) ProtoMessage()         {}
func (value *getStatsOnlineIPListResponse) Reset() {
	*value = getStatsOnlineIPListResponse{}
}
func (*getStatsOnlineIPListResponse) String() string { return "" }
func (*getStatsOnlineIPListResponse) ProtoMessage()  {}
func (value *routerConfig) Reset()                   { *value = routerConfig{} }
func (*routerConfig) String() string                 { return "" }
func (*routerConfig) ProtoMessage()                  {}
func (value *geodataRouterConfig) Reset()            { *value = geodataRouterConfig{} }
func (*geodataRouterConfig) String() string          { return "" }
func (*geodataRouterConfig) ProtoMessage()           {}
func (value *routingRule) Reset()                    { *value = routingRule{} }
func (*routingRule) String() string                  { return "" }
func (*routingRule) ProtoMessage()                   {}
func (value *geodataRoutingRule) Reset()             { *value = geodataRoutingRule{} }
func (*geodataRoutingRule) String() string           { return "" }
func (*geodataRoutingRule) ProtoMessage()            {}
func (value *routingDomain) Reset()                  { *value = routingDomain{} }
func (*routingDomain) String() string                { return "" }
func (*routingDomain) ProtoMessage()                 {}
func (value *domainRule) Reset()                     { *value = domainRule{} }
func (*domainRule) String() string                   { return "" }
func (*domainRule) ProtoMessage()                    {}
func (value *ipRule) Reset()                         { *value = ipRule{} }
func (*ipRule) String() string                       { return "" }
func (*ipRule) ProtoMessage()                        {}
func (value *cidrRule) Reset()                       { *value = cidrRule{} }
func (*cidrRule) String() string                     { return "" }
func (*cidrRule) ProtoMessage()                      {}
func (value *geoIP) Reset()                          { *value = geoIP{} }
func (*geoIP) String() string                        { return "" }
func (*geoIP) ProtoMessage()                         {}
func (value *cidr) Reset()                           { *value = cidr{} }
func (*cidr) String() string                         { return "" }
func (*cidr) ProtoMessage()                          {}
func (value *addRuleRequest) Reset()                 { *value = addRuleRequest{} }
func (*addRuleRequest) String() string               { return "" }
func (*addRuleRequest) ProtoMessage()                {}
func (value *emptyMessage) Reset()                   { *value = emptyMessage{} }
func (*emptyMessage) String() string                 { return "" }
func (*emptyMessage) ProtoMessage()                  {}

func serviceKey(authorizationID, serviceID string) string {
	return authorizationID + "\x00" + serviceID
}
