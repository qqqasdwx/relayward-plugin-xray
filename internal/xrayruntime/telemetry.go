package xrayruntime

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const (
	telemetryStateVersion    = 1
	maximumTelemetryFileSize = 16 << 20
	maximumQueuedActivity    = 4096
	activityRefreshInterval  = 30 * time.Second
)

var (
	ErrTelemetryDataLoss = errors.New("telemetry cursor points to deleted activity")
	ErrTelemetryCursor   = errors.New("telemetry cursor is ahead of available activity")
	ErrTelemetryFull     = errors.New("telemetry activity queue is full")
)

type ActivitySource struct {
	AuthorizationID string
	ServiceID       string
	SourceIP        string
}

type ActivityEvent struct {
	Sequence        uint64 `json:"sequence"`
	EventID         string `json:"event_id"`
	ObservedAt      int64  `json:"observed_at_unix_nano"`
	AuthorizationID string `json:"authorization_id"`
	ServiceID       string `json:"service_id"`
	SourceIP        string `json:"source_ip"`
	Destination     string `json:"destination,omitempty"`
	DestinationPort uint32 `json:"destination_port,omitempty"`
	Network         string `json:"network,omitempty"`
	Action          string `json:"action,omitempty"`
	ObservationKind string `json:"observation_kind,omitempty"`
}

type ActivityPage struct {
	Events           []ActivityEvent
	NextSequence     uint64
	HasMore          bool
	CollectionStatus string
}

type telemetryState struct {
	Version              int              `json:"version"`
	StreamID             string           `json:"stream_id"`
	AcknowledgedSequence uint64           `json:"acknowledged_sequence"`
	LastSequence         uint64           `json:"last_sequence"`
	Events               []ActivityEvent  `json:"events"`
	LastReported         map[string]int64 `json:"last_reported"`
	LogOffsets           map[string]int64 `json:"log_offsets,omitempty"`
	CollectionGapAt      int64            `json:"collection_gap_at,omitempty"`
	CollectionBacklog    bool             `json:"collection_backlog,omitempty"`
}

type telemetryStore struct {
	mu        sync.Mutex
	directory string
	path      string
	state     telemetryState
}

func openTelemetryStore(dataDirectory string) (*telemetryStore, error) {
	directory := filepath.Join(dataDirectory, "xray", "telemetry")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create telemetry state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect telemetry state directory: %w", err)
	}
	store := &telemetryStore{directory: directory, path: filepath.Join(directory, "state.json")}
	if err := store.loadOrCreate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *telemetryStore) streamID() string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.StreamID
}

func (store *telemetryStore) appendSnapshot(after uint64, maximum uint32, active map[string]ActivitySource, now time.Time) (ActivityPage, error) {
	if maximum == 0 || now.IsZero() {
		return ActivityPage{}, errors.New("telemetry page size and observation time are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current := cloneTelemetryState(store.state)
	if after < current.AcknowledgedSequence {
		return ActivityPage{}, ErrTelemetryDataLoss
	}
	if after > current.LastSequence {
		return ActivityPage{}, ErrTelemetryCursor
	}
	changed := false
	if after > current.AcknowledgedSequence {
		remove := int(after - current.AcknowledgedSequence)
		current.Events = append([]ActivityEvent(nil), current.Events[remove:]...)
		current.AcknowledgedSequence = after
		changed = true
	}
	keys := make([]string, 0, len(active))
	for key := range active {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	nextReported := make(map[string]int64, len(active))
	for _, key := range keys {
		source := active[key]
		lastReported := current.LastReported[key]
		if lastReported != 0 && now.UnixNano()-lastReported < activityRefreshInterval.Nanoseconds() {
			nextReported[key] = lastReported
			continue
		}
		if len(current.Events) >= maximumQueuedActivity {
			if len(store.state.Events) == 0 && after == 0 {
				return ActivityPage{}, ErrTelemetryFull
			}
			if lastReported != 0 {
				nextReported[key] = lastReported
			}
			continue
		}
		if current.LastSequence >= math.MaxInt64 {
			return ActivityPage{}, ErrTelemetryFull
		}
		current.LastSequence++
		current.Events = append(current.Events, ActivityEvent{
			Sequence: current.LastSequence, EventID: fmt.Sprintf("online-%d", current.LastSequence),
			ObservedAt: now.UTC().UnixNano(), AuthorizationID: source.AuthorizationID,
			ServiceID: source.ServiceID, SourceIP: source.SourceIP, ObservationKind: agentv1.ObservationActivity,
		})
		nextReported[key] = now.UTC().UnixNano()
		changed = true
	}
	if len(nextReported) != len(current.LastReported) {
		changed = true
	}
	current.LastReported = nextReported
	if changed {
		if err := store.persist(current); err != nil {
			return ActivityPage{}, err
		}
		store.state = current
	}
	count := len(current.Events)
	if count > int(maximum) {
		count = int(maximum)
	}
	events := append([]ActivityEvent(nil), current.Events[:count]...)
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].Sequence
	}
	return ActivityPage{Events: events, NextSequence: next, HasMore: count < len(current.Events)}, nil
}

func (store *telemetryStore) loadOrCreate() error {
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		streamID, generationErr := newTelemetryStreamID()
		if generationErr != nil {
			return generationErr
		}
		state := telemetryState{
			Version: telemetryStateVersion, StreamID: streamID,
			Events: []ActivityEvent{}, LastReported: map[string]int64{},
		}
		if err := store.persist(state); err != nil {
			return err
		}
		store.state = state
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect telemetry state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() > maximumTelemetryFileSize {
		return errors.New("telemetry state is not a private regular file")
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		return fmt.Errorf("read telemetry state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state telemetryState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode telemetry state: %w", err)
	}
	if err := requireTelemetryEOF(decoder); err != nil {
		return err
	}
	if err := validateTelemetryState(state); err != nil {
		return err
	}
	store.state = state
	return nil
}

func (store *telemetryStore) persist(state telemetryState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode telemetry state: %w", err)
	}
	if len(raw) > maximumTelemetryFileSize {
		return ErrTelemetryFull
	}
	file, err := os.CreateTemp(store.directory, ".state-*.json")
	if err != nil {
		return fmt.Errorf("create temporary telemetry state: %w", err)
	}
	temporaryPath := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary telemetry state: %w", err)
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("write telemetry state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync telemetry state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close telemetry state: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("commit telemetry state: %w", err)
	}
	remove = false
	return syncTelemetryDirectory(store.directory)
}

func validateTelemetryState(state telemetryState) error {
	stream, err := hex.DecodeString(state.StreamID)
	if state.Version != telemetryStateVersion || err != nil || len(stream) != 16 || state.LastSequence > math.MaxInt64 ||
		state.AcknowledgedSequence > state.LastSequence || len(state.Events) > maximumQueuedActivity {
		return errors.New("invalid telemetry state metadata")
	}
	if uint64(len(state.Events)) != state.LastSequence-state.AcknowledgedSequence {
		return errors.New("telemetry state contains a sequence gap")
	}
	for index, event := range state.Events {
		if event.ObservationKind != "" && event.ObservationKind != agentv1.ObservationActivity && event.ObservationKind != agentv1.ObservationConnection {
			return errors.New("invalid stored observation kind")
		}
		expected := state.AcknowledgedSequence + uint64(index) + 1
		if event.Sequence != expected || (event.EventID != fmt.Sprintf("online-%d", expected) && event.EventID != fmt.Sprintf("access-%d", expected)) || event.ObservedAt <= 0 ||
			event.AuthorizationID == "" || event.ServiceID == "" || !canonicalIP(event.SourceIP) {
			return errors.New("telemetry state contains an invalid activity event")
		}
		if event.ObservationKind == agentv1.ObservationConnection {
			if err := agentv1.ValidateAccessEvent(agentv1.AccessEvent{SourceStreamID: state.StreamID, SourceEventID: event.EventID, PluginID: "io.github.qqqasdwx.relayward-xray", ServiceID: event.ServiceID, AuthorizationID: event.AuthorizationID, SourceIP: event.SourceIP, Destination: event.Destination, DestinationPort: event.DestinationPort, Network: event.Network, Action: event.Action, ObservationKind: event.ObservationKind}); err != nil {
				return errors.New("invalid stored connection observation")
			}
		}
	}
	if state.LastReported == nil {
		return errors.New("telemetry state activity index is missing")
	}
	for key, observedAt := range state.LastReported {
		parts := strings.Split(key, "\x00")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !canonicalIP(parts[2]) || observedAt <= 0 {
			return errors.New("telemetry state contains an invalid activity index")
		}
	}
	return nil
}

func cloneTelemetryState(value telemetryState) telemetryState {
	result := value
	result.Events = append([]ActivityEvent(nil), value.Events...)
	result.LastReported = make(map[string]int64, len(value.LastReported))
	result.LogOffsets = make(map[string]int64, len(value.LogOffsets))
	for key, offset := range value.LogOffsets {
		result.LogOffsets[key] = offset
	}
	for key, observedAt := range value.LastReported {
		result.LastReported[key] = observedAt
	}
	return result
}

func newTelemetryStreamID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate telemetry stream ID: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func canonicalIP(value string) bool {
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.String() == value
}

func requireTelemetryEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("telemetry state contains a trailing JSON value")
		}
		return fmt.Errorf("decode trailing telemetry state: %w", err)
	}
	return nil
}

func syncTelemetryDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open telemetry state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync telemetry state directory: %w", err)
	}
	return nil
}
