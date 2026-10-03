package xrayruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayconfig"
)

const accessLogLimit = 16 << 20
const accessDiskLimit = 64 << 20

var accessPattern = regexp.MustCompile(`from (?:(tcp|udp):)?([^ ]+) (accepted|rejected) (tcp|udp):([^ ]+).* email: relayward:([0-9a-f-]{36}):([a-z0-9._-]+)\s*$`)
var blockedAccessPattern = regexp.MustCompile(`\[(?:[^\]]+ (?:->|>>|==>) )?` + regexp.QuoteMeta(xrayconfig.BlockedOutboundTag) + `\]`)

func (manager *Manager) render(configuration config.Configuration) ([]byte, error) {
	raw, err := xrayconfig.Render(configuration)
	if err != nil {
		return nil, err
	}
	if configuration.DisableAccessLog {
		return raw, nil
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	dir := filepath.Join(manager.dataDirectory, "xray", "access")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	value["log"].(map[string]any)["access"] = filepath.Join(dir, "current.log")
	return json.Marshal(value)
}

func parseAccess(line string, configuration config.Configuration) (ActivityEvent, bool, error) {
	matches := accessPattern.FindStringSubmatch(line)
	if matches == nil {
		if strings.Contains(line, "email: relayward:") {
			return ActivityEvent{}, false, errors.New("unrecognized managed access record")
		}
		return ActivityEvent{}, false, nil
	}
	service, ok := configuration.FindService(matches[7])
	if !ok || !service.Enabled {
		return ActivityEvent{}, false, nil
	}
	source, _, err := net.SplitHostPort(matches[2])
	if err != nil {
		return ActivityEvent{}, false, errors.New("invalid access source")
	}
	destination, port, err := net.SplitHostPort(matches[5])
	if err != nil {
		return ActivityEvent{}, false, errors.New("invalid access target")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return ActivityEvent{}, false, errors.New("invalid access port")
	}
	action := agentv1.AccessActionAccepted
	if matches[3] == "rejected" || blockedAccessPattern.MatchString(line) {
		action = agentv1.AccessActionBlocked
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ActivityEvent{}, false, errors.New("access timestamp missing")
	}
	observed, err := time.ParseInLocation("2006/01/02 15:04:05.999999999", fields[0]+" "+fields[1], time.Local)
	if err != nil {
		return ActivityEvent{}, false, errors.New("invalid access timestamp")
	}
	event := ActivityEvent{ObservedAt: observed.UnixNano(), AuthorizationID: matches[6], ServiceID: matches[7], SourceIP: source, Destination: strings.ToLower(strings.TrimSuffix(destination, ".")), DestinationPort: uint32(number), Network: matches[4], Action: action, ObservationKind: agentv1.ObservationConnection}
	standard := agentv1.AccessEvent{SourceStreamID: "00000000000000000000000000000000", SourceEventID: "access-validation", PluginID: "io.github.qqqasdwx.relayward-xray", ServiceID: event.ServiceID, AuthorizationID: event.AuthorizationID, SourceIP: event.SourceIP, Destination: event.Destination, DestinationPort: event.DestinationPort, Network: event.Network, Action: event.Action, ObservationKind: event.ObservationKind}
	if err := agentv1.ValidateAccessEvent(standard); err != nil {
		return ActivityEvent{}, false, errors.New("invalid managed access record")
	}
	return event, true, nil
}

func (manager *Manager) collectAccess(ctx context.Context, process *managedProcess, configuration config.Configuration) error {
	dir := filepath.Join(manager.dataDirectory, "xray", "access")
	if err := manager.boundAccessLogs(dir); err != nil {
		return err
	}
	current := filepath.Join(dir, "current.log")
	info, err := os.Stat(current)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) || info.Size() >= accessLogLimit {
		if err == nil {
			if err = os.Rename(current, filepath.Join(dir, fmt.Sprintf("rotated-%020d.log", time.Now().UnixNano()))); err != nil {
				return err
			}
		}
		logger, ok := process.api.(interface{ restartLogger(context.Context) error })
		if !ok {
			return errors.New("runtime does not support access log rotation")
		}
		if err = logger.restartLogger(ctx); err != nil {
			return errors.New("reopen Xray access log failed")
		}
		if _, err = os.Stat(current); err != nil {
			return errors.New("Xray access log is unavailable after reopening")
		}
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil {
		return err
	}
	store := manager.telemetry
	store.mu.Lock()
	defer store.mu.Unlock()
	state := cloneTelemetryState(store.state)
	state.CollectionBacklog = false
	// Drain rotated files before the active writer; evictions are visible as a gap.
	sort.Slice(paths, func(i, j int) bool {
		if paths[i] == current {
			return false
		}
		if paths[j] == current {
			return true
		}
		return paths[i] < paths[j]
	})
	// A queued event and its file offset are committed in the same atomic state file.
	for _, path := range paths {
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		key := fmt.Sprint(info.Sys().(*syscall.Stat_t).Ino)
		offset := state.LogOffsets[key]
		if offset > info.Size() {
			state.CollectionGapAt = time.Now().UnixNano()
			offset = 0
		}
		if _, err = file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			return err
		}
		reader := bufio.NewReaderSize(file, 65536)
		for len(state.Events) < maximumQueuedActivity-64 {
			if err := ctx.Err(); err != nil {
				file.Close()
				return err
			}
			line, size, oversized, err := readAccessLine(reader)
			if err == io.EOF {
				if size > 0 && path != current {
					state.CollectionGapAt = time.Now().UnixNano()
					offset += size
					state.LogOffsets[key] = offset
				}
				break
			}
			if err != nil {
				file.Close()
				return err
			}
			offset += size
			state.LogOffsets[key] = offset
			if oversized {
				state.CollectionGapAt = time.Now().UnixNano()
				continue
			}
			event, valid, parseErr := parseAccess(line, configuration)
			if parseErr != nil {
				state.CollectionGapAt = time.Now().UnixNano()
				continue
			}
			if !valid {
				continue
			}
			state.LastSequence++
			event.Sequence = state.LastSequence
			event.EventID = fmt.Sprintf("access-%d", event.Sequence)
			state.Events = append(state.Events, event)
		}
		file.Close()
		if offset < info.Size() {
			state.CollectionBacklog = true
		}
		if err = store.persist(state); err != nil {
			return err
		}
		store.state = state
		if path != current && offset == info.Size() {
			if err = os.Remove(path); err != nil {
				return err
			}
			delete(state.LogOffsets, key)
			if err = store.persist(state); err != nil {
				return err
			}
			store.state = state
		}
	}
	return nil
}

// Truncate rather than unlink over-budget files: a failed logger restart may
// leave Xray writing the rotated inode. Truncation also bounds that open writer.
func (manager *Manager) boundAccessLogs(dir string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil {
		return err
	}
	var total int64
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		total += info.Size()
	}
	if total <= accessDiskLimit {
		return nil
	}
	current := filepath.Join(dir, "current.log")
	sort.Slice(paths, func(i, j int) bool {
		if paths[i] == current {
			return false
		}
		if paths[j] == current {
			return true
		}
		return paths[i] < paths[j]
	})
	manager.telemetry.mu.Lock()
	defer manager.telemetry.mu.Unlock()
	state := cloneTelemetryState(manager.telemetry.state)
	for _, path := range paths {
		if total <= accessDiskLimit {
			break
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		state.CollectionGapAt = time.Now().UnixNano()
		state.LogOffsets[fmt.Sprint(info.Sys().(*syscall.Stat_t).Ino)] = 0
		if err = manager.telemetry.persist(state); err != nil {
			return err
		}
		manager.telemetry.state = state
		if err = os.Truncate(path, 0); err != nil {
			return err
		}
		total -= info.Size()
	}
	return nil
}

func readAccessLine(reader *bufio.Reader) (line string, size int64, oversized bool, err error) {
	for {
		part, readErr := reader.ReadSlice('\n')
		size += int64(len(part))
		if size <= 65536 {
			line += string(part)
		} else {
			oversized = true
			line = ""
		}
		if readErr == bufio.ErrBufferFull {
			continue
		}
		return line, size, oversized, readErr
	}
}

func (api *xrayAPI) restartLogger(ctx context.Context) error {
	return api.connection.Invoke(ctx, "/xray.app.log.command.LoggerService/RestartLogger", &emptyMessage{}, &emptyMessage{})
}

func (store *telemetryStore) collectionGap() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state.CollectionBacklog || store.state.CollectionGapAt > time.Now().Add(-24*time.Hour).UnixNano()
}
