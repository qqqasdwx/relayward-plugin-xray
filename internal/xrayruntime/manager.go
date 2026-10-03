// Package xrayruntime validates configuration and supervises the Xray child process.
package xrayruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayrelease"
)

const (
	configurationTestTimeout = 10 * time.Second
	defaultStartupGrace      = 750 * time.Millisecond
	processStopTimeout       = 5 * time.Second
	processRestartTimeout    = 15 * time.Second
	defaultRestartDelay      = time.Second
	maximumRestartDelay      = 30 * time.Second
)

var ErrConfigurationRejected = errors.New("Xray rejected the configuration")

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Installer interface {
	Ensure(context.Context, string) (xrayrelease.Installation, error)
}

type Status struct {
	Generation          uint64
	ConfigurationSHA256 string
	Healthy             bool
	Message             string
	Listeners           []ListenerStatus
}

type Manager struct {
	dataDirectory string
	installer     Installer
	startupGrace  time.Duration
	connectAPI    func(context.Context, config.Configuration) (runtimeAPI, error)
	inspect       func(config.Configuration) []ListenerStatus
	probe         func(context.Context, string) (EgressProbe, error)
	interfaces    func() ([]net.Interface, error)
	addresses     func(net.Interface) ([]net.Addr, error)
	lifecycle     context.Context
	cancel        context.CancelFunc
	restartDelay  time.Duration

	operation             sync.Mutex
	state                 sync.Mutex
	process               *managedProcess
	running               *runtimeSpec
	restartMessage        string
	generation            uint64
	digest                string
	epoch                 string
	services              map[string]*serviceState
	telemetry             *telemetryStore
	blocks                []DynamicBlock
	blockPolicyGeneration uint64
	blockRevision         uint64
}

type runtimeSpec struct {
	installation  xrayrelease.Installation
	configPath    string
	configuration config.Configuration
}

type serviceState struct {
	authorizationID  string
	serviceID        string
	enabled          bool
	policyGeneration uint64
	stateRevision    uint64
	uploadBase       uint64
	downloadBase     uint64
	uploadRaw        uint64
	downloadRaw      uint64
}

type managedProcess struct {
	command   *exec.Cmd
	api       runtimeAPI
	done      chan struct{}
	waitError error
}

func NewManager(dataDirectory string, installer Installer) (*Manager, error) {
	telemetry, err := openTelemetryStore(dataDirectory)
	if err != nil {
		return nil, err
	}
	lifecycle, cancel := context.WithCancel(context.Background())
	return &Manager{
		dataDirectory: dataDirectory,
		installer:     installer,
		startupGrace:  defaultStartupGrace,
		lifecycle:     lifecycle,
		cancel:        cancel,
		restartDelay:  defaultRestartDelay,
		connectAPI: func(ctx context.Context, configuration config.Configuration) (runtimeAPI, error) {
			return connectXrayAPI(ctx, configuration)
		},
		inspect:    inspectListeners,
		probe:      probeCloudflareTrace,
		interfaces: net.Interfaces,
		addresses: func(networkInterface net.Interface) ([]net.Addr, error) {
			return networkInterface.Addrs()
		},
		services:  make(map[string]*serviceState),
		telemetry: telemetry,
	}, nil
}

func (manager *Manager) Validate(ctx context.Context, configuration config.Configuration) error {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	installation, err := manager.installer.Ensure(ctx, configuration.XrayVersion)
	if err != nil {
		return err
	}
	raw, err := manager.render(configuration)
	if err != nil {
		return err
	}
	configPath, cleanup, err := manager.writeTemporaryConfiguration(raw)
	if err != nil {
		return err
	}
	defer cleanup()
	return testConfiguration(ctx, manager.dataDirectory, installation, configPath)
}

func (manager *Manager) Apply(ctx context.Context, generation uint64, digest string, configuration config.Configuration) error {
	manager.operation.Lock()
	defer manager.operation.Unlock()
	if !sha256Pattern.MatchString(digest) {
		return errors.New("invalid Xray configuration digest")
	}
	candidateEpoch := manager.epoch
	if candidateEpoch == "" {
		var err error
		candidateEpoch, err = newCounterEpoch()
		if err != nil {
			return err
		}
	}
	installation, err := manager.installer.Ensure(ctx, configuration.XrayVersion)
	if err != nil {
		return err
	}
	raw, err := manager.render(configuration)
	if err != nil {
		return err
	}
	configPath, cleanup, err := manager.writeTemporaryConfiguration(raw)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := testConfiguration(ctx, manager.dataDirectory, installation, configPath); err != nil {
		return err
	}
	stablePath, err := manager.commitConfiguration(configPath)
	if err != nil {
		return err
	}
	candidate := &runtimeSpec{installation: installation, configPath: stablePath, configuration: configuration}

	manager.state.Lock()
	previousProcess := manager.process
	previousSpec := manager.running
	manager.state.Unlock()
	if previousProcess != nil {
		if err := manager.refreshTraffic(ctx, previousProcess); err != nil {
			return fmt.Errorf("collect final Xray traffic before restart: %w", err)
		}
		if err := manager.rollTrafficForward(); err != nil {
			return err
		}
		stopContext, cancel := context.WithTimeout(ctx, processStopTimeout)
		err := previousProcess.stop(stopContext)
		cancel()
		if err != nil {
			return fmt.Errorf("stop current Xray process: %w", err)
		}
	}
	candidateProcess, err := manager.startConfigured(ctx, candidate)
	if err != nil {
		restored := manager.restore(previousSpec)
		manager.state.Lock()
		manager.process = restored
		manager.running = previousSpec
		manager.restartMessage = ""
		manager.state.Unlock()
		if restored != nil {
			manager.watchProcess(restored, previousSpec)
		}
		if previousSpec != nil && restored == nil {
			return errors.New("candidate Xray failed to start and the previous process could not be restored")
		}
		if previousSpec == nil {
			return errors.New("candidate Xray failed to start")
		}
		return errors.New("candidate Xray failed to start; the previous process was restored")
	}
	manager.state.Lock()
	manager.process = candidateProcess
	manager.running = candidate
	manager.generation = generation
	manager.digest = digest
	manager.restartMessage = ""
	manager.state.Unlock()
	manager.watchProcess(candidateProcess, candidate)
	manager.epoch = candidateEpoch
	manager.reconcileConfiguredServices(configuration)
	return nil
}

func (manager *Manager) reconcileConfiguredServices(configuration config.Configuration) {
	for _, state := range manager.services {
		service, exists := configuration.FindService(state.serviceID)
		if exists && service.Enabled {
			continue
		}
		state.enabled = false
		state.policyGeneration = 0
		state.stateRevision = 0
	}
	blocks := manager.blocks[:0]
	for _, block := range manager.blocks {
		service, exists := configuration.FindService(block.ServiceID)
		if exists && service.Enabled {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) != len(manager.blocks) {
		manager.blocks = blocks
		manager.blockPolicyGeneration = 0
		manager.blockRevision = 0
	}
}

func (manager *Manager) GetStatus() Status {
	manager.state.Lock()
	status := Status{Generation: manager.generation, ConfigurationSHA256: manager.digest}
	if manager.generation == 0 {
		manager.state.Unlock()
		return status
	}
	if manager.process == nil || manager.process.exited() {
		status.Message = manager.restartMessage
		if status.Message == "" {
			status.Message = "Xray process is not running"
		}
		manager.state.Unlock()
		return status
	}
	if manager.running == nil {
		status.Message = "Xray runtime configuration is unavailable"
		manager.state.Unlock()
		return status
	}
	configuration := manager.running.configuration
	manager.state.Unlock()
	status.Listeners = manager.inspect(configuration)
	status.Healthy = true
	for _, listener := range status.Listeners {
		if listener.State == ListenerNotListening {
			status.Healthy = false
			status.Message = fmt.Sprintf("Xray is not listening on %s/%s port %d", listener.ServiceID, listener.Network, listener.Port)
			break
		}
	}
	return status
}

func (manager *Manager) Close(ctx context.Context) error {
	manager.cancel()
	manager.operation.Lock()
	defer manager.operation.Unlock()
	manager.state.Lock()
	process := manager.process
	manager.process = nil
	manager.running = nil
	manager.restartMessage = ""
	manager.state.Unlock()
	if process == nil {
		return nil
	}
	return process.stop(ctx)
}

func (manager *Manager) watchProcess(process *managedProcess, spec *runtimeSpec) {
	go func() {
		select {
		case <-process.done:
		case <-manager.lifecycle.Done():
			return
		}

		manager.operation.Lock()
		manager.state.Lock()
		if manager.process != process || manager.running != spec {
			manager.state.Unlock()
			manager.operation.Unlock()
			return
		}
		manager.process = nil
		manager.restartMessage = "Xray process exited unexpectedly"
		manager.state.Unlock()
		_ = process.stop(context.Background())
		manager.operation.Unlock()

		delay := manager.restartDelay
		if delay <= 0 {
			delay = defaultRestartDelay
		}
		for {
			timer := time.NewTimer(delay)
			select {
			case <-manager.lifecycle.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			manager.operation.Lock()
			manager.state.Lock()
			if manager.process != nil || manager.running != spec {
				manager.state.Unlock()
				manager.operation.Unlock()
				return
			}
			manager.state.Unlock()

			ctx, cancel := context.WithTimeout(manager.lifecycle, processRestartTimeout)
			replacement, err := manager.startConfigured(ctx, spec)
			cancel()
			if err == nil {
				manager.state.Lock()
				manager.process = replacement
				manager.restartMessage = ""
				manager.state.Unlock()
				manager.operation.Unlock()
				manager.watchProcess(replacement, spec)
				return
			}
			manager.state.Lock()
			manager.restartMessage = fmt.Sprintf("restart Xray process: %v", err)
			manager.state.Unlock()
			manager.operation.Unlock()

			delay = min(delay*2, maximumRestartDelay)
		}
	}()
}

func (manager *Manager) restore(spec *runtimeSpec) *managedProcess {
	if spec == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), processStopTimeout)
	defer cancel()
	process, err := manager.startConfigured(ctx, spec)
	if err != nil {
		return nil
	}
	return process
}

func (manager *Manager) startConfigured(ctx context.Context, spec *runtimeSpec) (*managedProcess, error) {
	process, err := manager.start(ctx, spec)
	if err != nil {
		return nil, err
	}
	api, err := manager.connectAPI(ctx, spec.configuration)
	if err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), processStopTimeout)
		defer cancel()
		_ = process.stop(stopContext)
		return nil, err
	}
	process.api = api
	if err := manager.restoreServices(ctx, spec, api); err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), processStopTimeout)
		defer cancel()
		_ = process.stop(stopContext)
		return nil, err
	}
	if err := manager.restoreBlockRules(ctx, spec.configuration, api); err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), processStopTimeout)
		defer cancel()
		_ = process.stop(stopContext)
		return nil, err
	}
	return process, nil
}

func (manager *Manager) start(ctx context.Context, spec *runtimeSpec) (*managedProcess, error) {
	command := exec.Command(spec.installation.Binary, "run", "-config", spec.configPath)
	command.Dir = spec.installation.AssetDir
	command.Env = childEnvironment(manager.dataDirectory, spec.installation.AssetDir)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &managedProcess{command: command, done: make(chan struct{})}
	go func() {
		process.waitError = command.Wait()
		close(process.done)
	}()
	timer := time.NewTimer(manager.startupGrace)
	defer timer.Stop()
	select {
	case <-process.done:
		if process.waitError != nil {
			return nil, process.waitError
		}
		return nil, errors.New("Xray process exited during startup")
	case <-ctx.Done():
		stopContext, cancel := context.WithTimeout(context.Background(), processStopTimeout)
		defer cancel()
		_ = process.stop(stopContext)
		return nil, ctx.Err()
	case <-timer.C:
		return process, nil
	}
}

func newCounterEpoch() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate traffic counter epoch: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func (manager *Manager) writeTemporaryConfiguration(raw []byte) (string, func(), error) {
	directory := filepath.Join(manager.dataDirectory, "xray", "configurations")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", nil, fmt.Errorf("create Xray configuration directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", nil, fmt.Errorf("protect Xray configuration directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".candidate-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary Xray configuration: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		cleanup()
		return "", nil, fmt.Errorf("protect temporary Xray configuration: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		cleanup()
		return "", nil, fmt.Errorf("write temporary Xray configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		cleanup()
		return "", nil, fmt.Errorf("sync temporary Xray configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close temporary Xray configuration: %w", err)
	}
	return path, cleanup, nil
}

func (manager *Manager) commitConfiguration(temporaryPath string) (string, error) {
	candidate, err := os.ReadFile(temporaryPath)
	if err != nil {
		return "", fmt.Errorf("read candidate Xray configuration: %w", err)
	}
	digest := sha256.Sum256(candidate)
	finalPath := filepath.Join(filepath.Dir(temporaryPath), hex.EncodeToString(digest[:])+".json")
	if info, err := os.Lstat(finalPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o400 {
			return "", errors.New("stored Xray configuration is not a private regular file")
		}
		existing, readErr := os.ReadFile(finalPath)
		if readErr != nil {
			return "", fmt.Errorf("read stored Xray configuration: %w", readErr)
		}
		if string(existing) != string(candidate) {
			return "", errors.New("stored Xray configuration does not match its content digest")
		}
		return finalPath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect stored Xray configuration: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o400); err != nil {
		return "", fmt.Errorf("protect stored Xray configuration: %w", err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("commit Xray configuration: %w", err)
	}
	return finalPath, nil
}

func testConfiguration(parent context.Context, home string, installation xrayrelease.Installation, configPath string) error {
	ctx, cancel := context.WithTimeout(parent, configurationTestTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, installation.Binary, "run", "-test", "-config", configPath)
	command.Dir = installation.AssetDir
	command.Env = childEnvironment(home, installation.AssetDir)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return ErrConfigurationRejected
	}
	return nil
}

func childEnvironment(home, assetDirectory string) []string {
	environment := []string{
		"HOME=" + home,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"XRAY_LOCATION_ASSET=" + assetDirectory,
	}
	if temporaryDirectory := os.Getenv("TMPDIR"); temporaryDirectory != "" {
		environment = append(environment, "TMPDIR="+temporaryDirectory)
	}
	return environment
}

func (process *managedProcess) exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *managedProcess) stop(ctx context.Context) error {
	if process != nil && process.api != nil {
		process.api.close()
		process.api = nil
	}
	if process == nil || process.command == nil || process.command.Process == nil || process.exited() {
		return nil
	}
	_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(processStopTimeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
	case <-timer.C:
	}
	_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
	select {
	case <-process.done:
		return nil
	case <-time.After(time.Second):
		return errors.New("Xray process did not exit after SIGKILL")
	}
}
