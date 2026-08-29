package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	centerpluginv1 "github.com/Relayward/relayward-sdk/centerplugin/v1"
	"github.com/Relayward/relayward-sdk/contract"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/center"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/node"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
	pluginsocket "github.com/qqqasdwx/relayward-plugin-xray/internal/socket"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayrelease"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

var version = "0.0.0-dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	if err := contract.ValidateSemanticVersion(version); err != nil {
		os.Exit(2)
	}
	centerSocket := os.Getenv(centerpluginv1.EnvironmentPluginSocket)
	nodeSocket := os.Getenv(nodepluginv1.EnvironmentSocketPath)
	var err error
	switch {
	case centerSocket != "" && nodeSocket == "":
		err = runCenter(centerSocket)
	case nodeSocket != "" && centerSocket == "":
		err = runNode(nodeSocket)
	default:
		err = errors.New("exactly one Relayward plugin socket must be configured")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCenter(socketPath string) error {
	if os.Getenv(centerpluginv1.EnvironmentPluginID) != pluginmeta.ID {
		return errors.New("unexpected center plugin identity")
	}
	hostSocket := os.Getenv(centerpluginv1.EnvironmentHostSocket)
	if !filepath.IsAbs(socketPath) || !filepath.IsAbs(hostSocket) {
		return errors.New("center plugin and Host sockets must be absolute")
	}
	listener, err := pluginsocket.Listen(socketPath)
	if err != nil {
		return err
	}
	connection, err := grpc.NewClient("passthrough:///relayward-plugin-host",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", hostSocket)
		}),
	)
	if err != nil {
		listener.Close()
		return fmt.Errorf("create Relayward Host client: %w", err)
	}
	server := grpc.NewServer()
	centerpluginv1.RegisterCenterPluginServer(server, center.New(version, centerpluginv1.NewPluginHostClient(connection)))
	return serve(listener, server, connection.Close)
}

func runNode(socketPath string) error {
	if os.Getenv(nodepluginv1.EnvironmentPluginID) != pluginmeta.ID {
		return errors.New("unexpected node plugin identity")
	}
	dataDirectory := os.Getenv(nodepluginv1.EnvironmentDataDirectory)
	if !filepath.IsAbs(socketPath) || !filepath.IsAbs(dataDirectory) {
		return errors.New("node plugin socket and data directory must be absolute")
	}
	source := xrayrelease.NewClient()
	installer := xrayrelease.NewInstaller(dataDirectory, source)
	runtime, err := xrayruntime.NewManager(dataDirectory, installer)
	if err != nil {
		return err
	}
	listener, err := pluginsocket.Listen(socketPath)
	if err != nil {
		return err
	}
	server := grpc.NewServer()
	nodepluginv1.RegisterNodePluginServer(server, node.New(version, runtime))
	cleanup := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		return runtime.Close(ctx)
	}
	return serve(listener, server, cleanup)
}

func serve(listener net.Listener, server *grpc.Server, cleanup func() error) error {
	defer listener.Close()
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-serveResult:
		if cleanup != nil {
			_ = cleanup()
		}
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("serve plugin RPC: %w", err)
	case <-signals:
		server.Stop()
		if cleanup != nil {
			return cleanup()
		}
		return nil
	}
}
