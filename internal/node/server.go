package node

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/contract"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qqqasdwx/relayward-plugin-xray/internal/config"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/pluginmeta"
	"github.com/qqqasdwx/relayward-plugin-xray/internal/xrayruntime"
)

type Runtime interface {
	Validate(context.Context, config.Configuration) error
	Apply(context.Context, uint64, string, config.Configuration) error
	ApplyServiceState(context.Context, uint64, uint64, string, string, bool) error
	ApplyDynamicBlocks(context.Context, uint64, uint64, []xrayruntime.DynamicBlock) error
	CollectTraffic(context.Context) ([]xrayruntime.TrafficCounter, error)
	CollectActivity(context.Context, uint64, uint32) (xrayruntime.ActivityPage, error)
	TelemetryStreamID() string
	GetStatus() xrayruntime.Status
}

type Server struct {
	nodepluginv1.UnimplementedNodePluginServer
	version string
	runtime Runtime
}

func New(version string, runtime Runtime) *Server {
	return &Server{version: version, runtime: runtime}
}

func (server *Server) GetInfo(context.Context, *nodepluginv1.GetInfoRequest) (*nodepluginv1.GetInfoResponse, error) {
	return &nodepluginv1.GetInfoResponse{
		ApiVersion: contract.NodePluginAPIVersion,
		PluginId:   pluginmeta.ID,
		Version:    server.version,
		Capabilities: []string{
			nodepluginv1.CapabilityRecentActivity,
			nodepluginv1.CapabilityDynamicBlocking,
			nodepluginv1.CapabilityServiceControl,
			nodepluginv1.CapabilityTrafficCounters,
		},
		TelemetryStreamId: server.runtime.TelemetryStreamID(),
	}, nil
}

func (server *Server) CollectTelemetry(ctx context.Context, request *nodepluginv1.CollectTelemetryRequest) (*nodepluginv1.CollectTelemetryResponse, error) {
	if err := nodepluginv1.ValidateCollectTelemetryRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid telemetry request")
	}
	values, err := server.runtime.CollectTraffic(ctx)
	if err != nil {
		if errors.Is(err, xrayruntime.ErrRuntimeUnavailable) {
			return nil, status.Error(codes.FailedPrecondition, "Xray runtime is unavailable")
		}
		return nil, status.Error(codes.Unavailable, "Xray traffic collection failed")
	}
	activity, err := server.runtime.CollectActivity(ctx, request.AfterSequence, request.MaximumEvents)
	if err != nil {
		switch {
		case errors.Is(err, xrayruntime.ErrRuntimeUnavailable):
			return nil, status.Error(codes.FailedPrecondition, "Xray runtime is unavailable")
		case errors.Is(err, xrayruntime.ErrTelemetryDataLoss):
			return nil, status.Error(codes.DataLoss, "Xray activity cursor is no longer available")
		case errors.Is(err, xrayruntime.ErrTelemetryCursor):
			return nil, status.Error(codes.InvalidArgument, "Xray activity cursor is ahead of the stream")
		case errors.Is(err, xrayruntime.ErrTelemetryFull):
			return nil, status.Error(codes.ResourceExhausted, "Xray activity queue is full")
		default:
			return nil, status.Error(codes.Unavailable, "Xray activity collection failed")
		}
	}
	response := &nodepluginv1.CollectTelemetryResponse{
		ObservedAtUnixNano: time.Now().UTC().UnixNano(),
		Counters:           make([]*nodepluginv1.TrafficCounter, len(values)),
		Events:             make([]*nodepluginv1.AccessEvent, len(activity.Events)),
		NextSequence:       activity.NextSequence,
		HasMore:            activity.HasMore,
	}
	for index, value := range values {
		response.Counters[index] = &nodepluginv1.TrafficCounter{
			AuthorizationId: value.AuthorizationID,
			ServiceId:       value.ServiceID,
			CounterEpoch:    value.CounterEpoch,
			UploadBytes:     value.UploadBytes,
			DownloadBytes:   value.DownloadBytes,
		}
	}
	for index, value := range activity.Events {
		response.Events[index] = &nodepluginv1.AccessEvent{
			Sequence: value.Sequence, EventId: value.EventID, ObservedAtUnixNano: value.ObservedAt,
			AuthorizationId: value.AuthorizationID, ServiceId: value.ServiceID,
			SourceIp: value.SourceIP, Action: agentv1.AccessActionAccepted,
		}
	}
	if err := nodepluginv1.ValidateCollectTelemetryResponse(request, response); err != nil {
		return nil, status.Error(codes.Internal, "Xray returned invalid telemetry")
	}
	return response, nil
}

func (server *Server) ReplaceDynamicBlocks(ctx context.Context, request *nodepluginv1.ReplaceDynamicBlocksRequest) (*nodepluginv1.ReplaceDynamicBlocksResponse, error) {
	if err := nodepluginv1.ValidateReplaceDynamicBlocksRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid dynamic block request")
	}
	blocks := make([]xrayruntime.DynamicBlock, len(request.Blocks))
	for index, block := range request.Blocks {
		blocks[index] = xrayruntime.DynamicBlock{
			AuthorizationID: block.AuthorizationId, ServiceID: block.ServiceId, SourceIP: block.SourceIp,
			ExpiresAtUnixNano: block.ExpiresAtUnixNano,
		}
	}
	if err := server.runtime.ApplyDynamicBlocks(ctx, request.PolicyGeneration, request.BlockRevision, blocks); err != nil {
		switch {
		case errors.Is(err, xrayruntime.ErrUnsupportedService):
			return nil, status.Error(codes.InvalidArgument, "unsupported Xray service")
		case errors.Is(err, xrayruntime.ErrServiceDisabled):
			return nil, status.Error(codes.FailedPrecondition, "Xray service is disabled")
		case errors.Is(err, xrayruntime.ErrRuntimeUnavailable):
			return nil, status.Error(codes.FailedPrecondition, "Xray runtime is unavailable")
		case errors.Is(err, xrayruntime.ErrDynamicBlockConflict):
			return nil, status.Error(codes.Aborted, "Xray dynamic block revision changed")
		default:
			return nil, status.Error(codes.Unavailable, "Xray dynamic block update failed")
		}
	}
	return &nodepluginv1.ReplaceDynamicBlocksResponse{
		PolicyGeneration: request.PolicyGeneration, BlockRevision: request.BlockRevision,
		BlockCount: uint32(len(request.Blocks)),
	}, nil
}

func (server *Server) SetServiceState(ctx context.Context, request *nodepluginv1.SetServiceStateRequest) (*nodepluginv1.SetServiceStateResponse, error) {
	if err := nodepluginv1.ValidateSetServiceStateRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid service state request")
	}
	if err := server.runtime.ApplyServiceState(ctx, request.PolicyGeneration, request.StateRevision,
		request.AuthorizationId, request.ServiceId, request.Enabled); err != nil {
		switch {
		case errors.Is(err, xrayruntime.ErrUnsupportedService):
			return nil, status.Error(codes.InvalidArgument, "unsupported Xray service")
		case errors.Is(err, xrayruntime.ErrRuntimeUnavailable), errors.Is(err, xrayruntime.ErrServiceDisabled):
			return nil, status.Error(codes.FailedPrecondition, "Xray service is unavailable")
		case errors.Is(err, xrayruntime.ErrServiceStateConflict):
			return nil, status.Error(codes.Aborted, "Xray service state revision changed")
		default:
			return nil, status.Error(codes.Unavailable, "Xray service state update failed")
		}
	}
	return &nodepluginv1.SetServiceStateResponse{
		PolicyGeneration: request.PolicyGeneration,
		StateRevision:    request.StateRevision,
		AuthorizationId:  request.AuthorizationId,
		ServiceId:        request.ServiceId,
		Enabled:          request.Enabled,
		Reason:           request.Reason,
	}, nil
}

func (server *Server) ValidateConfiguration(ctx context.Context, request *nodepluginv1.ConfigurationRequest) (*nodepluginv1.ConfigurationValidated, error) {
	if err := nodepluginv1.ValidateConfigurationRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration envelope")
	}
	configuration, err := config.Decode(request.Json)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Xray plugin configuration")
	}
	if err := server.runtime.Validate(ctx, configuration); err != nil {
		if errors.Is(err, xrayruntime.ErrConfigurationRejected) {
			return nil, status.Error(codes.InvalidArgument, "Xray rejected the configuration")
		}
		return nil, status.Error(codes.Unavailable, "Xray runtime preparation failed")
	}
	return &nodepluginv1.ConfigurationValidated{Generation: request.Generation, Sha256: request.Sha256}, nil
}

func (server *Server) ApplyConfiguration(ctx context.Context, request *nodepluginv1.ConfigurationRequest) (*nodepluginv1.ConfigurationApplied, error) {
	if err := nodepluginv1.ValidateConfigurationRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration envelope")
	}
	configuration, err := config.Decode(request.Json)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Xray plugin configuration")
	}
	if err := server.runtime.Apply(ctx, request.Generation, request.Sha256, configuration); err != nil {
		if errors.Is(err, xrayruntime.ErrConfigurationRejected) {
			return nil, status.Error(codes.InvalidArgument, "Xray rejected the configuration")
		}
		return nil, status.Error(codes.Internal, "Xray runtime switch failed")
	}
	return &nodepluginv1.ConfigurationApplied{Generation: request.Generation, Sha256: request.Sha256}, nil
}

func (server *Server) GetStatus(context.Context, *nodepluginv1.GetStatusRequest) (*nodepluginv1.GetStatusResponse, error) {
	runtimeStatus := server.runtime.GetStatus()
	health := nodepluginv1.Health_HEALTH_STARTING
	if runtimeStatus.Generation != 0 {
		health = nodepluginv1.Health_HEALTH_UNHEALTHY
		if runtimeStatus.Healthy {
			health = nodepluginv1.Health_HEALTH_HEALTHY
		}
	}
	return &nodepluginv1.GetStatusResponse{
		Generation:          runtimeStatus.Generation,
		ConfigurationSha256: runtimeStatus.ConfigurationSHA256,
		Health:              health,
		Message:             runtimeStatus.Message,
	}, nil
}
