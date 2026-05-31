package agenttransport

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/agent/v1"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

const heartbeatIntervalSeconds = 30

// service implements agentv1.AgentServiceServer.
type service struct {
	agentv1.UnimplementedAgentServiceServer
	pool     *pgxpool.Pool
	log      *slog.Logger
	agents   store.Agents
	shutdown <-chan struct{}
}

// Register upserts the agent into its tenant's registry. The id and tenant are
// taken from the verified certificate, so this is always tenant-correct.
func (svc *service) Register(ctx context.Context, req *agentv1.RegisterRequest) (*agentv1.RegisterResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	name := req.GetHostname()
	if name == "" {
		name = id.AgentID
	}
	var agent *store.Agent
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool,
		func(ctx context.Context, s tenancy.Scope) error {
			a, e := svc.agents.Register(ctx, s, id.AgentID, name, req.GetHostname(),
				req.GetAgentVersion(), id.String(), req.GetCapabilities())
			agent = a
			return e
		})
	if err != nil {
		svc.log.Error("agent register failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		return nil, status.Error(codes.Internal, "register failed")
	}
	svc.log.Info("agent registered", "tenant", id.TenantID, "agent", id.AgentID, "hostname", req.GetHostname())
	return &agentv1.RegisterResponse{
		AgentId:                  agent.ID,
		TenantId:                 agent.TenantID,
		ConfigEpoch:              0,
		HeartbeatIntervalSeconds: heartbeatIntervalSeconds,
	}, nil
}

// Attest acknowledges the agent's identity. The mTLS handshake already proved it;
// SVID-based node/workload attestation is S-EE1.
func (svc *service) Attest(ctx context.Context, _ *agentv1.AttestRequest) (*agentv1.AttestResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return &agentv1.AttestResponse{Ok: true, Message: "attested " + id.String()}, nil
}

// Heartbeat marks the agent online.
func (svc *service) Heartbeat(ctx context.Context, _ *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool,
		func(ctx context.Context, s tenancy.Scope) error {
			_, e := svc.agents.Heartbeat(ctx, s, id.AgentID)
			return e
		})
	if err != nil {
		return nil, status.Error(codes.Internal, "heartbeat failed")
	}
	return &agentv1.HeartbeatResponse{ConfigStale: false, HeartbeatIntervalSeconds: heartbeatIntervalSeconds}, nil
}

// StreamConfig pushes configuration to the agent. Placeholder: one empty epoch-0
// update, then the stream stays open until the agent disconnects. Real test/probe
// config arrives in S7+.
func (svc *service) StreamConfig(_ *agentv1.StreamConfigRequest, stream grpc.ServerStreamingServer[agentv1.StreamConfigResponse]) error {
	id, err := identityFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if err := stream.Send(&agentv1.StreamConfigResponse{Epoch: 0}); err != nil {
		return err
	}
	svc.log.Debug("config stream opened", "tenant", id.TenantID, "agent", id.AgentID)
	select {
	case <-stream.Context().Done(): // agent disconnected
	case <-svc.shutdown: // server shutting down
	}
	return nil
}

// StreamResults accepts a stream of results and acknowledges the count. Result
// validation, bus publish, and TSDB write are S6.
func (svc *service) StreamResults(stream grpc.ClientStreamingServer[agentv1.StreamResultsRequest, agentv1.StreamResultsResponse]) error {
	if _, err := identityFromContext(stream.Context()); err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	var accepted uint64
	for {
		_, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&agentv1.StreamResultsResponse{Accepted: accepted})
		}
		if err != nil {
			return err
		}
		accepted++
	}
}
