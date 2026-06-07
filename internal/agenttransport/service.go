package agenttransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/a2a"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

const heartbeatIntervalSeconds = 30

// service implements agentv1.AgentServiceServer.
type service struct {
	agentv1.UnimplementedAgentServiceServer
	pool     *pgxpool.Pool
	bus      bus.Bus
	broker   *a2a.Broker
	log      *slog.Logger
	agents   store.Agents
	shutdown <-chan struct{}
	// hb coalesces heartbeat UPDATEs (Sprint 14, SCALE-012); nil = sync.
	hb       *heartbeatBatcher
	accepted atomic.Uint64 // results accepted across all StreamResults calls
	// freshness refuses stale/replayed stream envelopes (Sprint 12, WIRE-006).
	freshness *nonceCache

	// Version-skew policy (S34): the control plane is the authority on agent↔control
	// compatibility. An agent outside the N/N-1 window is rejected at Register so a
	// rolling upgrade never lets an incompatible agent into the fleet.
	compat         lifecycle.Policy
	controlVersion string
}

// Register upserts the agent into its tenant's registry. The id and tenant are
// taken from the verified certificate, so this is always tenant-correct.
func (svc *service) Register(ctx context.Context, req *agentv1.RegisterRequest) (*agentv1.RegisterResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	// Version-skew gate (S34): reject an agent outside the supported window before it
	// joins the registry. FailedPrecondition signals "upgrade required" (retrying
	// without upgrading won't help), distinct from a transient error.
	if ok, reason := svc.compat.Check(svc.controlVersion, req.GetAgentVersion()); !ok {
		svc.log.Warn("rejecting incompatible agent",
			"tenant", id.TenantID, "agent", id.AgentID,
			"agent_version", req.GetAgentVersion(), "control_version", svc.controlVersion, "reason", reason)
		return nil, status.Errorf(codes.FailedPrecondition,
			"agent version %q incompatible with control plane %q: %s", req.GetAgentVersion(), svc.controlVersion, reason)
	}
	name := req.GetHostname()
	if name == "" {
		name = id.AgentID
	}
	var agent *store.Agent
	var quotaErr error
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool,
		func(ctx context.Context, s tenancy.Scope) error {
			// Per-tenant quota gate (S-T3): NEW agents only — an existing
			// agent re-registering (idempotent upsert) must never be rejected
			// at quota, or a running fleet would break on restart.
			if _, gerr := svc.agents.Get(ctx, s, id.AgentID); gerr != nil {
				if qerr := usage.AllowCreate(ctx, id.TenantID, usage.MeterAgents); qerr != nil {
					quotaErr = qerr
					return qerr
				}
			}
			a, e := svc.agents.Register(ctx, s, id.AgentID, name, req.GetHostname(),
				req.GetAgentVersion(), id.String(), req.GetCapabilities())
			agent = a
			return e
		})
	if quotaErr != nil {
		svc.log.Warn("agent registration rejected at quota", "tenant", id.TenantID, "agent", id.AgentID, "error", quotaErr.Error())
		return nil, status.Error(codes.ResourceExhausted, quotaErr.Error())
	}
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
	if svc.hb != nil {
		// SCALE-012: coalesced — one multi-row UPDATE per tenant per window
		// instead of one UPDATE per heartbeat RPC.
		svc.hb.record(id.TenantID, id.AgentID)
		return &agentv1.HeartbeatResponse{ConfigStale: false, HeartbeatIntervalSeconds: heartbeatIntervalSeconds}, nil
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

// StreamConfig is an EXPLICIT DENY (Sprint 13, ARCH-003; ADR
// docs/adr/config-push.md, U-044): the RPC stays in the schema for wire
// compatibility, but the server refuses it immediately — no frame is sent, no
// stream is held open, and the agent has no code path that calls it. Config
// push is deliberately not a capability; implementing it requires the
// signed-push ADR, never a quiet handler change.
func (svc *service) StreamConfig(_ *agentv1.StreamConfigRequest, _ grpc.ServerStreamingServer[agentv1.StreamConfigResponse]) error {
	return status.Error(codes.Unimplemented,
		"config push is not a capability; see docs/adr/config-push.md (U-044)")
}

// StreamResults accepts a stream of results, publishes each to the result bus,
// and acknowledges the count. The result's tenant + agent are taken from the
// verified certificate (never the payload), so a result is always attributed to
// the sending agent's tenant (CLAUDE.md §7 guardrails 1 and 5).
func (svc *service) StreamResults(stream grpc.ClientStreamingServer[agentv1.StreamResultsRequest, agentv1.StreamResultsResponse]) error {
	id, err := identityFromContext(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	ctx := stream.Context()
	// WIRE-006: the stream envelope must be FRESH and UNSEEN — a replayed or
	// stale open is refused before any result is read (fail closed).
	if svc.freshness != nil {
		md, _ := metadata.FromIncomingContext(ctx)
		if ferr := svc.freshness.check(md, id.TenantID+"/"+id.AgentID); ferr != nil {
			svc.log.Warn("REFUSED results stream: freshness/replay check failed (WIRE-006)",
				"tenant", id.TenantID, "agent", id.AgentID, "error", ferr.Error())
			return status.Error(codes.Unauthenticated, "stream envelope rejected: "+ferr.Error())
		}
	}
	var accepted uint64
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			svc.accepted.Add(accepted)
			return stream.SendAndClose(&agentv1.StreamResultsResponse{Accepted: accepted})
		}
		if err != nil {
			svc.accepted.Add(accepted)
			return err
		}
		if err := svc.ingest(ctx, id, req); err != nil {
			// A bus-publish failure surfaces as a stream error so the agent
			// retries the (still-buffered) batch: at-least-once delivery.
			svc.accepted.Add(accepted)
			svc.log.Error("result ingest failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
			return status.Error(codes.Unavailable, "ingest failed")
		}
		accepted++
	}
}

// ingest decodes one result, stamps the authoritative tenant + agent identity
// from the certificate, and publishes it to the result bus keyed by tenant.
func (svc *service) ingest(ctx context.Context, id crypto.SPIFFEID, req *agentv1.StreamResultsRequest) error {
	var r resultv1.Result
	if err := proto.Unmarshal(req.GetPayload(), &r); err != nil {
		// A malformed payload is a poison message: drop it (counted as accepted
		// so the agent does not wedge retrying it) rather than fail the stream.
		svc.log.Error("dropping malformed result payload", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		return nil
	}
	// Authoritative identity comes from the mTLS certificate, not the payload.
	r.TenantId = id.TenantID
	r.AgentId = id.AgentID
	if svc.bus == nil {
		return nil // no bus wired (minimal server): accept and count only
	}
	value, err := proto.Marshal(&r)
	if err != nil {
		return err
	}
	// Siloed bus lanes (S-T2): a siloed/hybrid tenant's results ride its own
	// namespaced topic. FAIL CLOSED (RED-006): if the lane cannot be resolved,
	// the result is DROPPED with a loud error — a siloed tenant's telemetry
	// must never silently ride the shared lane. The agent's store-and-forward
	// retries cover the blip.
	t, rerr := tenancy.CurrentRouter().TargetsFor(ctx, id.TenantID)
	if rerr != nil {
		svc.log.Error("DROPPING result: isolation routing unavailable (RED-006, fail closed)",
			"tenant", id.TenantID, "agent", id.AgentID, "error", rerr.Error())
		return fmt.Errorf("isolation routing unavailable: %w", rerr)
	}
	topic, terr := bus.TopicFor(t.BusNamespace, bus.NetworkResultsTopic)
	if terr != nil {
		svc.log.Error("DROPPING result: invalid bus namespace (RED-006, fail closed)",
			"tenant", id.TenantID, "namespace", t.BusNamespace, "error", terr.Error())
		return terr
	}
	return svc.bus.Publish(ctx, topic, []byte(r.TenantId), value)
}

// PollCoordination returns the next brokered agent-to-agent task for the calling
// agent. The tenant and agent are taken from the verified certificate, so an
// agent can only ever receive its own tasks (CLAUDE.md §7 guardrails 1 and 5).
func (svc *service) PollCoordination(ctx context.Context, _ *agentv1.PollCoordinationRequest) (*agentv1.PollCoordinationResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if svc.broker == nil {
		return &agentv1.PollCoordinationResponse{HasTask: false}, nil
	}
	task, ok := svc.broker.PollFor(id.TenantID, id.AgentID)
	if !ok {
		return &agentv1.PollCoordinationResponse{HasTask: false}, nil
	}
	return &agentv1.PollCoordinationResponse{HasTask: true, Task: toProtoTask(task)}, nil
}

// ReportEndpoint records where a responder is listening for a session. The
// broker verifies the caller is that session's responder in its tenant.
func (svc *service) ReportEndpoint(ctx context.Context, req *agentv1.ReportEndpointRequest) (*agentv1.ReportEndpointResponse, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if svc.broker == nil {
		return nil, status.Error(codes.Unavailable, "coordination not enabled")
	}
	if err := svc.broker.ReportEndpoint(id.TenantID, id.AgentID, req.GetSessionId(), req.GetHost(), req.GetPort()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &agentv1.ReportEndpointResponse{Accepted: true}, nil
}

func toProtoTask(t a2a.Task) *agentv1.A2ATask {
	role := agentv1.A2ARole_A2A_ROLE_UNSPECIFIED
	switch t.Role {
	case a2a.RoleResponder:
		role = agentv1.A2ARole_A2A_ROLE_RESPONDER
	case a2a.RoleInitiator:
		role = agentv1.A2ARole_A2A_ROLE_INITIATOR
	}
	return &agentv1.A2ATask{
		SessionId:     t.SessionID,
		Role:          role,
		Mode:          t.Mode,
		Count:         t.Count,
		ResponderHost: t.ResponderHost,
		ResponderPort: t.ResponderPort,
		PeerAgentId:   t.PeerAgentID,
	}
}
