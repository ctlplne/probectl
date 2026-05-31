package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/netctl/internal/canary"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/agent/v1"
	resultv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/result/v1"
	"github.com/imfeelingtheagi/netctl/internal/version"
)

const (
	drainInterval   = 2 * time.Second
	minBackoff      = time.Second
	maxBackoff      = 30 * time.Second
	registerTimeout = 10 * time.Second
)

// Agent is the netctl agent runtime: a plugin host that always probes into a
// store-and-forward buffer, plus a forwarder that registers, heartbeats, and
// drains the buffer to the control plane — reconnecting with backoff so probing
// is never blocked by an outage.
type Agent struct {
	cfg      *Config
	log      *slog.Logger
	buffer   *Buffer
	host     *Host
	tenantID string
	agentID  string
}

// New builds an agent. Its identity (tenant + id) comes from its client
// certificate's SPIFFE id.
func New(cfg *Config, reg *canary.Registry, log *slog.Logger) (*Agent, error) {
	id, err := crypto.SPIFFEIDFromCertFile(cfg.TLS.CertFile)
	if err != nil {
		return nil, fmt.Errorf("agent identity: %w", err)
	}
	buffer, err := OpenBuffer(cfg.Buffer.Dir, cfg.Buffer.MaxRecords)
	if err != nil {
		return nil, err
	}
	var sched []scheduled
	for _, cc := range cfg.Canaries {
		c, err := reg.New(canary.Config{
			Type: cc.Type, Target: cc.Target, Interval: cc.Interval.Std(), Timeout: cc.Timeout.Std(), Params: cc.Params,
		})
		if err != nil {
			return nil, err
		}
		sched = append(sched, scheduled{canary: c, interval: cc.Interval.Std()})
	}
	host := &Host{scheduled: sched, buffer: buffer, tenantID: id.TenantID, agentID: id.AgentID, log: log}
	return &Agent{cfg: cfg, log: log, buffer: buffer, host: host, tenantID: id.TenantID, agentID: id.AgentID}, nil
}

// Run starts probing and forwarding until ctx is canceled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent starting", "tenant", a.tenantID, "agent", a.agentID,
		"control_plane", a.cfg.ControlPlane.GRPCAddr, "canaries", len(a.cfg.Canaries))
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { a.host.Run(gctx); return nil })
	g.Go(func() error { return a.forward(gctx) })
	return g.Wait()
}

// forward maintains a control-plane session, reconnecting with backoff. Probing
// continues regardless, so results buffer during outages and drain on reconnect.
func (a *Agent) forward(ctx context.Context) error {
	backoff := minBackoff
	for ctx.Err() == nil {
		client, err := Dial(a.cfg.ControlPlane.GRPCAddr,
			a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile, a.cfg.TLS.CAFile, a.cfg.TLS.ServerName)
		if err != nil {
			a.log.Warn("connect failed; buffering results", "error", err.Error())
		} else {
			err = a.session(ctx, client)
			_ = client.Close()
			if err == nil {
				return nil // ctx canceled, clean exit
			}
			a.log.Warn("control-plane session ended; will reconnect", "error", err.Error())
		}
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return nil
}

// session registers, then heartbeats and drains until an RPC error or ctx done.
func (a *Agent) session(ctx context.Context, client *Client) error {
	rctx, cancel := context.WithTimeout(ctx, registerTimeout)
	resp, err := client.Register(rctx, &agentv1.RegisterRequest{
		Hostname: a.cfg.Agent.Hostname, AgentVersion: version.Get().Version, Capabilities: a.cfg.Agent.Capabilities,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	a.log.Info("registered with control plane", "agent", resp.GetAgentId(), "tenant", resp.GetTenantId())

	hbInterval := a.cfg.Agent.HeartbeatInterval.Std()
	if s := resp.GetHeartbeatIntervalSeconds(); s > 0 {
		hbInterval = time.Duration(s) * time.Second
	}
	ticker := time.NewTicker(drainInterval)
	defer ticker.Stop()
	lastHB := time.Now()
	for {
		select {
		case <-ctx.Done():
			dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.drainOnce(dctx, client) // best-effort final drain
			dcancel()
			return nil
		case <-ticker.C:
			if time.Since(lastHB) >= hbInterval {
				if err := client.Heartbeat(ctx, &agentv1.HeartbeatRequest{AgentId: a.agentID}); err != nil {
					return fmt.Errorf("heartbeat: %w", err)
				}
				lastHB = time.Now()
			}
			if err := a.drainOnce(ctx, client); err != nil {
				return fmt.Errorf("drain: %w", err)
			}
		}
	}
}

// drainOnce forwards the buffered results in one client stream. At-least-once:
// records are removed only after the control plane acks the batch, so a failure
// mid-batch retains everything to retry (duplicates possible; S6 handles dedup).
func (a *Agent) drainOnce(ctx context.Context, client *Client) error {
	frames, err := a.buffer.PeekAll()
	if err != nil {
		return err
	}
	if len(frames) == 0 {
		return nil
	}
	stream, err := client.StreamResults(ctx)
	if err != nil {
		return err
	}
	for _, fr := range frames {
		req, err := frameToRequest(fr)
		if err != nil {
			a.log.Error("discarding malformed buffered result", "error", err.Error())
			continue
		}
		if err := stream.Send(req); err != nil {
			_, _ = stream.CloseAndRecv()
			return err
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if err := a.buffer.Remove(len(frames)); err != nil {
		return err
	}
	a.log.Debug("drained results", "count", len(frames), "accepted", ack.GetAccepted())
	return nil
}

// frameToRequest converts a buffered JSON result envelope into a StreamResults
// request carrying the canonical OTel-aligned result (proto) as its payload. The
// disk buffer stays JSON; only the wire payload is the proto schema.
func frameToRequest(frame []byte) (*agentv1.StreamResultsRequest, error) {
	var env resultEnvelope
	if err := json.Unmarshal(frame, &env); err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(envToResult(&env))
	if err != nil {
		return nil, err
	}
	return &agentv1.StreamResultsRequest{
		Type:              env.Result.Type,
		Payload:           payload,
		ObservedUnixNanos: unixNano(env.Result.StartedAt),
	}, nil
}

// envToResult maps the agent's result envelope onto the canonical result schema.
// The control plane re-stamps tenant + agent from the mTLS certificate, so the
// identity here is advisory.
func envToResult(env *resultEnvelope) *resultv1.Result {
	r := env.Result
	return &resultv1.Result{
		TenantId:          env.TenantID,
		AgentId:           env.AgentID,
		CanaryType:        r.Type,
		ServerAddress:     r.Target,
		Success:           r.Success,
		ErrorMessage:      r.Error,
		StartTimeUnixNano: unixNano(r.StartedAt),
		DurationNano:      int64(r.Duration),
		Metrics:           r.Metrics,
		Attributes:        r.Attributes,
	}
}

// unixNano returns t in Unix nanoseconds, or 0 for the zero time (whose UnixNano
// is an unhelpful large negative number).
func unixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// sleep waits for d or until ctx is canceled; it returns false if canceled.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
