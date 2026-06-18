// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
)

// Coordinator participates in brokered agent-to-agent measurement. It keeps its
// own control-plane connection, polls for tasks, and runs the responder or
// initiator role, enqueuing results into the shared store-and-forward buffer so
// they drain through the normal pipeline.
type Coordinator struct {
	cfg       *Config
	buffer    *Buffer
	tenantID  string
	agentID   string
	advertise string
	log       *slog.Logger
}

func newCoordinator(cfg *Config, buffer *Buffer, tenantID, agentID string, log *slog.Logger) *Coordinator {
	advertise := cfg.A2A.AdvertiseHost
	if advertise == "" {
		advertise = detectAdvertiseHost()
	}
	return &Coordinator{cfg: cfg, buffer: buffer, tenantID: tenantID, agentID: agentID, advertise: advertise, log: log}
}

// Run polls for coordination tasks until ctx is canceled, reconnecting with
// backoff (mirroring the forwarder so coordination survives outages).
func (co *Coordinator) Run(ctx context.Context) error {
	backoff := minBackoff
	for ctx.Err() == nil {
		client, err := Dial(co.cfg.ControlPlane.GRPCAddr,
			co.cfg.TLS.CertFile, co.cfg.TLS.KeyFile, co.cfg.TLS.CAFile, co.cfg.TLS.ServerName)
		if err != nil {
			co.log.Warn("coordination connect failed; retrying", "error", err.Error())
		} else {
			err = co.poll(ctx, client)
			_ = client.Close()
			if err == nil {
				return nil // ctx canceled, clean exit
			}
			co.log.Warn("coordination poll ended; reconnecting", "error", err.Error())
		}
		if !sleep(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return nil
}

func (co *Coordinator) poll(ctx context.Context, client *Client) error {
	ticker := time.NewTicker(co.cfg.A2A.PollInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			resp, err := client.PollCoordination(pctx)
			cancel()
			if err != nil {
				return err
			}
			if resp.GetHasTask() {
				go co.handle(ctx, client, resp.GetTask())
			}
		}
	}
}

func (co *Coordinator) handle(ctx context.Context, client *Client, task *agentv1.A2ATask) {
	switch task.GetRole() {
	case agentv1.A2ARole_A2A_ROLE_RESPONDER:
		co.runResponder(ctx, client, task)
	case agentv1.A2ARole_A2A_ROLE_INITIATOR:
		co.runInitiator(ctx, task)
	default:
		co.log.Warn("unknown coordination role", "session", task.GetSessionId())
	}
}

func (co *Coordinator) runResponder(ctx context.Context, client *Client, task *agentv1.A2ATask) {
	resp, err := canary.StartA2AResponder(task.GetMode(), co.advertise, task.GetSessionId())
	if err != nil {
		co.log.Error("a2a responder listen failed", "session", task.GetSessionId(), "error", err.Error())
		return
	}
	_, portStr, _ := net.SplitHostPort(resp.Addr())
	port, _ := strconv.Atoi(portStr)

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	err = client.ReportEndpoint(rctx, task.GetSessionId(), co.advertise, uint32(port))
	cancel()
	if err != nil {
		co.log.Error("a2a report endpoint failed", "session", task.GetSessionId(), "error", err.Error())
		return
	}

	serveCtx, stop := context.WithTimeout(ctx, co.cfg.A2A.ResponderTTL.Std())
	defer stop()
	co.enqueue(resp.Serve(serveCtx, int(task.GetCount()), task.GetPeerAgentId()))
}

func (co *Coordinator) runInitiator(ctx context.Context, task *agentv1.A2ATask) {
	addr := net.JoinHostPort(task.GetResponderHost(), strconv.Itoa(int(task.GetResponderPort())))
	ictx, cancel := context.WithTimeout(ctx, co.cfg.A2A.ResponderTTL.Std())
	defer cancel()
	res, err := canary.RunA2AInitiator(ictx, task.GetMode(), addr, int(task.GetCount()), 3*time.Second, task.GetPeerAgentId(), task.GetSessionId())
	if err != nil {
		co.log.Error("a2a initiator failed", "session", task.GetSessionId(), "error", err.Error())
		return
	}
	co.enqueue(res)
}

func (co *Coordinator) enqueue(res canary.Result) {
	payload, err := json.Marshal(resultEnvelope{TenantID: co.tenantID, AgentID: co.agentID, ResultID: newResultID(), Result: res})
	if err != nil {
		co.log.Error("a2a marshal result", "error", err.Error())
		return
	}
	if err := co.buffer.Enqueue(payload); err != nil {
		co.log.Warn("dropping a2a result (buffer full)", "error", err.Error())
	}
}

// detectAdvertiseHost returns a non-loopback IPv4 to advertise to peers, falling
// back to loopback. Operators behind NAT should set advertise_host explicitly.
func detectAdvertiseHost() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}
