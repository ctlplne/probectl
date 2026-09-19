// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/canary"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
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
		// SCALE-008, same as the forwarder: jitter so a fleet does not
		// reconnect in lockstep after a control-plane restart. This loop is
		// otherwise identical to Agent.forward's, and used to be the one of
		// the two that slept on the raw backoff.
		if !sleep(ctx, jittered(backoff)) {
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return nil
}

// poll runs coordination tasks until ctx is canceled or the session fails.
//
// Task handlers are JOINED before poll returns (errgroup, the sanctioned
// idiom). They used to be bare `go co.handle(...)` calls, which outlived Run
// and — worse — could still be using client after the caller closed it on the
// way round the reconnect loop.
func (co *Coordinator) poll(ctx context.Context, client *Client) error {
	ticker := time.NewTicker(co.cfg.A2A.PollInterval.Std())
	defer ticker.Stop()

	var handlers errgroup.Group
	pollErr := func() error {
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
					task := resp.GetTask()
					handlers.Go(func() error { co.handle(ctx, client, task); return nil })
				}
			}
		}
	}()
	_ = handlers.Wait() // handle never returns an error; it logs and gives up
	return pollErr
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
	// DPR-246: both errors were discarded, so a listener address this code could
	// not parse was reported to the peer as port 0 — a measurement endpoint nobody
	// can reach, indistinguishable from a healthy one. ParseUint with an explicit
	// 16-bit width also makes the uint32 conversion below provably in range
	// instead of relying on the address happening to be well formed.
	_, portStr, splitErr := net.SplitHostPort(resp.Addr())
	if splitErr != nil {
		co.log.Warn("a2a: cannot parse responder address", "addr", resp.Addr(), "error", splitErr.Error())
		return
	}
	port64, portErr := strconv.ParseUint(portStr, 10, 16)
	if portErr != nil {
		co.log.Warn("a2a: responder address has no usable port", "addr", resp.Addr(), "error", portErr.Error())
		return
	}
	port := uint32(port64)

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	err = client.ReportEndpoint(rctx, task.GetSessionId(), co.advertise, port)
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
	payload, err := json.Marshal(resultEnvelope{
		SchemaVersion: resultEnvelopeSchemaVersion,
		TenantID:      co.tenantID,
		AgentID:       co.agentID,
		ResultID:      newResultID(),
		Result:        res,
	})
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
