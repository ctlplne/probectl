// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/l7redact"
)

// The redaction floor, enforced at the source (D-43 refinement 3). Agents
// publish to the bus before anything reaches the store, and Kafka and NATS
// JetStream retain messages, so the agent itself must never emit looser data
// than its tenant allows. It fetches the tenant's floor from the control plane
// over the existing mTLS agent channel (the tenant comes from its certificate,
// never from anything it sends), refuses to start capture when its local
// l7_capture_redaction is looser than the floor, and applies metadata when it
// received no floor at all. The control-plane ingest strip is the second layer.

// Capture states the agent reports (agentv1.L7CapturePosture.state).
const (
	l7StateOff            = "off"
	l7StateRefusedConsent = "refused_consent"
	l7StateRefusedFloor   = "refused_floor"
	l7StateAttachFailed   = "attach_failed"
	l7StateCapturing      = "capturing"
	l7StateReplaying      = "replaying"
)

// Policy-channel timing.
const (
	defaultL7PolicyInterval = 5 * time.Minute
	l7PolicyCallTimeout     = 10 * time.Second
)

// L7PolicyClient is the agent's side of the D-43 policy channel.
type L7PolicyClient interface {
	// FetchFloor returns the tenant's redaction floor.
	FetchFloor(ctx context.Context) (string, error)
	// ReportPosture sends the agent's current capture posture.
	ReportPosture(ctx context.Context, p *agentv1.L7CapturePosture) error
	Close() error
}

// grpcL7Policy is the shipping client: the existing AgentService over mTLS,
// with the certificate the agent's registered identity was issued.
type grpcL7Policy struct {
	conn *grpc.ClientConn
	svc  agentv1.AgentServiceClient
}

// dialL7Policy connects the policy channel when control_plane.grpc_addr is
// configured; nil, nil when it is not (the agent then applies metadata). The
// client certificate is loaded through a rotating identity, so a renewed SVID
// is presented on the next handshake without a restart.
func dialL7Policy(cp ControlPlaneConfig) (L7PolicyClient, error) {
	if cp.GRPCAddr == "" {
		return nil, nil
	}
	cfg, _, err := crypto.ClientMTLSConfigRotating(cp.CertFile, cp.KeyFile, cp.CAFile, "")
	if err != nil {
		return nil, fmt.Errorf("ebpf: control-plane mTLS identity: %w", err)
	}
	if cp.ServerName != "" {
		cfg.ServerName = cp.ServerName
	}
	conn, err := grpc.NewClient(cp.GRPCAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, fmt.Errorf("ebpf: control-plane channel: %w", err)
	}
	return &grpcL7Policy{conn: conn, svc: agentv1.NewAgentServiceClient(conn)}, nil
}

func (g *grpcL7Policy) FetchFloor(ctx context.Context) (string, error) {
	resp, err := g.svc.FetchL7Policy(ctx, &agentv1.FetchL7PolicyRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetRedactionFloor(), nil
}

func (g *grpcL7Policy) ReportPosture(ctx context.Context, p *agentv1.L7CapturePosture) error {
	_, err := g.svc.ReportL7Posture(ctx, &agentv1.ReportL7PostureRequest{Posture: p})
	return err
}

func (g *grpcL7Policy) Close() error { return g.conn.Close() }

// errNoFloor marks "no floor received" (no channel, or the call failed).
var errNoFloor = errors.New("no L7 redaction floor received")

// fetchFloor asks the control plane for the tenant's floor, bounded. A floor
// that is not a known mode is treated as not received (metadata applies).
func fetchFloor(ctx context.Context, c L7PolicyClient) (string, error) {
	if c == nil {
		return "", errNoFloor
	}
	cctx, cancel := context.WithTimeout(ctx, l7PolicyCallTimeout)
	defer cancel()
	floor, err := c.FetchFloor(cctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errNoFloor, err)
	}
	if !l7redact.ValidMode(floor) {
		return "", fmt.Errorf("%w: control plane sent unknown floor %q", errNoFloor, floor)
	}
	return floor, nil
}

// l7FloorDecision is what the agent does with its local mode against a floor.
type l7FloorDecision struct {
	mode   string // the mode capture runs under ("" when refused)
	floor  string // the floor applied ("" when none was received)
	refuse string // why capture is refused ("" when it may start)
	// clamped is true when no floor arrived and a looser local mode was
	// tightened to metadata.
	clamped bool
}

// decideL7Floor applies refinement 3: with a floor, a looser local mode is
// refused (never silently tightened — the operator asked for something the
// tenant does not allow, and must see that); with no floor, the stricter of the
// local mode and metadata applies.
func decideL7Floor(local, floor string, floorErr error) l7FloorDecision {
	local = l7redact.Normalize(local)
	if floorErr != nil {
		mode := l7redact.Stricter(local, l7redact.ModeMetadata)
		return l7FloorDecision{mode: mode, clamped: mode != local}
	}
	if l7redact.Looser(local, floor) {
		return l7FloorDecision{floor: floor, refuse: fmt.Sprintf(
			"l7_capture_redaction %q is looser than this tenant's redaction floor %q — capture refused (D-43); set l7_capture_redaction to %q or stricter, or have a tenant admin opt the tenant into %q",
			local, floor, floor, local)}
	}
	return l7FloorDecision{mode: local, floor: floor}
}

// postureState is the agent's reported capture state.
type postureState struct {
	state  string
	mode   string
	floor  string
	active bool
}

// posture renders the agent's capture posture for ReportL7Posture.
func (a *Agent) posture() *agentv1.L7CapturePosture {
	a.l7mu.Lock()
	st := a.l7state
	a.l7mu.Unlock()
	return &agentv1.L7CapturePosture{
		Enabled:        a.cfg.L7CaptureEnabled,
		ConsentTenant:  a.cfg.L7CaptureConsentTenant,
		Scope:          append([]string(nil), a.cfg.L7CaptureScope...),
		RedactionMode:  l7redact.Normalize(a.cfg.L7CaptureRedaction),
		EffectiveMode:  st.mode,
		RedactionFloor: st.floor,
		Active:         st.active,
		State:          st.state,
	}
}

func (a *Agent) setL7State(st postureState) {
	a.l7mu.Lock()
	a.l7state = st
	a.l7mu.Unlock()
	a.l7live.Store(st.active && st.state == l7StateCapturing)
}

// reportPosture sends the current posture, bounded and best effort: the
// control plane being unreachable never stops the agent, and the posture is
// sent again on the next policy tick.
func (a *Agent) reportPosture(ctx context.Context) {
	if a.policy == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, l7PolicyCallTimeout)
	defer cancel()
	if err := a.policy.ReportPosture(cctx, a.posture()); err != nil {
		a.log.Warn("ebpf L7 capture posture not reported to the control plane (retried on the next policy check)",
			"error", err.Error())
	}
}

// refreshL7Floor re-reads the floor on the policy tick. A floor that tightened
// past the running mode stops capture at once: the L7 source is closed and
// nothing more is parsed or published (fail closed). A loosened floor never
// widens a running agent — that takes a restart with the new local setting.
func (a *Agent) refreshL7Floor(ctx context.Context) (stop bool) {
	floor, err := fetchFloor(ctx, a.policy)
	if err != nil {
		a.reportPosture(ctx)
		return false
	}
	a.l7mu.Lock()
	running := a.l7state
	a.l7mu.Unlock()
	if running.mode != "" && l7redact.Looser(running.mode, floor) {
		a.log.Error("ebpf L7 capture STOPPED: the tenant's redaction floor tightened past the running mode (D-43)",
			"running_mode", running.mode, "floor", floor)
		a.setL7State(postureState{state: l7StateRefusedFloor, floor: floor})
		a.l7mode = ""
		stop = true
	} else if running.mode != "" && running.floor != floor {
		running.floor = floor
		a.setL7State(running)
	}
	a.reportPosture(ctx)
	return stop
}
