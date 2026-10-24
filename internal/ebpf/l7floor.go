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
	// l7StateRefusedChannel is agent-local: consented live capture needs the
	// control-plane channel, and a control plane that recorded its posture
	// (D-43 S1). The control plane never stores it — there is nothing to
	// store it through.
	l7StateRefusedChannel = "refused_channel"
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

// checkChannelIdentity binds the policy channel to this agent (D-43 S3): the
// certificate's SPIFFE identity must name the tenant and the collector
// agent_id this agent publishes as. A Secret copied from another release, or
// another tenant's identity, would otherwise fetch THAT tenant's floor and
// record the posture on THAT tenant's agent while this agent published as
// itself.
func checkChannelIdentity(cfg *Config) error {
	id, err := channelSPIFFEID(cfg.ControlPlane.CertFile)
	if err != nil {
		return fmt.Errorf("ebpf: control-plane identity unreadable: %w", err)
	}
	if id.TenantID != cfg.TenantID {
		return fmt.Errorf("ebpf: control-plane certificate names tenant %q but this agent is configured for tenant %q — the identity Secret is not this agent's", id.TenantID, cfg.TenantID)
	}
	if id.AgentID != cfg.AgentID {
		return fmt.Errorf("ebpf: control-plane certificate names agent %q but this agent publishes as %q — the identity Secret is not this agent's", id.AgentID, cfg.AgentID)
	}
	return nil
}

// channelSPIFFEID reads the SPIFFE identity of the policy-channel certificate.
func channelSPIFFEID(certFile string) (crypto.SPIFFEID, error) {
	return crypto.SPIFFEIDFromCertFile(certFile)
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

// reportState sends the posture capture is about to run under, and returns
// whether the control plane recorded it.
func (a *Agent) reportState(ctx context.Context, st postureState) error {
	if a.policy == nil {
		return errNoChannel
	}
	p := a.posture()
	p.EffectiveMode, p.RedactionFloor, p.Active, p.State = st.mode, st.floor, st.active, st.state
	cctx, cancel := context.WithTimeout(ctx, l7PolicyCallTimeout)
	defer cancel()
	return a.policy.ReportPosture(cctx, p)
}

// errNoChannel marks a consented capture with no control-plane channel.
var errNoChannel = errors.New("no control-plane channel configured")

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

// staleFloorGrace is how many consecutive policy checks may fail before a
// running mode looser than metadata falls back to metadata (D-43 S2). At the
// default 5-minute interval that is 15 minutes; at the 30-second minimum,
// 90 seconds. A stale floor never keeps a looser mode indefinitely.
const staleFloorGrace = 3

// refreshL7Floor re-reads the floor on the policy tick. A floor that tightened
// past the running mode stops capture at once: the L7 source is closed and
// nothing more is parsed or published (fail closed). A loosened floor never
// widens a running agent — that takes a restart with the new local setting.
// When the floor cannot be read for staleFloorGrace checks in a row, a mode
// looser than metadata falls back to metadata until a fresh floor arrives; the
// fresh floor restores the decided mode only after the control plane recorded
// the posture it restores (D-43 S2).
func (a *Agent) refreshL7Floor(ctx context.Context) (stop bool) {
	a.l7mu.Lock()
	running := a.l7state
	a.l7mu.Unlock()
	floor, err := fetchFloor(ctx, a.policy)
	if err != nil {
		a.floorFailures++
		if a.floorFailures >= staleFloorGrace && running.mode != "" && l7redact.Looser(running.mode, l7redact.ModeMetadata) {
			a.log.Warn("ebpf L7 capture: the redaction floor could not be refreshed — falling back to metadata until a fresh floor arrives (D-43)",
				"failed_checks", a.floorFailures, "running_mode", running.mode, "error", err.Error())
			running.mode = l7redact.ModeMetadata
			a.setL7State(running)
			a.l7mode = l7redact.ModeMetadata
		}
		a.reportPosture(ctx)
		return false
	}
	a.floorFailures = 0
	if running.mode == "" {
		a.reportPosture(ctx)
		return false
	}
	d := decideL7Floor(a.cfg.L7CaptureRedaction, floor, nil)
	if d.refuse != "" || l7redact.Looser(running.mode, floor) {
		a.log.Error("ebpf L7 capture STOPPED: the tenant's redaction floor tightened past the running mode (D-43)",
			"running_mode", running.mode, "floor", floor)
		a.setL7State(postureState{state: l7StateRefusedFloor, floor: floor})
		a.l7mode = ""
		a.stoppedFloor = floor
		a.reportPosture(ctx)
		return true
	}
	next := running
	next.floor = floor
	if l7redact.Looser(d.mode, running.mode) {
		// Restoring the decided mode from a fallback widens what is emitted:
		// only once the control plane has recorded it.
		next.mode = d.mode
		if rerr := a.reportState(ctx, next); rerr != nil {
			next.mode = running.mode
		} else {
			a.l7mode = d.mode
		}
	}
	a.setL7State(next)
	a.reportPosture(ctx)
	return false
}

// emitFloor is the mode every L7 record leaving the agent must satisfy at
// flush time: the running mode, or — once a tightened floor stopped capture —
// that floor. Records aggregated under an earlier, looser mode are re-minimized
// to it, so a tightening applies to what is already buffered too (D-43).
func (a *Agent) emitFloor() string {
	if a.l7mode != "" {
		return a.l7mode
	}
	if a.stoppedFloor != "" {
		return a.stoppedFloor
	}
	return l7redact.DefaultMode
}

// reminimize applies emitFloor to buffered L7 records before they are
// published; under length nothing is published.
func (a *Agent) reminimize(recs []L7Record) []L7Record {
	mode := a.emitFloor()
	if !l7redact.Persists(mode) {
		return nil
	}
	for i := range recs {
		recs[i].Call = minimizeCall(recs[i].Call, mode)
	}
	return recs
}
