// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

// Compliance / segmentation-validation wiring (S46, F43): the validator
// consumes the flow (S38) and eBPF (S20) streams the control plane already
// receives, checks them against declared segmentation policies, and serves
// verdicts at /v1/compliance with audit-grade evidence at
// /v1/compliance/evidence. Violations are SIGNALS into the incident pipeline
// and the SIEM — probectl validates, it never enforces (guardrail 9).

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/config"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BuildCompliance loads segmentation policies and builds the validator.
// (nil, false, nil) when disabled; a malformed policy dir is a startup ERROR
// (a boundary the operator believes is validated must actually be).
func BuildCompliance(cfg *config.Config, log *slog.Logger) (*compliance.Engine, bool, error) {
	if cfg == nil || !cfg.ComplianceEnabled {
		return nil, false, nil
	}
	policies, err := compliance.LoadDir(cfg.CompliancePolicyDir)
	if err != nil {
		return nil, false, err
	}
	eng := compliance.NewEngine(policies)
	if log != nil {
		log.Info("compliance validator enabled", "policies", eng.Policies())
	}
	return eng, true, nil
}

// WithCompliance attaches the validator backing /v1/compliance. nil is a
// no-op (the endpoints report compliance_running=false).
func (s *Server) WithCompliance(e *compliance.Engine) *Server {
	if e != nil {
		s.complianceEngine = e
	}
	return s
}

// handleCompliance serves GET /v1/compliance — per-rule verdicts + coverage.
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.complianceEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"compliance_running": false, "items": []compliance.RuleResult{},
		})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"compliance_running": true,
		"items":              s.complianceEngine.Results(tid),
		"coverage":           s.complianceEngine.CoverageFor(tid),
	})
	return nil
}

// handleComplianceEvidence serves GET /v1/compliance/evidence — the
// audit-grade, hash-chained export (PCI/NIST mappings + coverage caveats).
func (s *Server) handleComplianceEvidence(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.complianceEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"compliance_running": false})
		return nil
	}
	ev, err := s.complianceEngine.Export(tid)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-compliance-evidence.json"`)
	writeJSON(w, http.StatusOK, ev)
	return nil
}

// ComplianceConsumer feeds the validator from the flow + eBPF topics and
// exports violation signals to incidents and the SIEM.
type ComplianceConsumer struct {
	engine     *compliance.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	siem       *siem.Forwarder
	gate       ComplianceAlertGate // DPR-073: cluster-wide once-only export of a violation
	log        *slog.Logger
	rejections *rejectionLogger       // DPR-074: fail-closed rejections, loud once per window
	binding    pipeline.TenantBinding // TENANT-101; nil = unit tests
	nsTenants  map[string]string
}

// NewComplianceConsumer builds the consumer over a non-nil engine.
func NewComplianceConsumer(b bus.Bus, e *compliance.Engine, c *incident.Correlator, log *slog.Logger) *ComplianceConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &ComplianceConsumer{engine: e, bus: b, correlator: c, log: log, rejections: newRejectionLogger(0)}
}

// ComplianceAlertGate decides, cluster-wide, whether THIS replica exports a
// violation's side effects (DPR-073). Every replica evaluates the same traffic
// in its own view group, so without the gate three replicas would file three
// incidents and three SIEM events per violation, and a replay after a rollout
// would file them again.
type ComplianceAlertGate interface {
	Claim(ctx context.Context, tenant, policy, rule string, at time.Time) (bool, error)
}

// WithAlertGate installs the once-only export gate. nil (no database — the
// single-process/lightweight shapes) exports every violation locally.
func (cc *ComplianceConsumer) WithAlertGate(g ComplianceAlertGate) *ComplianceConsumer {
	cc.gate = g
	return cc
}

// pgComplianceGate backs the gate with the compliance_alerted table (FORCE RLS).
type pgComplianceGate struct {
	pool   *pgxpool.Pool
	window time.Duration
}

// DefaultComplianceRealert is how long a claimed violation stays claimed
// (DPR-110): inside the window every replica and every replay collapses to the
// one export that won the claim; the next window re-arms the pair, so an
// ongoing violation keeps saying so and a remediated one that returns is
// reported again instead of meeting a gate that was closed forever.
const DefaultComplianceRealert = 24 * time.Hour

func (p pgComplianceGate) Claim(ctx context.Context, tenant, policy, rule string, at time.Time) (won bool, err error) {
	period := compliancePeriod(at, p.window)
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), p.pool, func(ctx context.Context, sc tenancy.Scope) error {
		won, err = (store.ComplianceAlerted{}).Claim(ctx, sc, policy, rule, period)
		return err
	})
	return won, err
}

// compliancePeriod buckets an observation time into the re-alert window. A
// non-positive window means the default; the bucket is UTC so replicas in
// different zones agree on which claim they are racing for.
func compliancePeriod(at time.Time, window time.Duration) string {
	if window <= 0 {
		window = DefaultComplianceRealert
	}
	if at.IsZero() {
		at = time.Now()
	}
	return at.UTC().Truncate(window).Format(time.RFC3339)
}

// NewPGComplianceGate returns the Postgres-backed once-only export gate. window
// is how long a claim holds (0 = DefaultComplianceRealert).
func NewPGComplianceGate(pool *pgxpool.Pool, window time.Duration) ComplianceAlertGate {
	return pgComplianceGate{pool: pool, window: window}
}

// WithSIEM forwards violation signals to the SIEM (S32). nil disables it.
func (cc *ComplianceConsumer) WithSIEM(fw *siem.Forwarder) *ComplianceConsumer {
	cc.siem = fw
	return cc
}

// Run subscribes to the shared flow/eBPF topics plus every siloed-tenant lane.
func (cc *ComplianceConsumer) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return pipeline.RunLanes(gctx, cc.bus, bus.FlowEventsTopic, viewGroup("compliance-flow"), cc.nsTenants, cc.handleFlowLane)
	})
	g.Go(func() error {
		return pipeline.RunLanes(gctx, cc.bus, bus.EBPFFlowsTopic, viewGroup("compliance-ebpf"), cc.nsTenants, cc.handleEBPFLane)
	})
	return g.Wait()
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101).
func (cc *ComplianceConsumer) WithTenantBinding(b pipeline.TenantBinding) *ComplianceConsumer {
	cc.binding = b
	return cc
}

// WithNamespaceTenants subscribes compliance to each siloed tenant's flow/eBPF lane.
func (cc *ComplianceConsumer) WithNamespaceTenants(ns map[string]string) *ComplianceConsumer {
	cc.nsTenants = ns
	return cc
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cc *ComplianceConsumer) LaneFanoutEnabled() bool { return true }

// rejectFlows verifies claimed identities, dropping the batch fail-closed.
func (cc *ComplianceConsumer) rejectFlows(ctx context.Context, plane string, ids []pipeline.Identity) bool {
	if cc.binding == nil || len(ids) == 0 {
		return false
	}
	if _, _, err := pipeline.VerifyBatchTenant(ctx, cc.binding, "", ids); err != nil {
		cc.rejections.Log(cc.log, "REJECTED batch: tenant verification failed (TENANT-101, fail closed)",
			[]string{"compliance", plane, ids[0].Tenant, ids[0].Agent, err.Error()},
			"view", "compliance", "plane", plane, "claimed_tenant", ids[0].Tenant,
			"agent_id", ids[0].Agent, "error", err.Error())
		return true
	}
	return false
}

func (cc *ComplianceConsumer) handleFlow(ctx context.Context, msg bus.Message) error {
	return cc.handleFlowLane(ctx, msg, "")
}

func (cc *ComplianceConsumer) handleFlowLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("compliance: skipping malformed flow batch", "error", err)
		return nil
	}
	stampFlowBatchLaneTenant(&batch, laneTenant)
	ids := make([]pipeline.Identity, len(batch.GetFlows()))
	for i, f := range batch.GetFlows() {
		ids[i] = pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
	}
	if cc.rejectFlows(ctx, "flow", ids) {
		return nil
	}
	for _, f := range batch.GetFlows() {
		if f.GetTenantId() == "" {
			continue // unscoped records are dropped (guardrail 1)
		}
		at := time.Unix(0, f.GetEndUnixNano())
		if f.GetEndUnixNano() == 0 {
			at = time.Unix(0, f.GetObservedAtUnixNano())
		}
		cc.export(ctx, cc.engine.Observe(f.GetTenantId(), compliance.FlowObs{
			Src: f.GetSourceAddress(), Dst: f.GetDestinationAddress(),
			DstPort: uint16(f.GetDestinationPort()), Bytes: scaledFlowBytes(f),
			Source: "flow", At: at,
		}))
	}
	return nil
}

func (cc *ComplianceConsumer) handleEBPFLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("compliance: skipping malformed ebpf batch", "error", err)
		return nil
	}
	stampEBPFBatchLaneTenant(&batch, laneTenant)
	ids := make([]pipeline.Identity, len(batch.GetFlows()))
	for i, f := range batch.GetFlows() {
		ids[i] = pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
	}
	if cc.rejectFlows(ctx, "ebpf", ids) {
		return nil
	}
	for _, f := range batch.GetFlows() {
		if f.GetTenantId() == "" {
			continue
		}
		cc.export(ctx, cc.engine.Observe(f.GetTenantId(), compliance.FlowObs{
			Src: f.GetSourceAddress(), Dst: f.GetDestinationAddress(),
			DstPort: uint16(f.GetDestinationPort()), Bytes: f.GetBytes(), // eBPF: unsampled, raw bytes are true volume
			Source: "ebpf", At: time.Unix(0, f.GetObservedAtUnixNano()),
		}))
	}
	return nil
}

func (cc *ComplianceConsumer) export(ctx context.Context, sigs []incident.Signal) {
	for _, sig := range sigs {
		if cc.gate != nil {
			won, err := cc.gate.Claim(ctx, sig.TenantID, sig.Attributes["compliance.policy"], sig.Attributes["compliance.rule"], sig.OccurredAt)
			switch {
			case err != nil:
				// Fail open on the gate only: a violation is never dropped because
				// the database blinked; a duplicate incident is the lesser harm.
				cc.log.Warn("compliance: export gate unavailable, exporting locally", "error", err,
					"tenant_id", sig.TenantID, "rule", sig.Attributes["compliance.rule"])
			case !won:
				cc.log.Debug("compliance: violation already exported by another replica",
					"tenant_id", sig.TenantID, "rule", sig.Attributes["compliance.rule"])
				continue
			}
		}
		if cc.correlator != nil {
			if _, err := cc.correlator.Ingest(ctx, sig); err != nil {
				cc.log.Warn("compliance: correlate violation failed", "error", err)
			}
		}
		if cc.siem != nil {
			if err := cc.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
				cc.log.Warn("compliance: forward violation to siem failed", "error", err)
			}
		}
		cc.log.Warn("segmentation violation observed",
			"tenant_id", sig.TenantID, "rule", sig.Attributes["compliance.rule"],
			"from", sig.Attributes["compliance.from"], "to", sig.Attributes["compliance.to"],
			"source", sig.Attributes["compliance.source"])
	}
}
