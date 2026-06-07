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

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/compliance"
	"github.com/imfeelingtheagi/probectl/internal/config"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/siem"
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
	log        *slog.Logger
	binding    pipeline.TenantBinding // TENANT-101; nil = unit tests
}

// NewComplianceConsumer builds the consumer over a non-nil engine.
func NewComplianceConsumer(b bus.Bus, e *compliance.Engine, c *incident.Correlator, log *slog.Logger) *ComplianceConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &ComplianceConsumer{engine: e, bus: b, correlator: c, log: log}
}

// WithSIEM forwards violation signals to the SIEM (S32). nil disables it.
func (cc *ComplianceConsumer) WithSIEM(fw *siem.Forwarder) *ComplianceConsumer {
	cc.siem = fw
	return cc
}

// Run subscribes to the flow and eBPF topics (own groups) until ctx ends.
func (cc *ComplianceConsumer) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	go func() { errc <- cc.bus.Subscribe(ctx, bus.FlowEventsTopic, "compliance-flow", cc.handleFlow) }()
	go func() { errc <- cc.bus.Subscribe(ctx, bus.EBPFFlowsTopic, "compliance-ebpf", cc.handleEBPF) }()
	return <-errc
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101).
func (cc *ComplianceConsumer) WithTenantBinding(b pipeline.TenantBinding) *ComplianceConsumer {
	cc.binding = b
	return cc
}

// rejectFlows verifies claimed identities, dropping the batch fail-closed.
func (cc *ComplianceConsumer) rejectFlows(ctx context.Context, plane string, ids []pipeline.Identity) bool {
	if cc.binding == nil || len(ids) == 0 {
		return false
	}
	if _, _, err := pipeline.VerifyBatchTenant(ctx, cc.binding, "", ids); err != nil {
		cc.log.Error("REJECTED batch: tenant verification failed (TENANT-101, fail closed)",
			"view", "compliance", "plane", plane, "claimed_tenant", ids[0].Tenant,
			"agent_id", ids[0].Agent, "error", err.Error())
		return true
	}
	return false
}

func (cc *ComplianceConsumer) handleFlow(ctx context.Context, msg bus.Message) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("compliance: skipping malformed flow batch", "error", err)
		return nil
	}
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
			DstPort: uint16(f.GetDestinationPort()), Bytes: f.GetBytes(),
			Source: "flow", At: at,
		}))
	}
	return nil
}

func (cc *ComplianceConsumer) handleEBPF(ctx context.Context, msg bus.Message) error {
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("compliance: skipping malformed ebpf batch", "error", err)
		return nil
	}
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
			DstPort: uint16(f.GetDestinationPort()), Bytes: f.GetBytes(),
			Source: "ebpf", At: time.Unix(0, f.GetObservedAtUnixNano()),
		}))
	}
	return nil
}

func (cc *ComplianceConsumer) export(ctx context.Context, sigs []incident.Signal) {
	for _, sig := range sigs {
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
