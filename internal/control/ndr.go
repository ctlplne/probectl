// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

// NDR-lite wiring (S42, F37): the behavioral detection engine consumes the
// streams the control plane already receives — DNS canary results (S12),
// flow records (S38), eBPF flows + L7 DNS calls (S20/S21) — and exports each
// confidence-scored detection through the SAME path as the S28 IOC matches:
// incident correlation (S17) + the triage DetectionStore (S-FE3) + the SIEM
// forwarder (S32). Detections are SIGNALS — nothing here can block traffic
// (guardrail 9).

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"sync/atomic"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/siem"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

// BuildNDR loads the detection-as-code ruleset and builds the engine.
// Returns (nil, false) when NDR is disabled; a malformed rules directory is
// a startup ERROR (fail closed — the operator believes their tuning is live).
// intel and topo are optional context sources (nil degrades gracefully).
func BuildNDR(cfg *config.Config, intel threat.IntelSource, topo threat.NeighborSource, log *slog.Logger) (*threat.Engine, bool, error) {
	if cfg == nil || !cfg.NDREnabled {
		return nil, false, nil
	}
	rules, err := threat.LoadRules(cfg.NDRRulesDir)
	if err != nil {
		return nil, false, fmt.Errorf("ndr: %w", err)
	}
	eng := threat.NewEngine(rules, intel, topo)
	if log != nil {
		active := eng.Rules()
		ids := make([]string, 0, len(active))
		for _, r := range active {
			ids = append(ids, fmt.Sprintf("%s@v%d", r.ID, r.Version))
		}
		log.Info("ndr detection engine enabled", "rules", ids, "intel", intel != nil, "topology", topo != nil)
	}
	return eng, true, nil
}

// NDRConsumer feeds the engine from the bus and exports raised detections.
type NDRConsumer struct {
	engine     *threat.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	detections *threat.DetectionStore
	siem       *siem.Forwarder
	log        *slog.Logger

	// binding is the registry-backed tenant verification (TENANT-101, ARCH-012).
	// The NDR consumer was the ONE bus consumer that trusted the payload tenant
	// on the shared flow/eBPF lanes: a bus actor could inject a record claiming
	// any tenant_id and have a detection raised against that victim tenant. With
	// a binding, a batch whose claimed identities don't verify is dropped
	// fail-closed. nil = unit tests only (production always sets it).
	binding   pipeline.TenantBinding
	nsTenants map[string]string

	// SCALE-005: the NDR consumer is a SECOND consumer group on the flow/eBPF
	// lanes (in addition to the storage FlowConsumer), and it ran with no
	// fairness gate — a tenant flooding its flow lane could saturate the threat
	// engine and starve every other tenant's detection latency. gate bounds
	// per-tenant flow/eBPF admission before ObserveFlow, identical to the
	// storage flow pipeline's contract. nil = unbounded (tests / opt-out).
	gate *fairness.Gate
	shed atomic.Uint64 // flow/eBPF records shed by the per-tenant fairness gate
}

// WithFairness bounds per-tenant flow/eBPF admission into the threat engine
// (SCALE-005). Over-rate tenants' records are shed BEFORE ObserveFlow, so a
// flow-flooding tenant cannot starve another tenant's detection latency.
func (cs *NDRConsumer) WithFairness(g *fairness.Gate) *NDRConsumer {
	cs.gate = g
	return cs
}

// admitFlows decides, per tenant, whether n flow/eBPF records are within the
// tenant's fairness bound (SCALE-005). Returns the set of tenants whose records
// must be SHED this batch; admitted tenants are absent from the map. A nil gate
// admits everything (tests / opt-out).
func (cs *NDRConsumer) admitFlows(ctx context.Context, counts map[string]int) map[string]bool {
	if cs.gate == nil || len(counts) == 0 {
		return nil
	}
	var shed map[string]bool
	for tenant, n := range counts {
		if tenant == "" {
			continue
		}
		if !cs.gate.AdmitN(ctx, tenant, fairness.MeterFlowEvents, int64(n)) {
			if shed == nil {
				shed = make(map[string]bool, 1)
			}
			shed[tenant] = true
			cs.shed.Add(uint64(n))
			cs.log.Debug("ndr flow records shed by fairness bounds", "tenant_id", tenant, "records", n)
		}
	}
	return shed
}

// Shed reports flow/eBPF records the NDR consumer shed for fairness (SCALE-005).
func (cs *NDRConsumer) Shed() uint64 { return cs.shed.Load() }

// WithTenantBinding installs registry-backed tenant verification (TENANT-101,
// ARCH-012) so the NDR consumer cannot raise a detection against a tenant the
// sending agent doesn't belong to.
func (cs *NDRConsumer) WithTenantBinding(b pipeline.TenantBinding) *NDRConsumer {
	cs.binding = b
	return cs
}

// WithNamespaceTenants subscribes NDR to each siloed tenant's flow/eBPF lane.
func (cs *NDRConsumer) WithNamespaceTenants(ns map[string]string) *NDRConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cs *NDRConsumer) LaneFanoutEnabled() bool { return true }

// rejectFlows verifies the claimed identities against the registry, dropping
// the whole batch fail-closed on mismatch (TENANT-101, ARCH-012).
func (cs *NDRConsumer) rejectFlows(ctx context.Context, plane string, ids []pipeline.Identity) bool {
	if cs.binding == nil || len(ids) == 0 {
		return false
	}
	if _, _, err := pipeline.VerifyBatchTenant(ctx, cs.binding, "", ids); err != nil {
		cs.log.Error("REJECTED batch: tenant verification failed (TENANT-101/ARCH-012, fail closed)",
			"view", "ndr", "plane", plane, "claimed_tenant", ids[0].Tenant,
			"agent_id", ids[0].Agent, "error", err.Error())
		return true
	}
	return false
}

// NewNDRConsumer builds the consumer over a non-nil engine.
func NewNDRConsumer(b bus.Bus, eng *threat.Engine, c *incident.Correlator, log *slog.Logger) *NDRConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &NDRConsumer{engine: eng, bus: b, correlator: c, log: log}
}

// WithDetections retains raised detections for the triage surface (S-FE3).
func (cs *NDRConsumer) WithDetections(ds *threat.DetectionStore) *NDRConsumer {
	cs.detections = ds
	return cs
}

// WithSIEM forwards each detection to the SIEM (S32). nil disables it.
func (cs *NDRConsumer) WithSIEM(fw *siem.Forwarder) *NDRConsumer {
	cs.siem = fw
	return cs
}

// Run subscribes to the DNS-result, flow, and eBPF topics (independent
// consumer groups) until ctx is canceled.
func (cs *NDRConsumer) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return pipeline.RunLanes(gctx, cs.bus, bus.NetworkResultsTopic, "ndr-dns", cs.nsTenants, cs.handleResultLane)
	})
	g.Go(func() error { return cs.RunFlowLanes(gctx) })
	return g.Wait()
}

// RunFlowLanes consumes ONLY the flow/eBPF lanes — production mode when the
// DNS results arrive via the decode-once ResultFan (SCALE-013).
func (cs *NDRConsumer) RunFlowLanes(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return pipeline.RunLanes(gctx, cs.bus, bus.FlowEventsTopic, "ndr-flow", cs.nsTenants, cs.handleFlowBatchLane)
	})
	g.Go(func() error {
		return pipeline.RunLanes(gctx, cs.bus, bus.EBPFFlowsTopic, "ndr-ebpf", cs.nsTenants, cs.handleEBPFBatchLane)
	})
	return g.Wait()
}

func (cs *NDRConsumer) handleResultLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		cs.log.Warn("ndr: skipping malformed result", "error", err)
		return nil
	}
	stampResultLaneTenant(&r, laneTenant)
	return cs.SinkResult(ctx, &r)
}

// SinkResult feeds one DECODED dns result (shared immutable — never mutated).
func (cs *NDRConsumer) SinkResult(ctx context.Context, r *resultv1.Result) error {
	if r.GetCanaryType() != "dns" && r.GetCanaryType() != "dnstrace" {
		return nil
	}
	tenant := r.GetTenantId()
	if tenant == "" {
		return nil // unscoped records are dropped, never guessed (guardrail 1)
	}
	source := r.GetAgentId()
	if source == "" {
		source = "agent"
	}
	// A DNS canary's target IS the queried name (it rides ServerAddress in
	// the result schema — see envToResult).
	sigs := cs.engine.ObserveDNS(tenant, threat.DNSObservation{
		Source: source,
		QName:  r.GetServerAddress(),
		At:     time.Unix(0, r.GetStartTimeUnixNano()),
	})
	cs.export(ctx, sigs)
	return nil
}

// handleFlowBatch feeds device flow records (S38) into the flow detectors.
func (cs *NDRConsumer) handleFlowBatch(ctx context.Context, msg bus.Message) error {
	return cs.handleFlowBatchLane(ctx, msg, "")
}

func (cs *NDRConsumer) handleFlowBatchLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cs.log.Warn("ndr: skipping malformed flow batch", "error", err)
		return nil
	}
	stampFlowBatchLaneTenant(&batch, laneTenant)
	ids := make([]pipeline.Identity, len(batch.GetFlows()))
	for i, f := range batch.GetFlows() {
		ids[i] = pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
	}
	if cs.rejectFlows(ctx, "flow", ids) {
		return nil
	}
	// SCALE-005: per-tenant fairness shed before feeding the engine.
	counts := map[string]int{}
	for _, f := range batch.GetFlows() {
		counts[f.GetTenantId()]++
	}
	shed := cs.admitFlows(ctx, counts)
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if tenant == "" || shed[tenant] {
			continue
		}
		at := time.Unix(0, f.GetEndUnixNano())
		if f.GetEndUnixNano() == 0 {
			at = time.Unix(0, f.GetObservedAtUnixNano())
		}
		sigs := cs.engine.ObserveFlow(tenant, threat.FlowObservation{
			Src:     f.GetSourceAddress(),
			Dst:     f.GetDestinationAddress(),
			DstPort: uint16(f.GetDestinationPort()),
			DstASN:  f.GetDestinationAsn(),
			Bytes:   scaledFlowBytes(f),
			At:      at,
		})
		cs.export(ctx, sigs)
	}
	return nil
}

// handleEBPFBatch feeds eBPF flows (S20) and L7 DNS calls (S21) into the
// detectors — host-level east-west visibility.
func (cs *NDRConsumer) handleEBPFBatch(ctx context.Context, msg bus.Message) error {
	return cs.handleEBPFBatchLane(ctx, msg, "")
}

func (cs *NDRConsumer) handleEBPFBatchLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cs.log.Warn("ndr: skipping malformed ebpf batch", "error", err)
		return nil
	}
	stampEBPFBatchLaneTenant(&batch, laneTenant)
	// ARCH-012: verify both the flow identities and the L7-call identities
	// against the registry before any detection is raised; a mismatch drops the
	// whole batch fail-closed.
	ids := make([]pipeline.Identity, 0, len(batch.GetFlows())+len(batch.GetL7Calls()))
	for _, f := range batch.GetFlows() {
		ids = append(ids, pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()})
	}
	for _, c := range batch.GetL7Calls() {
		ids = append(ids, pipeline.Identity{Tenant: c.GetTenantId(), Agent: c.GetAgentId()})
	}
	if cs.rejectFlows(ctx, "ebpf", ids) {
		return nil
	}
	// SCALE-005: per-tenant fairness shed (flows + L7 calls counted together)
	// before feeding the engine.
	counts := map[string]int{}
	for _, f := range batch.GetFlows() {
		counts[f.GetTenantId()]++
	}
	for _, c := range batch.GetL7Calls() {
		counts[c.GetTenantId()]++
	}
	shed := cs.admitFlows(ctx, counts)
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if tenant == "" || shed[tenant] {
			continue
		}
		sigs := cs.engine.ObserveFlow(tenant, threat.FlowObservation{
			Src:     f.GetSourceAddress(),
			Dst:     f.GetDestinationAddress(),
			DstPort: uint16(f.GetDestinationPort()),
			Bytes:   f.GetBytes(), // eBPF observes every packet (unsampled): raw bytes are already true volume
			At:      time.Unix(0, f.GetObservedAtUnixNano()),
		})
		cs.export(ctx, sigs)
	}
	for _, c := range batch.GetL7Calls() {
		if c.GetProtocol() != "dns" || c.GetTenantId() == "" || c.GetResource() == "" || shed[c.GetTenantId()] {
			continue
		}
		sigs := cs.engine.ObserveDNS(c.GetTenantId(), threat.DNSObservation{
			Source: c.GetSource(),
			QName:  c.GetResource(),
			At:     time.Unix(0, c.GetStartUnixNano()),
		})
		cs.export(ctx, sigs)
	}
	return nil
}

// export routes each raised detection through the shared outputs: incident
// correlation, the triage store, and the SIEM — exactly the IOC-match path.
func (cs *NDRConsumer) export(ctx context.Context, sigs []incident.Signal) {
	for _, sig := range sigs {
		incID := ""
		if cs.correlator != nil {
			inc, err := cs.correlator.Ingest(ctx, sig)
			if err != nil {
				cs.log.Warn("ndr: correlate detection into incident failed", "error", err)
			} else if inc != nil {
				incID = inc.ID
			}
		}
		if cs.detections != nil {
			if d, ok := threat.DetectionFromSignal(sig, incID); ok {
				cs.detections.Record(sig.TenantID, d)
			}
		}
		if cs.siem != nil {
			if err := cs.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
				cs.log.Warn("ndr: forward detection to siem failed", "error", err)
			}
		}
		cs.log.Info("ndr detection raised",
			"tenant_id", sig.TenantID, "kind", sig.Kind, "entity", sig.Target,
			"rule", sig.Attributes["detector.rule"], "confidence", sig.Attributes["detector.confidence"],
			"incident_id", incID)
	}
}
