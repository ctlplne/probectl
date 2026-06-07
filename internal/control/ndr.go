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

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
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
		return cs.bus.Subscribe(gctx, bus.NetworkResultsTopic, "ndr-dns", cs.handleResult)
	})
	g.Go(func() error { return cs.RunFlowLanes(gctx) })
	return g.Wait()
}

// RunFlowLanes consumes ONLY the flow/eBPF lanes — production mode when the
// DNS results arrive via the decode-once ResultFan (SCALE-013).
func (cs *NDRConsumer) RunFlowLanes(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return cs.bus.Subscribe(gctx, bus.FlowEventsTopic, "ndr-flow", cs.handleFlowBatch)
	})
	g.Go(func() error {
		return cs.bus.Subscribe(gctx, bus.EBPFFlowsTopic, "ndr-ebpf", cs.handleEBPFBatch)
	})
	return g.Wait()
}

// handleResult feeds DNS canary lookups (S12) into the DNS detectors.
func (cs *NDRConsumer) handleResult(ctx context.Context, msg bus.Message) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		cs.log.Warn("ndr: skipping malformed result", "error", err)
		return nil
	}
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
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cs.log.Warn("ndr: skipping malformed flow batch", "error", err)
		return nil
	}
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if tenant == "" {
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
			Bytes:   f.GetBytes(),
			At:      at,
		})
		cs.export(ctx, sigs)
	}
	return nil
}

// handleEBPFBatch feeds eBPF flows (S20) and L7 DNS calls (S21) into the
// detectors — host-level east-west visibility.
func (cs *NDRConsumer) handleEBPFBatch(ctx context.Context, msg bus.Message) error {
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cs.log.Warn("ndr: skipping malformed ebpf batch", "error", err)
		return nil
	}
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if tenant == "" {
			continue
		}
		sigs := cs.engine.ObserveFlow(tenant, threat.FlowObservation{
			Src:     f.GetSourceAddress(),
			Dst:     f.GetDestinationAddress(),
			DstPort: uint16(f.GetDestinationPort()),
			Bytes:   f.GetBytes(),
			At:      time.Unix(0, f.GetObservedAtUnixNano()),
		})
		cs.export(ctx, sigs)
	}
	for _, c := range batch.GetL7Calls() {
		if c.GetProtocol() != "dns" || c.GetTenantId() == "" || c.GetResource() == "" {
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
