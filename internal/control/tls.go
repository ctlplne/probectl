// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/siem"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

// BuildTLSAnalyzer builds the S27 TLS/cert posture analyzer from config. CT
// correlation is enabled only when the operator opts in (external fetch — AUP /
// sovereignty / no-phone-home).
func BuildTLSAnalyzer(cfg *config.Config) *threat.Analyzer {
	var ct threat.CTChecker
	if cfg.CTEnabled {
		ct = threat.NewCrtSh(cfg.CTEndpoint, 10*time.Second)
	}
	return threat.NewAnalyzer(threat.Config{
		ExpiryWarning: cfg.TLSExpiryWarning,
		TrustctlURL:   cfg.TrustctlURL,
	}, ct)
}

// TLSPostureConsumer subscribes to the network-results topic and, for HTTPS
// synthetic results, analyzes the ALREADY-CAPTURED TLS data (S13) into TLS/cert
// posture findings — correlating each into a threat-plane incident (feeding the
// unified timeline + alerting, S16/S17). It NEVER re-handshakes (S27 watch-out).
type TLSPostureConsumer struct {
	postures   *threat.PostureStore   // optional inventory (S-FE2)
	detections *threat.DetectionStore // optional triage feed (S-FE3)
	bus        bus.Bus
	correlator *incident.Correlator
	analyzer   *threat.Analyzer
	siem       *siem.Forwarder
	log        *slog.Logger
	nsTenants  map[string]string
}

// NewTLSPostureConsumer builds the consumer.
func NewTLSPostureConsumer(b bus.Bus, c *incident.Correlator, a *threat.Analyzer, log *slog.Logger) *TLSPostureConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &TLSPostureConsumer{bus: b, correlator: c, analyzer: a, log: log}
}

// WithSIEM forwards each TLS/cert posture signal to the SIEM (S32) in addition to
// correlating it into an incident. nil disables it (the default).
// WithPostureStore retains every analyzed posture (clean ones included) as the
// tenant's certificate inventory (S-FE2). nil is a no-op.
func (cs *TLSPostureConsumer) WithPostureStore(ps *threat.PostureStore) *TLSPostureConsumer {
	cs.postures = ps
	return cs
}

// WithDetections retains intel-attributed findings (malicious cert/JA3) for
// the triage surface (S-FE3). nil is a no-op.
func (cs *TLSPostureConsumer) WithDetections(ds *threat.DetectionStore) *TLSPostureConsumer {
	cs.detections = ds
	return cs
}

func (cs *TLSPostureConsumer) WithSIEM(fw *siem.Forwarder) *TLSPostureConsumer {
	cs.siem = fw
	return cs
}

// WithNamespaceTenants subscribes standalone TLS posture to siloed result lanes.
func (cs *TLSPostureConsumer) WithNamespaceTenants(ns map[string]string) *TLSPostureConsumer {
	cs.nsTenants = ns
	return cs
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cs *TLSPostureConsumer) LaneFanoutEnabled() bool { return true }

// Run subscribes until ctx is canceled (standalone mode; production uses
// SinkResult via the ResultFan, SCALE-013).
func (cs *TLSPostureConsumer) Run(ctx context.Context) error {
	return runResultSinkLanes(ctx, cs.bus, "tls-posture", cs.log, cs.nsTenants, cs.SinkResult)
}

// SinkPosture updates only the TLS posture read model. It is safe for
// per-replica fan-in because it has no external side effects: no incident
// correlation, no SIEM enqueue, and no detection-store append.
func (cs *TLSPostureConsumer) SinkPosture(ctx context.Context, r *resultv1.Result) error {
	cs.analyzeAndRecord(ctx, r)
	return nil
}

// SinkResult analyzes one DECODED result (shared immutable — never mutated).
func (cs *TLSPostureConsumer) SinkResult(ctx context.Context, r *resultv1.Result) error {
	for _, sig := range cs.analyzeAndRecord(ctx, r) {
		inc, err := cs.correlator.Ingest(ctx, sig)
		if err != nil {
			cs.log.Warn("correlate tls posture into incident failed", "error", err)
		}
		if cs.detections != nil {
			incID := ""
			if inc != nil {
				incID = inc.ID
			}
			if d, ok := threat.DetectionFromSignal(sig, incID); ok {
				cs.detections.Record(sig.TenantID, d)
			}
		}
		if cs.siem != nil {
			if err := cs.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
				cs.log.Warn("forward tls posture to siem failed", "error", err)
			}
		}
	}
	return nil
}

// analyzeAndRecord analyzes one result's captured TLS, retains the posture in
// the inventory (clean or not — S-FE2), and returns the threat-plane signals
// (nil for a non-HTTPS result or a clean posture).
func (cs *TLSPostureConsumer) analyzeAndRecord(ctx context.Context, r *resultv1.Result) []incident.Signal {
	if r.GetCanaryType() != "http" {
		return nil
	}
	obs, ok := threat.FromCanaryAttributes(r.GetServerAddress(), r.GetAttributes(), time.Unix(0, r.GetStartTimeUnixNano()))
	if !ok {
		return nil
	}
	posture := cs.analyzer.Analyze(ctx, obs)
	if cs.postures != nil {
		cs.postures.Record(r.GetTenantId(), posture)
	}
	return threat.ToSignals(r.GetTenantId(), posture)
}
