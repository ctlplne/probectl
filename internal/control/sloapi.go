// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

// SLO wiring (S45, F42): the engine consumes the synthetic-result stream,
// tracks OpenSLO-defined SLIs per tenant, and serves statuses at /v1/slos
// (with OpenSLO export at /v1/slos/openslo). Burn-rate breaches are SIGNALS
// into the incident pipeline; the engine also closes the S43 what-if seam
// (SLO impact in failure simulations).

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/slo"
)

// BuildSLO loads the OpenSLO definitions and builds the engine. Returns
// (nil, false, nil) when disabled; a malformed definitions directory is a
// startup ERROR (an SLO the operator believes is tracked must actually be).
func BuildSLO(cfg *config.Config, log *slog.Logger) (*slo.Engine, bool, error) {
	if cfg == nil || !cfg.SLOEnabled {
		return nil, false, nil
	}
	defs, err := slo.LoadDir(cfg.SLODir)
	if err != nil {
		return nil, false, err
	}
	eng := slo.NewEngine(defs)
	if log != nil {
		names := make([]string, 0, len(defs))
		for _, d := range eng.SLOs() {
			names = append(names, d.Name)
		}
		log.Info("slo engine enabled", "slos", names)
	}
	return eng, true, nil
}

// WithSLO attaches the engine backing /v1/slos. nil is a no-op (the endpoint
// reports slo_running=false).
func (s *Server) WithSLO(e *slo.Engine) *Server {
	if e != nil {
		s.sloEngine = e
	}
	return s
}

// handleSLOs serves GET /v1/slos — the caller's tenant's SLO statuses:
// attainment, error budget remaining, multi-window burn rates.
func (s *Server) handleSLOs(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.sloEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"slo_running": false, "items": []slo.Status{}})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slo_running": true,
		"items":       s.sloEngine.Statuses(tid),
	})
	return nil
}

// handleSLOExport serves GET /v1/slos/openslo — the loaded definitions as an
// OpenSLO v1 YAML stream (lossless round-trip with other OpenSLO tooling).
// Definitions are deployment-level configuration; statuses are tenant-scoped.
func (s *Server) handleSLOExport(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	if s.sloEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"slo_running": false})
		return nil
	}
	w.Header().Set("Content-Type", "application/yaml")
	first := true
	for _, d := range s.sloEngine.SLOs() {
		out, err := d.Export()
		if err != nil {
			return err
		}
		if !first {
			if _, err := w.Write([]byte("---\n")); err != nil {
				return nil // client went away mid-stream
			}
		}
		first = false
		if _, err := w.Write(out); err != nil {
			return nil
		}
	}
	return nil
}

// SLOConsumer feeds the engine from the synthetic-result stream and exports
// burn-rate signals to the incident correlator.
type SLOConsumer struct {
	engine     *slo.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	log        *slog.Logger
	nsTenants  map[string]string // CORRECT-005: namespace -> tenant for siloed lanes
}

// NewSLOConsumer builds the consumer over a non-nil engine.
func NewSLOConsumer(b bus.Bus, e *slo.Engine, c *incident.Correlator, log *slog.Logger) *SLOConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &SLOConsumer{engine: e, bus: b, correlator: c, log: log}
}

// WithNamespaceTenants subscribes the consumer to each siloed tenant's
// namespaced results lane (CORRECT-005), so SLO burn-rate is evaluated for
// siloed tenants too — not just pooled ones.
func (sc *SLOConsumer) WithNamespaceTenants(ns map[string]string) *SLOConsumer {
	sc.nsTenants = ns
	return sc
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (sc *SLOConsumer) LaneFanoutEnabled() bool { return true }

// Run subscribes to the shared results topic plus every siloed-tenant lane
// until ctx ends (CORRECT-005).
func (sc *SLOConsumer) Run(ctx context.Context) error {
	return pipeline.RunLanes(ctx, sc.bus, bus.NetworkResultsTopic, "slo-results", sc.nsTenants, sc.handleLane)
}

func (sc *SLOConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		sc.log.Warn("slo: skipping malformed result", "error", err)
		return nil
	}
	tenant := r.GetTenantId()
	if laneTenant != "" {
		tenant = laneTenant // namespaced lane is authoritative (CORRECT-005)
	}
	if tenant == "" {
		return nil // unscoped records are dropped (guardrail 1)
	}
	sigs := sc.engine.ObserveResult(tenant, r.GetCanaryType(), r.GetServerAddress(),
		r.GetSuccess(), time.Unix(0, r.GetStartTimeUnixNano()))
	for _, sig := range sigs {
		if sc.correlator != nil {
			if _, err := sc.correlator.Ingest(ctx, sig); err != nil {
				sc.log.Warn("slo: correlate burn signal failed", "error", err)
			}
		}
		sc.log.Info("slo burn-rate signal raised",
			"tenant_id", sig.TenantID, "slo", sig.Attributes["slo.name"],
			"window", sig.Attributes["slo.window"], "burn", sig.Attributes["slo.burn_long"])
	}
	return nil
}
