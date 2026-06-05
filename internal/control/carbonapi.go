package control

// Carbon/power observability wiring (S48, F48): the estimation engine rides
// the SAME flow stream and attribution config as the FinOps engine, and
// serves the tenant's energy/carbon estimate at /v1/carbon. Local-only — no
// outbound calls; the grid intensity is operator-set config.

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/carbon"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
)

// BuildCarbon builds the engine from config. Returns (nil, false, nil) when
// disabled; malformed attribution config is a startup ERROR (fail closed —
// silently mis-attributed ESG numbers are worse than none).
func BuildCarbon(cfg *config.Config, log *slog.Logger) (*carbon.Engine, bool, error) {
	if cfg == nil || !cfg.CarbonEnabled {
		return nil, false, nil
	}
	zones, err := cost.ParseZoneRules(cfg.CostZones)
	if err != nil {
		return nil, false, err
	}
	owners, err := cost.ParseOwnerRules(cfg.CostServices)
	if err != nil {
		return nil, false, err
	}
	eng := carbon.NewEngine(cost.NewMapper(zones, owners), carbon.DefaultCoefficients(float64(cfg.CarbonGridGCO2E)))
	if log != nil {
		log.Info("carbon engine enabled", "grid_gco2e_per_kwh", cfg.CarbonGridGCO2E,
			"zones", len(zones), "owners", len(owners))
	}
	return eng, true, nil
}

// WithCarbon attaches the engine backing /v1/carbon. nil is a no-op (the
// endpoint reports carbon_running=false).
func (s *Server) WithCarbon(e *carbon.Engine) *Server {
	if e != nil {
		s.carbonEngine = e
	}
	return s
}

// handleCarbon serves GET /v1/carbon — the caller's tenant's estimated
// network energy/carbon with the methodology block.
func (s *Server) handleCarbon(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.carbonEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"carbon_running": false})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"carbon_running": true,
		"summary":        s.carbonEngine.Summary(tid),
	})
	return nil
}

// CarbonConsumer feeds the engine from the flow topic (own consumer group).
type CarbonConsumer struct {
	engine *carbon.Engine
	bus    bus.Bus
	log    *slog.Logger
}

// NewCarbonConsumer builds the consumer over a non-nil engine.
func NewCarbonConsumer(b bus.Bus, e *carbon.Engine, log *slog.Logger) *CarbonConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &CarbonConsumer{engine: e, bus: b, log: log}
}

// Run subscribes to the flow topic until ctx ends.
func (cc *CarbonConsumer) Run(ctx context.Context) error {
	return cc.bus.Subscribe(ctx, bus.FlowEventsTopic, "carbon-flow", cc.handle)
}

func (cc *CarbonConsumer) handle(_ context.Context, msg bus.Message) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("carbon: skipping malformed flow batch", "error", err)
		return nil
	}
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if tenant == "" {
			continue // unscoped records are dropped (guardrail 1)
		}
		at := time.Unix(0, f.GetEndUnixNano())
		if f.GetEndUnixNano() == 0 {
			at = time.Unix(0, f.GetObservedAtUnixNano())
		}
		cc.engine.Observe(tenant, cost.FlowSample{
			Src:   f.GetSourceAddress(),
			Dst:   f.GetDestinationAddress(),
			Bytes: f.GetBytes(),
			At:    at,
		})
	}
	return nil
}
