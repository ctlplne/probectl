package control

// FinOps / egress-cost wiring (S44, F41): the cost engine consumes the flow
// stream the control plane already receives, attributes volume × public
// pricing to services/teams, and serves the summary at /v1/cost/summary.
// Budget breaches are SIGNALS into the incident pipeline (guardrail 9) —
// probectl never throttles traffic or touches the cloud bill.

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// BuildCost builds the engine from config. Returns (nil, false, nil) when
// disabled; malformed zone/owner/budget/pricing config is a startup ERROR
// (fail closed — silently mispriced cost data is worse than none).
func BuildCost(cfg *config.Config, log *slog.Logger) (*cost.Engine, bool, error) {
	if cfg == nil || !cfg.CostEnabled {
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
	budgets, err := cost.ParseBudgets(cfg.CostBudgets)
	if err != nil {
		return nil, false, err
	}
	var prices *cost.PriceTable
	if cfg.CostPriced {
		prices, err = cost.LoadPriceTable(cfg.CostPricesFile)
		if err != nil {
			return nil, false, err
		}
	}
	eng := cost.NewEngine(cost.NewMapper(zones, owners), prices, budgets)
	if log != nil {
		log.Info("cost engine enabled",
			"zones", len(zones), "owners", len(owners), "budgets", len(budgets),
			"priced", prices != nil)
	}
	return eng, true, nil
}

// WithCost attaches the engine backing /v1/cost/summary. nil is a no-op
// (the endpoint reports cost_running=false).
func (s *Server) WithCost(e *cost.Engine) *Server {
	if e != nil {
		s.costEngine = e
	}
	return s
}

// handleCostSummary serves GET /v1/cost/summary — the caller's tenant's
// attributed spend, chatty pairs, trend, and budget status.
func (s *Server) handleCostSummary(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.costEngine == nil {
		writeJSON(w, http.StatusOK, map[string]any{"cost_running": false})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cost_running": true,
		"summary":      s.costEngine.Summary(tid),
	})
	return nil
}

// CostConsumer feeds the engine from the flow topic and exports budget
// signals to the incident correlator.
type CostConsumer struct {
	engine     *cost.Engine
	bus        bus.Bus
	correlator *incident.Correlator
	log        *slog.Logger
}

// NewCostConsumer builds the consumer over a non-nil engine.
func NewCostConsumer(b bus.Bus, e *cost.Engine, c *incident.Correlator, log *slog.Logger) *CostConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &CostConsumer{engine: e, bus: b, correlator: c, log: log}
}

// Run subscribes to the flow topic (own consumer group) until ctx ends.
func (cc *CostConsumer) Run(ctx context.Context) error {
	return cc.bus.Subscribe(ctx, bus.FlowEventsTopic, "cost-flow", cc.handle)
}

func (cc *CostConsumer) handle(ctx context.Context, msg bus.Message) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("cost: skipping malformed flow batch", "error", err)
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
		sigs := cc.engine.Observe(tenant, cost.FlowSample{
			Src:   f.GetSourceAddress(),
			Dst:   f.GetDestinationAddress(),
			Bytes: f.GetBytes(),
			At:    at,
		})
		for _, sig := range sigs {
			if cc.correlator != nil {
				if _, err := cc.correlator.Ingest(ctx, sig); err != nil {
					cc.log.Warn("cost: correlate budget signal failed", "error", err)
				}
			}
			cc.log.Info("cost budget signal raised",
				"tenant_id", sig.TenantID, "target", sig.Target,
				"spent", sig.Attributes["cost.spent_usd"], "budget", sig.Attributes["cost.budget_usd"])
		}
	}
	return nil
}
