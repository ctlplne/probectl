// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
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
	binding    pipeline.TenantBinding // TENANT-101; nil = unit tests
	nsTenants  map[string]string
}

// NewCostConsumer builds the consumer over a non-nil engine.
func NewCostConsumer(b bus.Bus, e *cost.Engine, c *incident.Correlator, log *slog.Logger) *CostConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &CostConsumer{engine: e, bus: b, correlator: c, log: log}
}

// Run subscribes to the shared flow topic plus every siloed-tenant lane until ctx ends.
func (cc *CostConsumer) Run(ctx context.Context) error {
	return pipeline.RunLanes(ctx, cc.bus, bus.FlowEventsTopic, "cost-flow", cc.nsTenants, cc.handleLane)
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101).
func (cc *CostConsumer) WithTenantBinding(b pipeline.TenantBinding) *CostConsumer {
	cc.binding = b
	return cc
}

// WithNamespaceTenants subscribes the cost engine to each siloed tenant's flow lane.
func (cc *CostConsumer) WithNamespaceTenants(ns map[string]string) *CostConsumer {
	cc.nsTenants = ns
	return cc
}

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cc *CostConsumer) LaneFanoutEnabled() bool { return true }

func (cc *CostConsumer) handle(ctx context.Context, msg bus.Message) error {
	return cc.handleLane(ctx, msg, "")
}

func (cc *CostConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("cost: skipping malformed flow batch", "error", err)
		return nil
	}
	stampFlowBatchLaneTenant(&batch, laneTenant)
	if cc.binding != nil && len(batch.GetFlows()) > 0 {
		ids := make([]pipeline.Identity, len(batch.GetFlows()))
		for i, f := range batch.GetFlows() {
			ids[i] = pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
		}
		if _, _, err := pipeline.VerifyBatchTenant(ctx, cc.binding, "", ids); err != nil {
			cc.log.Error("REJECTED batch: tenant verification failed (TENANT-101, fail closed)",
				"view", "cost", "claimed_tenant", ids[0].Tenant, "agent_id", ids[0].Agent, "error", err.Error())
			return nil
		}
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
			Bytes: scaledFlowBytes(f),
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
