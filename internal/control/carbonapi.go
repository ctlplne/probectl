// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

// Carbon/power observability wiring (S48, F48): the estimation engine rides
// the SAME flow stream and attribution config as the FinOps engine, and
// serves the tenant's energy/carbon estimate at /v1/carbon. Local-only — no
// outbound calls; the grid intensity is operator-set config.

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/carbon"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/cost"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
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
	engine    *carbon.Engine
	bus       bus.Bus
	log       *slog.Logger
	nsTenants map[string]string // CORRECT-005: namespace -> tenant for siloed lanes
	// RTP-02: the carbon consumer did NO tenant verification at all — a holder
	// of bus producer credentials could write arbitrary bytes into any tenant's
	// energy/carbon (ESG) accounting by claiming its tenant_id in the payload.
	// binding + strictLane bring it to the same fail-closed contract as the
	// flow store and the cost/compliance views; rejected counts the drops.
	binding    pipeline.TenantBinding // TENANT-101; nil = unit tests
	strictLane bool
	rejections *rejectionLogger
	rejected   atomic.Uint64
}

// NewCarbonConsumer builds the consumer over a non-nil engine.
func NewCarbonConsumer(b bus.Bus, e *carbon.Engine, log *slog.Logger) *CarbonConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &CarbonConsumer{engine: e, bus: b, log: log, rejections: newRejectionLogger(0)}
}

// WithNamespaceTenants subscribes the consumer to each siloed tenant's
// namespaced flow lane (CORRECT-005).
func (cc *CarbonConsumer) WithNamespaceTenants(ns map[string]string) *CarbonConsumer {
	cc.nsTenants = ns
	return cc
}

// WithTenantBinding attaches the registry-backed tenant verification
// (TENANT-101). Without it the carbon view trusts the payload tenant (RTP-02).
func (cc *CarbonConsumer) WithTenantBinding(b pipeline.TenantBinding) *CarbonConsumer {
	cc.binding = b
	return cc
}

// WithStrictTenantLanes refuses agent-published flow batches on the shared
// pooled lane (RTP-02, WIRE-001), requiring the tenant-namespaced lane.
func (cc *CarbonConsumer) WithStrictTenantLanes(strict bool) *CarbonConsumer {
	cc.strictLane = strict
	return cc
}

// RejectedFlowBatches reports how many flow batches the carbon consumer dropped
// for failing tenant verification (RTP-02).
func (cc *CarbonConsumer) RejectedFlowBatches() uint64 { return cc.rejected.Load() }

// LaneFanoutEnabled satisfies pipeline.LaneFanout (CORRECT-005 coverage gate).
func (cc *CarbonConsumer) LaneFanoutEnabled() bool { return true }

// Run subscribes to the shared flow topic plus every siloed-tenant lane until
// ctx ends (CORRECT-005).
func (cc *CarbonConsumer) Run(ctx context.Context) error {
	// DPR-080: a per-replica view group — every replica holds the full totals.
	return pipeline.RunLanes(ctx, cc.bus, bus.FlowEventsTopic, viewGroup("carbon-flow"), cc.nsTenants, cc.handleLane)
}

func (cc *CarbonConsumer) handleLane(ctx context.Context, msg bus.Message, laneTenant string) error {
	var batch flowv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		cc.log.Warn("carbon: skipping malformed flow batch", "error", err)
		return nil
	}
	// RTP-02 (docs/guardrails.md G7-1, fail closed): verify the batch identities
	// against the registry and the lane before any byte lands in a tenant's ESG
	// accounting. In strict-lane mode the shared pooled lane is refused outright
	// (even without a binding), so a forged registered pair cannot write another
	// tenant's carbon totals; a dropped batch is counted.
	if len(batch.GetFlows()) > 0 {
		ids := make([]pipeline.Identity, len(batch.GetFlows()))
		for i, f := range batch.GetFlows() {
			ids[i] = pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()}
		}
		if _, _, err := pipeline.VerifyBatchTenantStrict(ctx, cc.binding, laneTenant, cc.strictLane, ids); err != nil {
			cc.rejected.Add(1)
			cc.rejections.Log(cc.log, "REJECTED batch: tenant verification failed (TENANT-101, fail closed)",
				[]string{"carbon", "flow", ids[0].Tenant, ids[0].Agent, err.Error()},
				"view", "carbon", "claimed_tenant", ids[0].Tenant, "agent_id", ids[0].Agent,
				"lane_tenant", laneTenant, "rejected_total", cc.rejected.Load(), "error", err.Error())
			return nil
		}
	}
	for _, f := range batch.GetFlows() {
		tenant := f.GetTenantId()
		if laneTenant != "" {
			tenant = laneTenant // namespaced lane is authoritative (CORRECT-005)
		}
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
			Bytes: scaledFlowBytes(f),
			At:    at,
		})
	}
	return nil
}
