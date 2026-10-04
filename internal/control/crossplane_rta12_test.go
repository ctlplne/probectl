// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/carbon"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/cost"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestCrossPlaneFlowBatchPopulatesAllThreeEngines closes RTA-12. The live-stack
// probe saw EMPTY compliance verdicts / cost attribution / carbon estimate and
// read that as a gap; it was simply the no-traffic state. This replays ONE
// shared flow batch for a single tenant through the real production entry points
// — the compliance, cost and carbon bus consumers — and asserts all three HTTP
// read surfaces then report non-empty, tenant-scoped, cross-plane output for
// that tenant (and that a second tenant's traffic never bleeds into the first).
//
// Fail-before levers (each already guarded by a focused unit test, re-asserted
// here through one batch): flip the compliance verdict mapping, drop the cost
// budget latch, or change a carbon coefficient and the corresponding assertion
// below fails. The whole point is the "after traffic" population the live probe
// never produced because it sent no flows.
func TestCrossPlaneFlowBatchPopulatesAllThreeEngines(t *testing.T) {
	tid := tenancy.DefaultTenantID.String()
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	// Engines wired exactly as production builds them.
	comp := complianceTestEngine(t)
	costEng, on, err := BuildCost(costTestConfig(), intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCost: on=%v err=%v", on, err)
	}
	carbEng, on, err := BuildCarbon(&config.Config{CarbonEnabled: true, CarbonGridGCO2E: 400}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCarbon: on=%v err=%v", on, err)
	}

	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	compCons := NewComplianceConsumer(nil, comp, correlator, intelTestLog())
	costCons := NewCostConsumer(nil, costEng, correlator, intelTestLog())
	carbCons := NewCarbonConsumer(nil, carbEng, intelTestLog())

	// ONE batch, ONE tenant (RTP-02: batches are single-tenant), TWO flows that
	// between them light up all three planes:
	//   A: corp -> cde :443  => a compliance violation (and carbon bytes)
	//   B: 10 GiB inter-AZ from checkout => cost attribution + budget breach
	//      (checkout/payments budget 0.05; 10 GiB inter-AZ = $0.10) + carbon bytes
	const bytesA, bytesB = 4096, 10 << 30
	batch := func(tenant string) []byte {
		raw, mErr := proto.Marshal(&flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{
			{
				TenantId: tenant, SourceAddress: "10.20.1.5", DestinationAddress: "10.10.2.9",
				DestinationPort: 443, Bytes: bytesA, EndUnixNano: at.UnixNano(),
			},
			{
				TenantId: tenant, SourceAddress: "10.0.1.5", DestinationAddress: "10.0.2.7",
				Bytes: bytesB, EndUnixNano: at.UnixNano(),
			},
		}})
		if mErr != nil {
			t.Fatalf("marshal: %v", mErr)
		}
		return raw
	}

	feed := func(tenant string) {
		raw := batch(tenant)
		if err := compCons.handleFlow(context.Background(), bus.Message{Value: raw}); err != nil {
			t.Fatalf("compliance consume (%s): %v", tenant, err)
		}
		if err := costCons.handle(context.Background(), bus.Message{Value: raw}); err != nil {
			t.Fatalf("cost consume (%s): %v", tenant, err)
		}
		if err := carbCons.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
			t.Fatalf("carbon consume (%s): %v", tenant, err)
		}
	}

	// The caller's tenant AND a second tenant both send identical traffic; the
	// read surfaces below must still show only the caller's.
	feed(tid)
	feed("rta12-other-tenant")

	srv := testServer(fakePinger{}).WithCompliance(comp).WithCost(costEng).WithCarbon(carbEng)

	// --- compliance plane ---
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK {
		t.Fatalf("compliance status = %d body=%s", rec.Code, rec.Body.String())
	}
	var compResp struct {
		Running  bool                    `json:"compliance_running"`
		Items    []compliance.RuleResult `json:"items"`
		Coverage compliance.Coverage     `json:"coverage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &compResp); err != nil {
		t.Fatal(err)
	}
	if !compResp.Running || len(compResp.Items) == 0 {
		t.Fatalf("RTA-12: compliance must report results after traffic, got %+v", compResp)
	}
	sawViolation := false
	for _, it := range compResp.Items {
		if it.Verdict == compliance.VerdictViolation {
			sawViolation = true
		}
	}
	if !sawViolation {
		t.Fatalf("RTA-12: expected a compliance violation after the corp->cde flow, got %+v", compResp.Items)
	}
	// Isolation: only this tenant's single observation batch is counted, not the
	// other tenant's identical traffic.
	if compResp.Coverage.Observations != 2 {
		t.Fatalf("RTA-12: compliance observations leaked across tenants: %+v", compResp.Coverage)
	}

	// --- cost plane ---
	rec = do(srv, http.MethodGet, "/v1/cost/summary")
	if rec.Code != http.StatusOK {
		t.Fatalf("cost status = %d body=%s", rec.Code, rec.Body.String())
	}
	var costResp struct {
		Running bool         `json:"cost_running"`
		Summary cost.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &costResp); err != nil {
		t.Fatal(err)
	}
	if !costResp.Running || !costResp.Summary.Priced {
		t.Fatalf("RTA-12: cost must be running+priced after traffic, got %+v", costResp)
	}
	if costResp.Summary.ByService["checkout"].USD < 0.09 || costResp.Summary.ByTeam["payments"].USD < 0.09 {
		t.Fatalf("RTA-12: cost attribution missing after traffic: byService=%+v byTeam=%+v",
			costResp.Summary.ByService, costResp.Summary.ByTeam)
	}
	if len(costResp.Summary.Budgets) != 1 || !costResp.Summary.Budgets[0].Exceeded {
		t.Fatalf("RTA-12: cost budget breach signal missing: %+v", costResp.Summary.Budgets)
	}
	// Isolation: only this tenant's bytes (A+B), never doubled by the other tenant.
	if costResp.Summary.TotalBytes != bytesA+bytesB {
		t.Fatalf("RTA-12: cross-tenant cost volume leaked: got %d want %d",
			costResp.Summary.TotalBytes, bytesA+bytesB)
	}

	// --- carbon plane ---
	rec = do(srv, http.MethodGet, "/v1/carbon")
	if rec.Code != http.StatusOK {
		t.Fatalf("carbon status = %d body=%s", rec.Code, rec.Body.String())
	}
	var carbResp struct {
		Running bool           `json:"carbon_running"`
		Summary carbon.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &carbResp); err != nil {
		t.Fatal(err)
	}
	if !carbResp.Running || carbResp.Summary.TotalBytes != bytesA+bytesB {
		t.Fatalf("RTA-12: carbon must estimate exactly this tenant's %d bytes, got %+v",
			int64(bytesA+bytesB), carbResp.Summary)
	}
	if carbResp.Summary.Methodology.GridGCO2ePerKWh != 400 || carbResp.Summary.Methodology.Measured {
		t.Fatalf("RTA-12: carbon methodology block wrong: %+v", carbResp.Summary.Methodology)
	}
}
