package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func costTestConfig() *config.Config {
	return &config.Config{
		CostEnabled:  true,
		CostPriced:   true,
		CostZones:    "10.0.1.0/24=us-east-1a,10.0.2.0/24=us-east-1b",
		CostServices: "10.0.1.0/24=checkout:payments",
		CostBudgets:  "team:payments=0.05",
	}
}

func TestBuildCostDisabledAndFailClosed(t *testing.T) {
	if _, on, err := BuildCost(&config.Config{CostEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	bad := costTestConfig()
	bad.CostZones = "not-a-rule"
	if _, _, err := BuildCost(bad, intelTestLog()); err == nil {
		t.Fatal("malformed zone rules must fail startup")
	}
	bad = costTestConfig()
	bad.CostPricesFile = "/does/not/exist.json"
	if _, _, err := BuildCost(bad, intelTestLog()); err == nil {
		t.Fatal("missing price file must fail startup")
	}
}

// Flow batch → attributed spend in the summary + a budget breach correlated
// into an incident (the S44 'Done when', end to end at the consumer).
func TestCostConsumerAttributesAndAlerts(t *testing.T) {
	eng, on, err := BuildCost(costTestConfig(), intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCost: %v", err)
	}
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	cc := NewCostConsumer(nil, eng, correlator, intelTestLog())

	// 10 GiB inter-AZ from checkout = $0.10 ≥ the $0.05 payments budget.
	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           "t1",
		SourceAddress:      "10.0.1.5",
		DestinationAddress: "10.0.2.7",
		Bytes:              10 << 30,
		EndUnixNano:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}, {
		// Unscoped record: dropped, never guessed into a tenant (guardrail 1).
		SourceAddress: "10.0.1.5", DestinationAddress: "10.0.2.7", Bytes: 1 << 30,
	}}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handle(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	s := eng.Summary("t1")
	if s.ByService["checkout"].USD < 0.09 || s.ByTeam["payments"].USD < 0.09 {
		t.Fatalf("attribution missing: %+v", s.ByService)
	}
	if len(s.Budgets) != 1 || !s.Budgets[0].Exceeded {
		t.Fatalf("budget status = %+v", s.Budgets)
	}
}

func TestCostSummaryEndpoint(t *testing.T) {
	eng, _, err := BuildCost(costTestConfig(), intelTestLog())
	if err != nil {
		t.Fatal(err)
	}
	// Spend for the DEFAULT tenant and for another tenant (isolation probe).
	eng.Observe(tenancy.DefaultTenantID.String(), cost.FlowSample{
		Src: "10.0.1.5", Dst: "10.0.2.7", Bytes: 10 << 30, At: time.Now()})
	eng.Observe("other-tenant", cost.FlowSample{
		Src: "10.0.1.9", Dst: "10.0.2.9", Bytes: 99 << 30, At: time.Now()})

	srv := testServer(fakePinger{}).WithCost(eng)
	rec := do(srv, http.MethodGet, "/v1/cost/summary")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Running bool         `json:"cost_running"`
		Summary cost.Summary `json:"summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || !resp.Summary.Priced || !resp.Summary.ZonesMapped {
		t.Fatalf("resp = %+v", resp)
	}
	// Only the caller's tenant's bytes (10 GiB, not 109 GiB).
	if resp.Summary.TotalBytes != 10<<30 {
		t.Fatalf("cross-tenant volume leaked: %d bytes", resp.Summary.TotalBytes)
	}
	if !strings.Contains(rec.Body.String(), "pricing_source") {
		t.Fatal("pricing provenance missing")
	}
}

func TestCostSummaryHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{}) // no WithCost
	rec := do(srv, http.MethodGet, "/v1/cost/summary")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cost_running":false`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
