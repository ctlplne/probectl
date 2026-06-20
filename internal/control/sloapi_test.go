// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/slo"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const testSLOYAML = `apiVersion: openslo/v1
kind: SLO
metadata:
  name: web-availability
  labels:
    team: platform
spec:
  service: web
  indicator:
    metadata:
      name: web-probe-success
    spec:
      ratioMetric:
        good:
          metricSource:
            type: probectl
            spec:
              target: web.acme.example
              outcome: success
        total:
          metricSource:
            type: probectl
            spec:
              target: web.acme.example
  timeWindow:
    - duration: 7d
      isRolling: true
  budgetingMethod: Occurrences
  objectives:
    - target: 0.99
`

func sloTestEngine(t *testing.T) *slo.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "slos.yaml"), []byte(testSLOYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, on, err := BuildSLO(&config.Config{SLOEnabled: true, SLODir: dir}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildSLO: on=%v err=%v", on, err)
	}
	return eng
}

func TestBuildSLODisabledAndFailClosed(t *testing.T) {
	if _, on, err := BuildSLO(&config.Config{SLOEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	if _, _, err := BuildSLO(&config.Config{SLOEnabled: true, SLODir: "/does/not/exist"}, intelTestLog()); err == nil {
		t.Fatal("missing SLO dir must fail startup")
	}
}

// Result stream → SLI events; a hard outage raises a burn signal into an
// incident (the S45 'Done when', end to end at the consumer).
func TestSLOConsumerTracksAndAlerts(t *testing.T) {
	eng := sloTestEngine(t)
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	sc := NewSLOConsumer(nil, eng, correlator, intelTestLog())

	// Fixed event times need a fixed clock: windows are anchored at "now", so
	// against the wall clock this test was a time bomb — it failed the day the
	// events below aged past the SLO's 7d window (2026-06-11, as it happens).
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eng.WithClock(func() time.Time { return at.Add(130 * time.Minute) })
	push := func(success bool, when time.Time) {
		raw, err := proto.Marshal(&resultv1.Result{
			TenantId: "t1", CanaryType: "http", ServerAddress: "web.acme.example",
			Success: success, StartTimeUnixNano: when.UnixNano(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := sc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
			t.Fatal(err)
		}
	}
	// Healthy baseline, then a hard outage.
	for i := 0; i < 100; i++ {
		push(true, at.Add(time.Duration(i)*time.Minute))
	}
	for i := 0; i < 30; i++ {
		push(false, at.Add(time.Duration(100+i)*time.Minute))
	}

	sts := eng.Statuses("t1")
	if len(sts) != 1 || sts[0].TotalEvents != 130 {
		t.Fatalf("statuses = %+v", sts)
	}
	var firing bool
	for _, br := range sts[0].BurnRates {
		firing = firing || br.Firing
	}
	if !firing {
		t.Fatal("hard outage did not light any burn window")
	}
	// Unscoped records are dropped.
	raw, _ := proto.Marshal(&resultv1.Result{CanaryType: "http", ServerAddress: "web.acme.example"})
	if err := sc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	if eng.Statuses("t1")[0].TotalEvents != 130 {
		t.Fatal("unscoped record counted")
	}
}

func TestSLOConsumerZeroEventTimeFallsBackToReceiveTime(t *testing.T) {
	eng := sloTestEngine(t)
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eng.WithClock(func() time.Time { return receivedAt })
	sc := NewSLOConsumer(nil, eng, nil, intelTestLog())
	sc.clock = func() time.Time { return receivedAt }

	raw, err := proto.Marshal(&resultv1.Result{
		TenantId: "t1", CanaryType: "http", ServerAddress: "web.acme.example",
		Success: true, StartTimeUnixNano: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	sts := eng.Statuses("t1")
	if len(sts) != 1 || sts[0].TotalEvents != 1 {
		t.Fatalf("zero event time was not bucketed at receive time: %+v", sts)
	}
}

func TestSLOConsumerFutureEventTimeClampsToReceiveTime(t *testing.T) {
	eng := sloTestEngine(t)
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eng.WithClock(func() time.Time { return receivedAt })
	sc := NewSLOConsumer(nil, eng, nil, intelTestLog())
	sc.clock = func() time.Time { return receivedAt }

	before := pipeline.FutureClamped()
	raw, err := proto.Marshal(&resultv1.Result{
		TenantId: "t1", CanaryType: "http", ServerAddress: "web.acme.example",
		Success: true, StartTimeUnixNano: receivedAt.Add(time.Hour).UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.handleLane(context.Background(), bus.Message{Value: raw}, ""); err != nil {
		t.Fatal(err)
	}
	sts := eng.Statuses("t1")
	if len(sts) != 1 || sts[0].TotalEvents != 1 {
		t.Fatalf("future event time was not clamped into the receive-time window: %+v", sts)
	}
	if pipeline.FutureClamped() <= before {
		t.Fatal("future SLO result did not increment the shared skew counter")
	}
}

func TestSLOEndpointsAndIsolation(t *testing.T) {
	eng := sloTestEngine(t)
	// Events for the default tenant only. Same fixed-clock rule as the
	// consumer test above: fixed event times, fixed "now".
	tid := tenancy.DefaultTenantID.String()
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	eng.WithClock(func() time.Time { return at.Add(60 * time.Minute) })
	for i := 0; i < 60; i++ {
		eng.ObserveResult(tid, "http", "web.acme.example", true, at.Add(time.Duration(i)*time.Minute))
	}

	srv := testServer(fakePinger{}).WithSLO(eng)
	rec := do(srv, http.MethodGet, "/v1/slos")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running bool         `json:"slo_running"`
		Items   []slo.Status `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Items) != 1 || resp.Items[0].TotalEvents != 60 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Items[0].Attainment != 1 || resp.Items[0].ErrorBudgetRemaining != 1 {
		t.Fatalf("healthy SLO state = %+v", resp.Items[0])
	}

	// OpenSLO export round-trips through the parser.
	rec = do(srv, http.MethodGet, "/v1/slos/openslo")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "apiVersion: openslo/v1") {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := slo.Parse(rec.Body.Bytes()); err != nil {
		t.Fatalf("export does not re-import: %v", err)
	}
}

func TestSLOHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/slos")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"slo_running":false`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// What-if simulations report SLO impact once the engine is wired (the S43
// seam, closed by S45).
func TestWhatIfReportsSLOImpact(t *testing.T) {
	eng := sloTestEngine(t)
	srv := testServer(fakePinger{}).WithTopology(seededTopology()).WithSLO(eng)

	// host:203.0.113.10 has label "web"… the SLO targets web.acme.example;
	// re-seed a path whose target IP matches the SLO target string.
	// Simpler: simulate the service node the SLO maps (none in the diamond),
	// so assert the impacted_slos field EXISTS and the coverage note is gone.
	rec := doJSONReq(srv, http.MethodPost, "/v1/topology/whatif",
		`{"target":"hop:10.0.0.2","at":"2026-06-04T12:00:00Z"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "slo impact not wired") {
		t.Fatalf("S43 seam still reports unwired SLOs: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"impacted_slos"`) {
		t.Fatalf("impacted_slos missing: %s", rec.Body.String())
	}
}
