// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The collector, bus, tenant runtime store, Explorer query and evaluator use
// shipped binaries. The packet contents replay a controlled retained history.
func TestSeasonalFlowBaselineUsesShippedCollectorAndTenantStore(t *testing.T) {
	proveShippedSeasonalFlow(t, "", anomaly.WeeklyTrainingWeeks)
}

func TestDailyFlowBaselineKeepsWholeHistoryOnShippedCollector(t *testing.T) {
	proveShippedSeasonalFlow(t, anomaly.SeasonalDaily, 7*anomaly.WeeklyTrainingWeeks)
}

func proveShippedSeasonalFlow(t *testing.T, cadence anomaly.SeasonalCadence, days int) {
	t.Helper()
	st := shipped.Start(t, shipped.Options{Name: "seasonalflow", TenantBand: 4, Env: map[string]string{"PROBECTL_ALERT_EVAL_INTERVAL": "1s"}})
	operator := st.OnboardOperator(t, "root@msp-seasonalflow.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 181}, {name: "blue", octet: 181}}
	for _, lane := range lanes {
		lane.provision(t, st, operator, "seasonal-"+run)
	}
	input, ends := seasonalWireCalendar(t, cadence, days)
	baseline := [2]uint64{10_000, 40_000}
	current := [2]uint64{25_000, 40_000}
	views := make([]flow.SavedQueryView, len(lanes))
	for i, lane := range lanes {
		replaySeasonalFlowGolden(t, lane, ends, baseline[i], current[i])
	}
	for i, lane := range lanes {
		waitSeasonalRawInputs(t, st, lane, ends, baseline[i], current[i])
		views[i] = saveSeasonalWireView(t, st, lane, ends[len(ends)-1])
	}
	rules := make([]alert.Rule, len(lanes))
	for i, lane := range lanes {
		input.Flow = &alert.SeasonalFlowInput{ViewID: views[i].ID, ViewVersion: views[i].Version, Measure: "bytes:total"}
		lane.do(t, st, http.MethodPost, "/v1/alerts", map[string]any{"name": "Retained flow " + lane.name, "seasonal_source": input}, &rules[i], http.StatusCreated)
	}
	for i, lane := range lanes {
		receipt := waitSeasonalWireReceipt(t, st, lane, rules[i], ends[len(ends)-1].Add(-time.Millisecond), baseline[i], current[i], i == 0, days)
		if receipt.Expectation.Seasonal.Calendar.Cadence != cadence || receipt.Expectation.Seasonal.Calendar.Provisional {
			t.Fatal("the shipped receipt did not retain its mature local calendar profile")
		}
		lane.do(t, st, http.MethodGet, "/v1/alerts/"+rules[1-i].ID+"/evaluations", nil, nil, http.StatusNotFound)
		assertSeasonalWireReceiptCLI(t, st, lane, rules[i], receipt)
		if receipt.Expectation.Seasonal.IncidentID != "" {
			lanes[1-i].do(t, st, http.MethodGet, "/v1/incidents/"+receipt.Expectation.Seasonal.IncidentID, nil, nil, http.StatusNotFound)
		}
	}
}

func seasonalWireCalendar(t *testing.T, cadence anomaly.SeasonalCadence, days int) (alert.SeasonalBaselineInput, []time.Time) {
	t.Helper()
	now := time.Now().UTC()
	zone := "UTC"
	if now.Minute() >= 30 {
		zone = "Asia/Kolkata" // keep the next completed local hour at least 30 minutes away
	}
	input := alert.SeasonalBaselineInput{Cadence: cadence, Timezone: zone, MinimumChange: 1000}
	model, err := input.Model()
	if err != nil {
		t.Fatal(err)
	}
	observed, end := model.LatestCompletedSlot(now)
	ends := append(model.ComparableCompleteEnds(observed), end)
	if len(ends) != days+1 {
		t.Fatalf("the complete history needs %d comparable dates", days)
	}
	return input, ends
}

func replaySeasonalFlowGolden(t *testing.T, lane *nativeLane, ends []time.Time, baseline, current uint64) {
	t.Helper()
	connection, err := net.Dial("udp", lane.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	for sequence, end := range ends {
		amount := baseline
		if sequence == len(ends)-1 {
			amount = current
		}
		packet := seasonalFlowGolden(t, lane, end.Add(-2*time.Minute), sequence, amount)
		written, err := connection.Write(packet)
		if err != nil || written != len(packet) {
			t.Fatal("writing the complete seasonal IPFIX golden datagram failed")
		}
	}
}

func seasonalFlowGolden(t *testing.T, lane *nativeLane, at time.Time, sequence int, amount uint64) []byte {
	t.Helper()
	address := [4]byte{10, byte(lane.octet), 19, 1}
	peer := [4]byte{10, byte(lane.octet), 19, 2}
	fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 8, 2, 8, 152, 8, 153, 8}
	template := nativeWire(t, uint16(290), uint16(len(fields)/2), fields)
	body := append(nativeWire(t, uint16(2), uint16(4+len(template))), template...)
	start, end := uint64(at.Add(-time.Second).UnixMilli()), uint64(at.UnixMilli())
	record := nativeWire(t, address, peer, uint16(42001), uint16(443), uint8(6), amount, uint64(5), start, end)
	body = append(body, nativeWire(t, uint16(290), uint16(4+len(record)), record)...)
	return append(nativeWire(t, uint16(10), uint16(16+len(body)), uint32(time.Now().Unix()), uint32(sequence), uint32(17)), body...)
}

func seasonalWirePlan(lane *nativeLane, end time.Time) flow.QueryPlan {
	plan := nativeGoldenPlan(lane.octet, end, []string{"protocol"})
	plan.DataSeries = "raw"
	plan.From, plan.To = end.Add(-10*time.Minute), end
	return plan
}

func waitSeasonalRawInputs(t *testing.T, st *shipped.Stack, lane *nativeLane, ends []time.Time, baseline, current uint64) {
	t.Helper()
	for i, end := range ends {
		amount := baseline
		if i == len(ends)-1 {
			amount = current
		}
		plan := seasonalWirePlan(lane, end)
		want := strconv.FormatUint(amount, 10)
		var status int
		var latest *flowstore.PlanResult
		var received bool
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			code, raw := st.Do(t, lane.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
			var out struct {
				Flow *flowstore.PlanResult `json:"flow"`
			}
			status = code
			if code == http.StatusOK && json.Unmarshal(raw, &out) == nil && out.Flow != nil {
				latest = out.Flow
				received = latest.Source == "raw" && latest.Coverage != nil && latest.Coverage.CompleteInputs &&
					latest.Totals["bytes:total"] == want && latest.Totals["flows:total"] == "1"
				if received {
					break
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		if received {
			continue
		}
		var details string
		if latest != nil {
			details = fmt.Sprintf("source=%s complete=%t bytes=%q flows=%q", latest.Source, latest.Coverage != nil && latest.Coverage.CompleteInputs,
				latest.Totals["bytes:total"], latest.Totals["flows:total"])
		}
		t.Fatalf("dated IPFIX input for %s at %s, expected one original of %s bytes, HTTP %d %s", lane.name, end.Format(time.RFC3339), want, status, details)
	}
}

func saveSeasonalWireView(t *testing.T, st *shipped.Stack, lane *nativeLane, end time.Time) flow.SavedQueryView {
	t.Helper()
	var view flow.SavedQueryView
	input := flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Retained IPFIX " + lane.name, Visibility: "private",
		Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 600}, Plan: seasonalWirePlan(lane, end)}}
	lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", input, &view, http.StatusCreated)
	return view
}

func waitSeasonalWireReceipt(t *testing.T, st *shipped.Stack, lane *nativeLane, rule alert.Rule, observed time.Time, baseline, current uint64, firing bool, days int) alert.EvaluationReceipt {
	t.Helper()
	var selected alert.EvaluationReceipt
	shipped.Await(t, "scheduled baseline of owned IPFIX history", time.Minute, func() bool {
		code, raw := st.Do(t, lane.cookie, http.MethodGet, "/v1/alerts/"+rule.ID+"/evaluations", nil)
		var receipts alert.EvaluationsResult
		if code != http.StatusOK || json.Unmarshal(raw, &receipts) != nil || len(receipts.Items) != 1 {
			return false
		}
		selected = receipts.Items[0]
		details := selected.Expectation.Seasonal
		if details == nil || details.Exact == nil || details.Exact.Current != strconv.FormatUint(current, 10) ||
			details.Exact.Median != strconv.FormatUint(baseline, 10) || !details.ObservedAt.Equal(observed) || len(details.Calendar.TrainingDays) != days || len(details.Citations) != 3 {
			return false
		}
		if firing {
			return selected.State == alert.EvaluationFiring && details.IncidentID != ""
		}
		return selected.State == alert.EvaluationNormal && details.IncidentID == ""
	})
	if firing {
		lane.do(t, st, http.MethodGet, "/v1/incidents/"+selected.Expectation.Seasonal.IncidentID, nil, nil, http.StatusOK)
	}
	return selected
}

func assertSeasonalWireReceiptCLI(t *testing.T, st *shipped.Stack, lane *nativeLane, rule alert.Rule, expected alert.EvaluationReceipt) {
	t.Helper()
	var result alert.EvaluationsResult
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &result, "alert", "evaluations", rule.ID)
	if len(result.Items) != 1 || result.Items[0].Expectation.Seasonal == nil || result.Items[0].Expectation.Seasonal.Exact == nil ||
		result.Items[0].Expectation.Seasonal.IncidentID != expected.Expectation.Seasonal.IncidentID ||
		result.Items[0].Expectation.Seasonal.Exact.Current != expected.Expectation.Seasonal.Exact.Current {
		t.Fatalf("release CLI lost the complete original receipt for %s", lane.name)
	}
}
