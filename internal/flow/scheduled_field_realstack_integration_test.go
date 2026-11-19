// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/json"
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

func TestScheduledFieldEpisodeUsesShippedCollectorAndTenantStore(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "scheduledfield", TenantBand: 4, Env: map[string]string{"PROBECTL_ALERT_EVAL_INTERVAL": "1s"}})
	operator := st.OnboardOperator(t, "root@msp-fieldflow.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 182}, {name: "blue", octet: 182}}
	for _, lane := range lanes {
		lane.provision(t, st, operator, "field-"+run)
	}
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	var rules [2]alert.Rule
	var views [2]flow.SavedQueryView
	for i, lane := range lanes {
		replayScheduledFieldIPFIX(t, lane, windows, i == 0)
		waitScheduledFieldWireInputs(t, st, lane, windows, i == 0)
		plan := nativeGoldenPlan(lane.octet, windows.After.End, []string{"src_addr", "dst_port"})
		plan.DataSeries, plan.From, plan.To = "raw", windows.After.Start, windows.After.End
		lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
			Name: "Scheduled source " + lane.name, Visibility: "private", Plan: plan, Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 604800},
		}}, &views[i], http.StatusCreated)
		view := views[i]
		var primary string
		for _, m := range view.Definition.Plan.Metrics {
			if m.Role == "primary" {
				primary = m.Measure + ":" + m.Calculation
			}
		}
		if primary != "bytes:total" {
			t.Fatal("shipped field fixture needs exact original bytes", primary)
		}
		input := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version, Condition: alert.QueryCondition{Mode: alert.FieldChangeCondition,
			Field: &flow.FieldComparisonInput{Version: view.Version, Mode: "rank", Measure: primary, Cadence: "complete_week", TopKeys: 2, MinimumChange: "50"}}}
		lane.do(t, st, http.MethodPost, "/v1/alerts", map[string]any{"name": "Port field " + lane.name, "query_source": input}, &rules[i], http.StatusCreated)
	}
	for i, lane := range lanes {
		shipped.Await(t, "scheduled field comparison completed in its tenant", time.Minute, func() bool {
			code, raw := st.Do(t, lane.cookie, http.MethodGet, "/v1/alerts/rules/"+rules[i].ID+"/query-source", nil)
			var source alert.QuerySourceState
			return code == http.StatusOK && json.Unmarshal(raw, &source) == nil && source.NextAt != nil && source.NextAt.After(rules[i].UpdatedAt)
		})
	}
	fingerprint := fieldWireFingerprint(t, st, lanes[0], rules[0])
	if !alert.ValidFieldDigest(fingerprint) || fieldWireFingerprint(t, st, lanes[1], rules[1]) != "" {
		t.Fatal("the shipped worker must produce exactly one changed-tenant receipt")
	}
	path := "/v1/alerts/rules/" + rules[0].ID + "/field-receipt?fingerprint=" + fingerprint
	var fromAPI, fromCLI alert.FieldEvaluationEvidence
	lanes[0].do(t, st, http.MethodGet, path, nil, &fromAPI, http.StatusOK)
	lanes[1].do(t, st, http.MethodGet, path, nil, nil, http.StatusNotFound)
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lanes[0].apiToken}, &fromCLI, "alert", "field-receipt", rules[0].ID, "--query", "fingerprint="+fingerprint)
	for _, result := range []alert.FieldEvaluationEvidence{fromAPI, fromCLI} {
		comp := result.Comparison
		if comp.ViewID != views[0].ID || len(result.Signals) != 1 || len(comp.Changes) != 1 || !comp.Before.To.Equal(comp.After.From) ||
			comp.Before.To.Sub(comp.Before.From) != 7*24*time.Hour || comp.After.To.Sub(comp.After.From) != 7*24*time.Hour ||
			comp.Changes[0].Kind != "entered_top_set" || comp.Changes[0].Group["dst_port"] != "853" ||
			comp.Changes[0].Before != nil || comp.Changes[0].After == nil || comp.Changes[0].After.Value != "25000" ||
			comp.Before.LastIncluded != "" || comp.Before.FirstExcluded != "" || comp.After.LastIncluded != "25000" || comp.After.FirstExcluded != "10" {
			t.Fatal("the shipped flow client lost the original field receipt")
		}
		lanes[0].do(t, st, http.MethodGet, "/v1/incidents/"+result.Signals[0].IncidentID, nil, nil, http.StatusOK)
		lanes[1].do(t, st, http.MethodGet, "/v1/incidents/"+result.Signals[0].IncidentID, nil, nil, http.StatusNotFound)
	}
}

func fieldWireFingerprint(t *testing.T, st *shipped.Stack, lane *nativeLane, rule alert.Rule) string {
	t.Helper()
	var result alert.EvaluationsResult
	lane.do(t, st, http.MethodGet, "/v1/alerts/"+rule.ID+"/evaluations", nil, &result, http.StatusOK)
	var fingerprint string
	for _, entry := range result.Items {
		if entry.Reason == "Saved flow field changes" {
			if fingerprint != "" {
				t.Fatal("multiple copies of the same field episode were published")
			}
			fingerprint = entry.Fingerprint
		}
	}
	return fingerprint
}

func replayScheduledFieldIPFIX(t *testing.T, lane *nativeLane, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	connection, err := net.Dial("udp", lane.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	sequence := 0
	for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		at := window.Start.Add(3 * 24 * time.Hour)
		type fieldPacket struct {
			port   uint16
			amount uint64
		}
		items := []fieldPacket{{443, 30000}, {53, 10}}
		if changed && i == 1 {
			items = append(items, fieldPacket{853, 25000})
		}
		for _, item := range items {
			packet := seasonalFlowGolden(t, lane, at, sequence, item.port, item.amount)
			written, err := connection.Write(packet)
			if err != nil || written != len(packet) {
				t.Fatal("writing the complete controlled IPFIX observation failed", err)
			}
			sequence++
		}
	}
}

func waitScheduledFieldWireInputs(t *testing.T, st *shipped.Stack, lane *nativeLane, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	for i, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		plan := nativeGoldenPlan(lane.octet, window.End, []string{"dst_port"})
		plan.DataSeries, plan.From, plan.To = "raw", window.Start, window.End
		groups, amount := 2, "30010"
		if changed && i == 1 {
			groups, amount = 3, "55010"
		}
		shipped.Await(t, "complete signed source population in tenant ClickHouse", 45*time.Second, func() bool {
			code, raw := st.Do(t, lane.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
			var result struct {
				Flow *flowstore.PlanResult `json:"flow"`
			}
			return code == http.StatusOK && json.Unmarshal(raw, &result) == nil && result.Flow != nil && result.Flow.Coverage != nil &&
				result.Flow.Coverage.CompleteInputs && result.Flow.Source == "raw" && result.Flow.TotalGroups == groups && result.Flow.Totals["bytes:total"] == amount
		})
	}
}
