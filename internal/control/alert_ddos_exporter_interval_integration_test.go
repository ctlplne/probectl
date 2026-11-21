// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFastDDoSExporterIntervalsRequireIndependentSupport(t *testing.T) {
	t.Run("legacy clock metadata", func(t *testing.T) { testExporterIntervals(t, false) })
	t.Run("original clock metadata", func(t *testing.T) { testExporterIntervals(t, true) })
}

// Every input is a synthetic flow record.
func testExporterIntervals(t *testing.T, originalClocks bool) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	const period = 5
	end := time.Now().UTC().Add(-45 * time.Second).Truncate(period * time.Second)
	clocks, err := ddosClocks(end, period)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
	}
	var ownReceipt [2]string
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		original := exporterIntervalFlowRows(tenant, clocks, lane == 1, originalClocks)
		if err := rows.Insert(ctx, original); err != nil {
			t.Fatal(err)
		}
		definition := fieldComparisonViewDefinition("Protected exporter interval")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		input := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version, Condition: alert.QueryCondition{
			Mode: alert.DDoSCondition, DDoS: &flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
				PeriodSeconds: period, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
				VectorShareBasisPoints: 6000, MinObservedRecords: 6, MinObservedAddresses: 2},
		}}
		created := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts", map[string]any{
			"name": "Exporter interval diagnostic", "query_source": input,
		}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(created, &rule); err != nil || rule.ID == "" {
			t.Fatal("create scoped interval diagnostic rule", err)
		}
		read := func(end time.Time) (alert.RuleMetricRead, error) {
			t.Helper()
			ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			source, due, err := f.server.loadAlertQueryRule(ctx, rule, 1<<20)
			if err != nil || !due || source == nil {
				t.Fatal("load scoped interval diagnostic rule", err)
			}
			actor, err := source.Source.CredentialCeiling(tenant)
			if err != nil {
				t.Fatal(err)
			}
			release, err := gate.BeginQuery(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			return f.server.readAlertDDoSRule(ctx, rule, *source, actor, flowstore.ExplorerQueryBudget(rows),
				AlertTagDependencies{IncidentWindow: time.Minute}, end.Add(time.Second))
		}
		if originalClocks && lane == 1 {
			ownReceipt[lane] = checkExporterTimingRecovery(t, f, rows, server, rule, end, read)
			continue
		}
		got, err := read(end)
		items := getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items
		if err != nil || got.QuerySelection == nil || !got.QuerySelection.Complete || len(got.Samples) != 1 {
			t.Fatal("expected a scoped pressure episode with independent original counts", lane, err)
		}
		if len(items) != 1 || items[0].Reason != "Sustained flow traffic pressure" || !alert.ValidFieldDigest(items[0].Fingerprint) {
			t.Fatal("missing original end-bucket receipt", lane, len(items))
		}
		ownReceipt[lane] = "/v1/alerts/rules/" + rule.ID + "/ddos-receipt?fingerprint=" + items[0].Fingerprint
		body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodGet, ownReceipt[lane], nil, http.StatusOK)
		var evidence alert.DDoSEvaluationEvidence
		if err := json.Unmarshal(body, &evidence); err != nil {
			t.Fatal(err)
		}
		packets, bytes, records := "7200", "720000", 6
		if originalClocks {
			packets, bytes, records = "8600", "860000", 7
		}
		for index, observed := range []flow.DDoSAssessment{evidence.Previous, evidence.Current} {
			comparison := [2]anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current}[index]
			if observed.Before.Packets != "3600" || observed.Before.Bytes != "360000" ||
				observed.After.Packets != packets || observed.After.Bytes != bytes || observed.After.ObservedRecords != records ||
				!observed.Before.From.Equal(comparison.Before.Start) || !observed.After.From.Equal(comparison.After.Start) ||
				!observed.After.To.Equal(comparison.After.End) || observed.Detection == nil || observed.Detection.Class != anomaly.DDoSVolumetric {
				t.Fatal("the receipt did not use the original projected clocks, counts and classification", lane, index, observed)
			}
		}
		if lane == 1 {
			// Exercise an older receipt against the same original rows with
			// newly available clock provenance. Re-measure its saved totals.
			annotated := exporterIntervalFlowRows(tenant, clocks, true, true)
			if err := rows.Insert(ctx, annotated); err != nil {
				t.Fatal(err)
			}
		}
		reportPath := fmt.Sprintf("/v1/incidents/%s/ddos-report?rule_id=%s&fingerprint=%s", evidence.IncidentID, rule.ID, items[0].Fingerprint)
		reportBody := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodGet, reportPath, nil, http.StatusOK)
		var report alert.DDoSReport
		if err := json.Unmarshal(reportBody, &report); err != nil || report.PeakPacketRate.Count != packets || report.PeakPacketRate.Seconds != period ||
			len(report.TopSources) != 1 || report.TopSources[0].Address != "198.51.100.42" {
			t.Fatal("the incident report lost the saved end-time totals or original scoped source", report, err)
		}
		callSeasonalAPI(t, server, f.tokens[f.tenants[1-lane]], http.MethodGet, reportPath, nil, http.StatusNotFound)
	}
	for lane, tenant := range f.tenants {
		if sibling := ownReceipt[1-lane]; sibling != "" {
			callSeasonalAPI(t, server, f.tokens[tenant], http.MethodGet, sibling, nil, http.StatusNotFound)
		}
	}
}

func checkExporterTimingRecovery(t *testing.T, f *roleExplanationAPIFixture, rows flowstore.Store, server *httptest.Server, rule alert.Rule, end time.Time,
	read func(time.Time) (alert.RuleMetricRead, error)) string {
	t.Helper()
	const seconds = 5
	const period = seconds * time.Second
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(rule.TenantID))
	quietEnd := end.Add(-2 * period)
	quiet, err := ddosClocks(quietEnd, seconds)
	if err != nil {
		t.Fatal(err)
	}
	quietRows := exporterIntervalFlowRows(rule.TenantID, quiet, false, false)
	for i := range quietRows {
		quietRows[i].Packets, quietRows[i].PacketsScaled = 600, 600
		quietRows[i].Bytes, quietRows[i].BytesScaled = 60000, 60000
		quietRows[i].ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
	}
	if err := rows.Insert(ctx, quietRows); err != nil {
		t.Fatal(err)
	}
	initial, err := read(quietEnd)
	if err != nil || initial.QuerySelection == nil || !initial.QuerySelection.At.Equal(quietEnd) || len(initial.Samples) != 0 {
		t.Fatal("the quiet control did not establish the original watermark", initial, err)
	}
	// A fresh contained pair arrives after the two ambiguous windows.
	recoveredEnd := end.Add(2 * period)
	recovered, err := ddosClocks(recoveredEnd, seconds)
	if err != nil {
		t.Fatal(err)
	}
	if err := rows.Insert(ctx, exporterIntervalFlowRows(rule.TenantID, recovered, false, true)); err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []time.Time{end.Add(-period), end, end.Add(period)} {
		got, err := read(boundary)
		if !errors.Is(err, errDDoSTimingCoverage) || got.QuerySelection != nil || len(got.Samples) != 0 {
			t.Fatal("a whole crossing interval opened a short episode or established a complete window", boundary, got, err)
		}
	}
	f.in(rule.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		source, err := (store.AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, 1<<20)
		if err != nil || source == nil || !source.State.At.Equal(quietEnd) || len(source.State.Keys) != 0 {
			t.Fatal("timing uncertainty changed the durable watermark or active groups", err)
		}
		return nil
	})
	if receipts := getSeasonalFlowReceipts(t, server, f.tokens[rule.TenantID], rule.ID).Items; len(receipts) != 0 {
		t.Fatal("timing uncertainty published a receipt", len(receipts))
	}
	got, err := read(recoveredEnd)
	if err != nil || got.QuerySelection == nil || !got.QuerySelection.At.Equal(recoveredEnd) || len(got.Samples) != 1 {
		t.Fatal("valid adjacent windows failed to recover after the earlier timing uncertainty", got, err)
	}
	items := getSeasonalFlowReceipts(t, server, f.tokens[rule.TenantID], rule.ID).Items
	if len(items) != 1 || !alert.ValidFieldDigest(items[0].Fingerprint) {
		t.Fatal("the recovered pair must open one owned receipt", len(items))
	}
	path := "/v1/alerts/rules/" + rule.ID + "/ddos-receipt?fingerprint=" + items[0].Fingerprint
	var evidence alert.DDoSEvaluationEvidence
	if err := json.Unmarshal(callSeasonalAPI(t, server, f.tokens[rule.TenantID], http.MethodGet, path, nil, http.StatusOK), &evidence); err != nil || !evidence.Previous.After.To.Equal(recoveredEnd.Add(-period)) || !evidence.Current.After.To.Equal(recoveredEnd) {
		t.Fatal("the recovered receipt used an earlier ambiguous clock", evidence, err)
	}
	continuedEnd := recoveredEnd.Add(period)
	continued, err := ddosClocks(continuedEnd, seconds)
	if err != nil {
		t.Fatal(err)
	}
	if err := rows.Insert(ctx, exporterIntervalFlowRows(rule.TenantID, continued, false, true)); err != nil {
		t.Fatal(err)
	}
	got, err = read(continuedEnd)
	if err != nil || got.QuerySelection == nil || !got.QuerySelection.At.Equal(continuedEnd) || len(got.Samples) != 1 {
		t.Fatal("the recovered episode should remain active as the next window qualifies", got, err)
	}
	continuedReceipts := getSeasonalFlowReceipts(t, server, f.tokens[rule.TenantID], rule.ID).Items
	if len(continuedReceipts) != 1 || continuedReceipts[0].Fingerprint != items[0].Fingerprint {
		t.Fatal("continuing the recovered episode duplicated or replaced its original receipt", len(continuedReceipts))
	}
	return path
}

func exporterIntervalFlowRows(tenant string, windows ddosEpisodeClocks, spansSeveralWindows, originalClocks bool) []flowstore.Row {
	var rows []flowstore.Row
	for _, comparison := range []anomaly.FlowFieldComparisonClocks{windows.Previous, windows.Current} {
		for side, window := range []anomaly.TrainingWindow{comparison.Before, comparison.After} {
			packets, duration := uint64(600), 750*time.Millisecond
			if side == 1 {
				packets = 1200
				if spansSeveralWindows {
					duration = 20 * time.Second
				}
			}
			for index := range 6 {
				// Both lanes have the same end clocks, including the cases
				// where the start clock predates the comparison window.
				at := window.Start.Add(time.Duration(index+1) * 750 * time.Millisecond)
				row := delayFixtureFlow(tenant, at, false)
				row.StartTS = at.Add(-duration)
				if originalClocks {
					row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
				}
				row.Packets, row.PacketsScaled = packets, packets
				row.Bytes, row.BytesScaled = packets*100, packets*100
				rows = append(rows, row)
			}
			if originalClocks && side == 1 && !spansSeveralWindows {
				// This has the exact same network grouping as the six fully
				// contained records. Its timing cannot consume their support.
				at := window.Start.Add(4750 * time.Millisecond)
				row := delayFixtureFlow(tenant, at, false)
				row.StartTS = at.Add(-20 * time.Second)
				row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
				row.Packets, row.PacketsScaled = 1400, 1400
				row.Bytes, row.BytesScaled = 140000, 140000
				rows = append(rows, row)
			}
		}
	}
	return rows
}
