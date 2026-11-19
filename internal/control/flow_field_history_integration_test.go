// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFieldHourlyHistoryReadsBothTenantCohortsFromClickHouse(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	metrics := tsdb.NewMemory()
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(metrics).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)

	at := time.Now()
	week, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldHourlyWeek, 3600)
	if err != nil {
		t.Fatal(err)
	}
	month, err := anomaly.FlowFieldCompletedWindows(at, anomaly.FlowFieldHourlyMonth, 3600)
	if err != nil {
		t.Fatal(err)
	}
	var selected [2]flow.SavedQueryView
	for i, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		draft, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: fieldHourlyPlanDefinition("Owned hourly egress")})
		if err != nil {
			t.Fatal(err)
		}
		selected[i] = draft
		seedFieldHourlyPlanRows(t, rows, tenant, month, i == 0)
	}
	read := func(tenant string, view flow.SavedQueryView, cadence anomaly.FlowFieldComparisonCadence, status int) []byte {
		t.Helper()
		input := flow.FieldComparisonInput{Version: view.Version, Mode: "rank", Cadence: string(cadence), PeriodSeconds: 3600,
			Measure: "bytes:total", TopKeys: 300, MinimumChange: "100"}
		return callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/explorer/flow-views/"+view.ID+"/field-comparison", input, status)
	}
	owned, stable := f.tenants[0], f.tenants[1]
	for i, cadence := range []anomaly.FlowFieldComparisonCadence{anomaly.FlowFieldHourlyWeek, anomaly.FlowFieldHourlyMonth} {
		clocks := []anomaly.FlowFieldComparisonClocks{week, month}[i]
		var changed, quiet flow.FieldComparison
		if err := json.Unmarshal(read(owned, selected[0], cadence, http.StatusOK), &changed); err != nil {
			t.Fatal(err)
		}
		want := 2
		if i == 1 {
			want = 1 // four weeks include the first hour in which port 8443 ranked
		}
		if changed.History == nil || changed.History.Hours != clocks.History.Samples || !changed.History.From.Equal(clocks.History.Start) ||
			len(changed.Changes) != want || changed.After.TotalGroups != 302 ||
			changed.After.LastIncluded != "700" || changed.After.FirstExcluded != "299" ||
			changed.Changes[0].Group["dst_port"] != "853" || changed.Changes[0].After == nil || changed.Changes[0].After.Value != "9007199254740993" {
			t.Fatal("complete admitted history or its exact top-300 boundary was lost", changed.History, changed.After, changed.Changes)
		}
		if err := json.Unmarshal(read(stable, selected[1], cadence, http.StatusOK), &quiet); err != nil || quiet.History == nil ||
			quiet.History.Hours != clocks.History.Samples || len(quiet.Changes) != 0 || quiet.ViewID != selected[1].ID {
			t.Fatal("stable sibling received the owned cohort or had no proof of its own history", err)
		}
		read(stable, selected[0], cadence, http.StatusNotFound)
		read(owned, selected[1], cadence, http.StatusNotFound)
	}
	proveHourlyScheduledFieldReceipt(t, f, socket, metrics, gate, selected, month)
}

func proveHourlyScheduledFieldReceipt(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, metrics *tsdb.Memory,
	gate *fairness.Gate, views [2]flow.SavedQueryView, clocks anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	var rules [2]alert.Rule
	var fingerprint string
	for i, tenant := range f.tenants {
		interval := int64(0)
		if i == 1 {
			interval = 7200
		}
		view := views[i]
		input := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version, EverySeconds: interval,
			Condition: alert.QueryCondition{Mode: alert.FieldChangeCondition, Field: &flow.FieldComparisonInput{
				Version: view.Version, Mode: "rank", Cadence: string(anomaly.FlowFieldHourlyMonth), PeriodSeconds: 3600,
				Measure: "bytes:total", TopKeys: 300, MinimumChange: "100",
			}}}
		token := f.tokens[tenant]
		raw := callSeasonalAPI(t, socket, token, http.MethodPost, "/v1/alerts", map[string]any{"name": "Hourly field membership", "query_source": input}, http.StatusCreated)
		if err := json.Unmarshal(raw, &rules[i]); err != nil || rules[i].ID == "" {
			t.Fatal("could not create the owned history schedule", err)
		}
		evaluate, ok := BuildAlertEvaluator(f.pool, metrics, alert.ChannelDeps{}, time.Minute, tenancy.ID(tenant), nil, f.server.log,
			AlertTagDependencies{Gate: gate, Queries: f.server, IncidentWindow: time.Minute})
		if !ok {
			t.Fatal("history evaluator is unavailable")
		}
		for range 2 {
			if err := evaluate.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		expected := time.Duration(max(3600, interval)) * time.Second
		raw = callSeasonalAPI(t, socket, token, http.MethodGet, "/v1/alerts/rules/"+rules[i].ID+"/query-source", nil, http.StatusOK)
		var source alert.QuerySourceState
		if err := json.Unmarshal(raw, &source); err != nil || source.NextAt == nil || !source.NextAt.Equal(clocks.After.End.Add(expected)) {
			t.Fatal("hourly source did not advance to its exact scheduled clock", err)
		}
		ledger := getSeasonalFlowReceipts(t, socket, token, rules[i].ID)
		fieldReceipts := 0
		for _, entry := range ledger.Items {
			if entry.Reason == "Saved flow field changes" {
				fieldReceipts++
				if i == 0 {
					fingerprint = entry.Fingerprint
				}
			}
		}
		if i == 0 && (fieldReceipts != 1 || !alert.ValidFieldDigest(fingerprint)) || i == 1 && fieldReceipts != 0 {
			t.Fatal("scheduled history duplicated a field episode or crossed tenants", fieldReceipts)
		}
	}
	path := "/v1/alerts/rules/" + rules[0].ID + "/field-receipt?fingerprint=" + fingerprint
	receipt := func(raw []byte) {
		t.Helper()
		var fact alert.FieldEvaluationEvidence
		if err := json.Unmarshal(raw, &fact); err != nil {
			t.Fatal(err)
		}
		assertScheduledFieldEvidence(t, fact, views[0].ID, clocks)
	}
	receipt(callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, path, nil, http.StatusOK))
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
	assertScheduledFieldClients(t, f, socket, rules[0].ID, fingerprint, views[0].ID, clocks, receipt)
}

func fieldHourlyPlanDefinition(name string) flow.QueryViewDefinition {
	definition := fieldComparisonViewDefinition(name)
	definition.Time.LookbackSeconds = 3600
	definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
		{Field: "src_addr", Op: flow.QueryEqual, Values: []string{"192.0.2.41"}},
	}}
	return definition
}

func seedFieldHourlyPlanRows(t *testing.T, store flowstore.Store, tenant string, clocks anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	var input []flowstore.Row
	for i, end := range clocks.Ends() {
		at := end.Add(-30 * time.Minute)
		add := func(port uint16, amount uint64) {
			input = append(input, flowstore.Row{TenantID: tenant, AgentID: "hourly-ranked-vantage", Exporter: "192.0.2.10", Protocol: "ipfix",
				TS: at, StartTS: at.Add(-time.Second), SrcAddr: "192.0.2.41", DstAddr: "198.51.100.42", DstPort: port, Transport: "tcp",
				Sampling: 1, Bytes: amount, BytesScaled: amount, Packets: 1, PacketsScaled: 1})
		}
		add(443, 299)
		add(53, 200)
		add(18001, 9007199254741993)
		input[len(input)-1].SrcAddr = "192.0.2.42"
		if changed && i == 0 {
			add(8443, 700)
		}
		if i == clocks.History.Samples-1 || i == clocks.History.Samples {
			for port := range 298 {
				add(uint16(10000+port), uint64(2000+port))
			}
		}
		if changed && i == clocks.History.Samples {
			add(853, 9007199254740993)
			add(8443, 700)
		}
	}
	if err := store.Insert(t.Context(), input); err != nil {
		t.Fatal(err)
	}
}
