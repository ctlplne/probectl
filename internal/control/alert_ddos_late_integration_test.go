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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// This fixture withholds a synthetic stored observation, then delivers it
// after the next window has completed. The original clocks, authorization,
// storage and receipt still run through the live scheduled evaluator path.
func TestFastDDoSPreservesTheOriginalEpisodeWhenAnObservationArrivesOneWindowLate(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	const width = 5 * time.Second
	end := time.Now().UTC().Add(-30 * time.Second).Truncate(width)
	var rules [2]alert.Rule
	var delayed flowstore.Row
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Delayed original flow fixture")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		settings := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
			PeriodSeconds: 5, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
		source := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &settings}}
		body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": "Delayed original flow", "query_source": source}, http.StatusCreated)
		if err := json.Unmarshal(body, &rules[lane]); err != nil || rules[lane].ID == "" {
			t.Fatal("unable to bind the scoped rule", err)
		}
		var initial []flowstore.Row
		for offset := -2; offset <= 1; offset++ {
			at := end.Add(time.Duration(offset)*width - 2*time.Second)
			reference := delayFixtureFlow(tenant, at.AddDate(0, 0, -7), false)
			current := delayFixtureFlow(tenant, at, lane == 0 && (offset == -1 || offset == 0))
			initial = append(initial, reference)
			if lane == 0 && offset == 0 {
				delayed = current
				continue
			}
			initial = append(initial, current)
		}
		if err := rows.Insert(t.Context(), initial); err != nil {
			t.Fatal(err)
		}
	}
	read := func(lane int, at time.Time) (alert.RuleMetricRead, error) {
		t.Helper()
		rule := rules[lane]
		ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(rule.TenantID)), 8*time.Second)
		defer cancel()
		source, due, err := f.server.loadAlertQueryRule(ctx, rule, 1<<20)
		if err != nil || !due || source == nil {
			t.Fatal("unable to read the tenant's due rule and original state", err)
		}
		actor, err := source.Source.CredentialCeiling(rule.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		release, err := gate.BeginQuery(ctx, rule.TenantID)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		return f.server.readAlertDDoSRule(ctx, rule, *source, actor, flowstore.ExplorerQueryBudget(rows),
			AlertTagDependencies{IncidentWindow: time.Minute}, at)
	}
	for lane := range rules {
		got, err := read(lane, end.Add(-width+time.Second))
		if err != nil || got.QuerySelection == nil || !got.QuerySelection.At.Equal(end.Add(-width)) || len(got.Samples) != 0 {
			t.Fatal("the first synthetic pressure window should establish state without opening an episode", lane, got.QuerySelection, err)
		}
	}
	if result, err := read(0, end.Add(time.Second)); err == nil || result.QuerySelection != nil {
		t.Fatal("the absent observation became a complete evaluation", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		source, err := (store.AlertRules{}).GetQuerySource(ctx, sc, rules[0].ID, rules[0].UpdatedAt, 1<<20)
		if err != nil || source == nil || !source.State.At.Equal(end.Add(-width)) {
			t.Fatal("the absent window advanced durable state", err)
		}
		return nil
	})
	if err := rows.Insert(t.Context(), []flowstore.Row{delayed}); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		got, err := read(lane, end.Add(width+time.Second))
		if err != nil || got.QuerySelection == nil || (lane == 0 && (!got.QuerySelection.At.Equal(end) || len(got.Samples) != 1)) ||
			(lane == 1 && len(got.Samples) != 0) {
			t.Fatal("one-window-delayed observations must preserve the original positive episode and the quiet sibling", lane, got.QuerySelection, err)
		}
		var fingerprints []string
		for _, receipt := range getSeasonalFlowReceipts(t, server, f.tokens[tenant], rules[lane].ID).Items {
			if receipt.Reason == "Sustained flow traffic pressure" {
				fingerprints = append(fingerprints, receipt.Fingerprint)
			}
		}
		if lane == 1 && len(fingerprints) != 0 || lane == 0 && len(fingerprints) != 1 {
			t.Fatal("delayed observations changed the tenant episode count", lane, len(fingerprints))
		}
		if lane == 0 {
			path := "/v1/alerts/rules/" + rules[0].ID + "/ddos-receipt?fingerprint=" + fingerprints[0]
			var proof alert.DDoSEvaluationEvidence
			body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
			if err := json.Unmarshal(body, &proof); err != nil || !proof.Current.After.To.Equal(end) || !proof.Previous.After.To.Equal(end.Add(-width)) {
				t.Fatal("the delayed episode receipt used the delivery clock", err)
			}
			callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
			caughtUp, err := read(lane, end.Add(width+2*time.Second))
			if err != nil || caughtUp.QuerySelection == nil || !caughtUp.QuerySelection.At.Equal(end.Add(width)) || len(caughtUp.Samples) != 0 {
				t.Fatal("catch-up must resume current evaluation without emitting the recovered episode again", caughtUp.QuerySelection, err)
			}
			for _, receipt := range getSeasonalFlowReceipts(t, server, f.tokens[tenant], rules[0].ID).Items {
				if receipt.Reason == "Sustained flow traffic pressure" && receipt.Fingerprint != fingerprints[0] {
					t.Fatal("duplicate receipt after catch-up", receipt.Fingerprint)
				}
			}
		}
	}
}

func delayFixtureFlow(tenant string, at time.Time, pressure bool) flowstore.Row {
	row := flowstore.Row{TenantID: tenant, AgentID: "passive-assessment-source", Exporter: "203.0.113.15", Protocol: "ipfix",
		TS: at, StartTS: at.Add(-time.Second), SrcAddr: "198.51.100.42", DstAddr: "192.0.2.1", SrcPort: 42001, DstPort: 443,
		Transport: "tcp", TCPFlags: 16, Sampling: 1, Bytes: 90000, BytesScaled: 90000, Packets: 900, PacketsScaled: 900}
	if pressure {
		row.TCPFlags = 2
		row.Bytes, row.BytesScaled, row.Packets, row.PacketsScaled = 360000, 360000, 3600, 3600
	}
	return row
}
