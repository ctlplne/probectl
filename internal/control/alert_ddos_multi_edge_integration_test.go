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

func TestFastDDoSSeparatesSyntheticEdgeRedistributionFromAggregateGrowth(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	const period = 5
	end := time.Now().UTC().Add(-20 * time.Second).Truncate(period * time.Second)
	clocks, err := ddosClocks(end, period)
	if err != nil {
		t.Fatal(err)
	}
	exporters := [2]string{"203.0.113.15", "203.0.113.16"}
	var receipt string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		seedDDoSEdgeRedistribution(t, rows, tenant, exporters, clocks, lane == 0)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		run := func(selected []string) (alert.RuleMetricRead, []alert.EvaluationReceipt, string) {
			t.Helper()
			label := "Both authorized edges"
			if len(selected) == 1 {
				label = "First authorized edge"
			}
			definition := fieldComparisonViewDefinition(label)
			definition.Time.LookbackSeconds = 60
			definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
				{Field: "exporter", Op: flow.QueryIn, Values: selected},
			}}
			view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
			if err != nil {
				t.Fatal(err)
			}
			input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
				PeriodSeconds: period, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
				VectorShareBasisPoints: 6000, MinObservedRecords: len(selected), MinObservedAddresses: 2}
			sourceInput := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
				Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
			body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts",
				map[string]any{"name": label, "query_source": sourceInput}, http.StatusCreated)
			var rule alert.Rule
			if err := json.Unmarshal(body, &rule); err != nil || rule.ID == "" {
				t.Fatal("could not configure the protected host", err)
			}
			source, due, err := f.server.loadAlertQueryRule(ctx, rule, 1<<20)
			if err != nil || !due || source == nil {
				t.Fatal("the saved rule was unavailable", err)
			}
			actor, err := source.Source.CredentialCeiling(tenant)
			if err != nil {
				t.Fatal(err)
			}
			release, err := gate.BeginQuery(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.server.readAlertDDoSRule(ctx, rule, *source, actor, flowstore.ExplorerQueryBudget(rows),
				AlertTagDependencies{IncidentWindow: time.Minute}, end.Add(time.Second))
			release()
			if err != nil || got.QuerySelection == nil || !got.QuerySelection.Complete {
				t.Fatal("the exact selected observations must be complete", err)
			}
			return got, getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items, rule.ID
		}
		evaluated, items, id := run(exporters[:])
		for _, item := range items {
			if item.Reason != "Sustained flow traffic pressure" {
				continue
			}
			if lane != 0 || receipt != "" {
				t.Fatal("redistributed traffic fired the aggregate detector or duplicated an original receipt")
			}
			receipt = "/v1/alerts/rules/" + id + "/ddos-receipt?fingerprint=" + item.Fingerprint
		}
		if lane == 0 && (len(evaluated.Samples) != 1 || receipt == "") ||
			lane == 1 && len(evaluated.Samples) != 0 {
			t.Fatal("the aggregate detector did not separate the planted traffic populations")
		}
		if lane == 1 {
			single, _, _ := run(exporters[:1])
			if len(single.Samples) != 1 {
				t.Fatal("the single-edge control did not observe the local surge")
			}
		}
	}
	var proof alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, receipt, nil, http.StatusOK)
	if err := json.Unmarshal(body, &proof); err != nil || proof.Current.Detection == nil ||
		proof.Current.Detection.Class != anomaly.DDoSReflection || proof.Current.Detection.Service != "dns" ||
		proof.Current.Before.Packets != "3600" || proof.Current.After.Packets != "7200" {
		t.Fatal("the assessed population lost the original aggregate clocks, vector or counters", err)
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, receipt, nil, http.StatusNotFound)
}

func seedDDoSEdgeRedistribution(t *testing.T, store flowstore.Store, tenant string, exporters [2]string, clocks ddosEpisodeClocks, growth bool) {
	t.Helper()
	var rows []flowstore.Row
	for _, pair := range []anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current} {
		for i, window := range []anomaly.TrainingWindow{pair.Before, pair.After} {
			packets := [2]uint64{400, 3200}
			if i == 1 {
				packets = [2]uint64{3200, 400}
				if growth {
					packets = [2]uint64{3600, 3600}
				}
			}
			for edge, exporter := range exporters {
				row := delayFixtureFlow(tenant, window.Start.Add(2*time.Second), false)
				row.Exporter, row.Transport, row.SrcPort, row.DstPort, row.TCPFlags = exporter, "udp", 53, 43001, 0
				row.Packets, row.PacketsScaled = packets[edge], packets[edge]
				row.Bytes, row.BytesScaled = 100*packets[edge], 100*packets[edge]
				rows = append(rows, row)
			}
			outside := delayFixtureFlow(tenant, window.Start.Add(2*time.Second), i == 1)
			outside.Exporter = "203.0.113.196"
			rows = append(rows, outside)
		}
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
}
