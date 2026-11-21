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

func TestWeeklyDDoSReferenceRecoversOwnedEpisodeAndOriginalReport(t *testing.T) {
	testWeeklyDDoSReference(t, false, false)
}

func TestWeeklyDDoSRequiresIndependentContextForAContinuingVolumeTrend(t *testing.T) {
	t.Run("one protected address", func(t *testing.T) {
		testWeeklyDDoSReference(t, true, false)
	})
	t.Run("spread within a protected prefix", func(t *testing.T) {
		testWeeklyDDoSReference(t, true, true)
	})
}

func testWeeklyDDoSReference(t *testing.T, growing, spread bool) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	const width = 5 * time.Second
	end := time.Now().UTC().Add(-30 * time.Second).Truncate(width)

	read := func(rule alert.Rule) (alert.RuleMetricRead, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(tenancy.WithTenant(t.Context(), tenancy.ID(rule.TenantID)), 8*time.Second)
		defer cancel()
		budget := flowstore.ExplorerQueryBudget(rows)
		source, due, err := f.server.loadAlertQueryRule(ctx, rule, budget.MemoryBytes/8)
		if err != nil || !due || source == nil {
			t.Fatal("load scoped weekly detector", err)
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
		return f.server.readAlertDDoSRule(ctx, rule, *source, actor, budget, AlertTagDependencies{IncidentWindow: time.Minute}, end.Add(time.Second))
	}
	create := func(tenant, view, name string, input flow.DDoSAssessmentInput) alert.Rule {
		t.Helper()
		source := alert.QuerySourceInput{ViewID: view, ViewVersion: input.Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
		body := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": name, "query_source": source}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(body, &rule); err != nil || rule.ID == "" {
			t.Fatal("configure scoped weekly detector", err)
		}
		return rule
	}

	var representative [2]alert.Rule
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Weekly detector inputs")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		var population []flowstore.Row
		actualPackets := [5]uint64{6600, 4640, 3960, 3680, 3400}
		if lane == 1 {
			actualPackets[0] = 5200
		}
		for week := range actualPackets {
			if !growing && lane == 1 && week == 2 {
				continue
			}
			for _, clock := range []time.Time{end.Add(-width), end} {
				at := clock.AddDate(0, 0, -7*week).Add(-2 * time.Second)
				row := delayFixtureFlow(tenant, at, !growing && lane == 0 && week <= 1)
				if growing {
					row.Packets, row.PacketsScaled = actualPackets[week], actualPackets[week]
					if spread && week == 0 {
						row.Packets /= 2
						row.PacketsScaled = row.Packets
					}
					row.Bytes, row.BytesScaled = 100*row.Packets, 100*row.Packets
				}
				population = append(population, row)
				if spread && week == 0 {
					row.DstAddr = "192.0.2.2"
					population = append(population, row)
				}
			}
		}
		if err := rows.Insert(ctx, population); err != nil {
			t.Fatal(err)
		}
		input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
			PeriodSeconds: 5, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
		if spread {
			input.Prefix = "192.0.2.0/24"
		}
		if lane == 0 && !growing {
			priorWeek := create(tenant, view.ID, "Exact previous week", input)
			if result, err := read(priorWeek); err != nil || result.QuerySelection == nil || !result.QuerySelection.At.Equal(end) || len(result.Samples) != 0 {
				t.Fatal("the prior week's equal pressure should leave the legacy comparison quiet", err)
			}
		}
		input.ReferenceMode = flow.DDoSReferenceWeeklyRepresentative
		representative[lane] = create(tenant, view.ID, "Representative weekly evidence", input)
	}

	var fingerprint string
	for lane, rule := range representative {
		result, err := read(rule)
		if growing && lane == 1 {
			if !errors.Is(err, errDDoSTrendCoverage) || result.QuerySelection != nil {
				t.Fatal("a continuing weekly trend advanced the evaluator without independent corroboration", err)
			}
		} else if err != nil || result.QuerySelection == nil || !result.QuerySelection.At.Equal(end) || len(result.Samples) != 1-lane {
			t.Fatal("the weekly comparison lost the original clock or misclassified the tenant evidence", lane, result.Samples, err)
		}
		for _, item := range getSeasonalFlowReceipts(t, socket, f.tokens[rule.TenantID], rule.ID).Items {
			if item.Reason == "Sustained flow traffic pressure" {
				if lane != 0 || fingerprint != "" {
					t.Fatal("unexpected weekly-reference episode")
				}
				fingerprint = item.Fingerprint
			}
		}
	}
	if !alert.ValidFieldDigest(fingerprint) {
		t.Fatal("the selected week produced no retained receipt")
	}
	owned := representative[0]
	path := "/v1/alerts/rules/" + owned.ID + "/ddos-receipt?fingerprint=" + fingerprint
	var evidence alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, socket, f.tokens[owned.TenantID], http.MethodGet, path, nil, http.StatusOK)
	if err := json.Unmarshal(body, &evidence); err != nil || !evidence.Previous.Before.To.Equal(end.Add(-width).AddDate(0, 0, -14)) ||
		!evidence.Current.Before.To.Equal(end.AddDate(0, 0, -14)) || evidence.Current.ReferenceMode != flow.DDoSReferenceWeeklyRepresentative {
		t.Fatal("the episode lost the two selected original reference clocks", evidence, err)
	}
	if spread && (evidence.Current.Detection == nil || evidence.Current.Detection.Class != anomaly.DDoSPrefixSpread) {
		t.Fatal("acceleration above the same trend lost its destination-spread evidence")
	}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
	reportPath := "/v1/incidents/" + evidence.IncidentID + "/ddos-report?rule_id=" + owned.ID + "&fingerprint=" + fingerprint
	var report alert.DDoSReport
	wantBytes := "720000"
	if growing {
		wantBytes = "1320000"
	}
	body = callSeasonalAPI(t, socket, f.tokens[owned.TenantID], http.MethodGet, reportPath, nil, http.StatusOK)
	if err := json.Unmarshal(body, &report); err != nil || len(report.TopSources) != 1 || report.TopSources[0].Address != "198.51.100.42" ||
		report.TopSources[0].Bytes != wantBytes || report.ObservedSeconds != 10 {
		t.Fatal("the incident report did not re-read the selected original week and traffic", report, err)
	}
	callSeasonalAPI(t, socket, f.tokens[f.tenants[1]], http.MethodGet, reportPath, nil, http.StatusNotFound)
}
