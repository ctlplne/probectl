// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
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

type ddosEdgeSampling int

const (
	ddosEdgeUnsampled ddosEdgeSampling = iota
	ddosEdgeRateChange
	ddosEdgeRateSetChange
	ddosEdgeSparseSampling
)

func TestFastDDoSSeparatesSyntheticEdgeRedistributionFromAggregateGrowth(t *testing.T) {
	testDDoSEdgeScope(t, false, false, ddosEdgeUnsampled)
}

func TestFastDDoSRequiresOriginalExporterCoverage(t *testing.T) {
	t.Run("legacy_partial_reference", func(t *testing.T) { testDDoSEdgeScope(t, true, false, ddosEdgeUnsampled) })
	t.Run("required_original_exporters", func(t *testing.T) { testDDoSEdgeScope(t, true, true, ddosEdgeUnsampled) })
}

func TestFastDDoSRequiresComparableRequiredExporterSampling(t *testing.T) {
	testDDoSEdgeScope(t, false, true, ddosEdgeRateChange)
}

func TestFastDDoSRequiresComparableDefaultExporterSampling(t *testing.T) {
	testDDoSEdgeScope(t, false, false, ddosEdgeRateChange)
}

func TestFastDDoSRequiresComparableAggregateSampling(t *testing.T) {
	testDDoSEdgeScope(t, false, false, ddosEdgeRateSetChange)
}

func TestFastDDoSRequiresOriginalRecordsFromTheSampledExporter(t *testing.T) {
	testDDoSEdgeScope(t, false, true, ddosEdgeSparseSampling)
}

func testDDoSEdgeScope(t *testing.T, partialReference, required bool, sampling ddosEdgeSampling) {
	t.Helper()
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
		seedDDoSEdgeRedistribution(t, rows, tenant, exporters, clocks, lane == 0, lane == 1 && partialReference, sampling)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		run := func(selected []string) (alert.RuleMetricRead, []alert.EvaluationReceipt, string, error) {
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
			if required {
				input.RequiredExporters = selected
			}
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
			return got, getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items, rule.ID, err
		}
		evaluated, items, id, err := run(exporters[:])
		if lane == 1 && (sampling == ddosEdgeRateChange || sampling == ddosEdgeRateSetChange) {
			if !errors.Is(err, errDDoSExporterSampling) || evaluated.QuerySelection != nil || len(items) != 0 {
				t.Fatal("a change in rates for the same two exporters advanced the detector or published an episode", err)
			}
			continue
		}
		if lane == 1 && sampling == ddosEdgeSparseSampling {
			if !errors.Is(err, errDDoSSampleCoverage) || evaluated.QuerySelection != nil || len(items) != 0 {
				t.Fatal("an unsampled edge supplied missing record support for the sampled estimate", err)
			}
			continue
		}
		if lane == 1 && partialReference && required {
			if !errors.Is(err, errDDoSExporterCoverage) || evaluated.QuerySelection != nil || len(items) != 0 {
				t.Fatal("a missing original exporter became a complete baseline or produced a receipt", err)
			}
			continue
		}
		if err != nil || evaluated.QuerySelection == nil || !evaluated.QuerySelection.Complete {
			t.Fatal("the exact selected observations must be complete", err)
		}
		if lane == 1 && partialReference {
			if len(evaluated.Samples) != 1 || len(items) != 1 {
				t.Fatal("legacy comparison did not reproduce the apparent aggregate growth")
			}
			continue
		}
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
			single, _, _, err := run(exporters[:1])
			if err != nil || len(single.Samples) != 1 {
				t.Fatal("the single-edge control did not observe the local surge")
			}
		}
	}
	var proof alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, receipt, nil, http.StatusOK)
	if err := json.Unmarshal(body, &proof); err != nil || proof.Current.Detection == nil ||
		proof.Current.Detection.Class != anomaly.DDoSReflection || proof.Current.Detection.Service != "dns" ||
		proof.Current.Before.Packets != "3600" || proof.Current.After.Packets != "7200" ||
		required && (proof.Current.Before.ObservedExporters != 2 || proof.Current.After.ObservedExporters != 2) ||
		sampling != ddosEdgeUnsampled && (!proof.Current.Before.Sampled || !proof.Current.After.Sampled) {
		t.Fatal("the assessed population lost the original aggregate clocks, vector or counters", err)
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, receipt, nil, http.StatusNotFound)
}

func seedDDoSEdgeRedistribution(t *testing.T, store flowstore.Store, tenant string, exporters [2]string, clocks ddosEpisodeClocks, growth, missingReferenceEdge bool, sampling ddosEdgeSampling) {
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
			if missingReferenceEdge && i == 1 {
				packets = [2]uint64{400, 3200}
			}
			rates := [2]uint64{1, 1}
			switch sampling {
			case ddosEdgeRateChange, ddosEdgeRateSetChange:
				rates = [2]uint64{1, 8}
				if !growth {
					// The reported sampling rates change while the original
					// per-exporter packet counts stay fixed.
					raw := [2]uint64{400, 100}
					if i == 1 {
						rates = [2]uint64{8, 1}
						if sampling == ddosEdgeRateSetChange {
							rates[1] = 8
						}
					}
					packets = [2]uint64{raw[0] * rates[0], raw[1] * rates[1]}
				}
			case ddosEdgeSparseSampling:
				rates = [2]uint64{1, 8}
				if !growth && i == 1 {
					packets = [2]uint64{400, 6800}
				}
			}
			sparse := sampling == ddosEdgeSparseSampling && !growth && i == 1
			for edge, exporter := range exporters {
				if missingReferenceEdge && i == 0 && edge == 1 {
					continue
				}
				rate := rates[edge]
				records := uint64(1)
				if rate > 1 && !sparse {
					records = 2
				}
				raw := packets[edge] / rate
				for index := range records {
					row := delayFixtureFlow(tenant, window.Start.Add(2*time.Second), false)
					row.Exporter, row.Transport, row.SrcPort, row.DstPort, row.TCPFlags = exporter, "udp", 53, 43001, 0
					row.SrcAddr = [...]string{"198.51.100.42", "198.51.100.43"}[index]
					row.Sampling, row.Packets = rate, raw/records
					if index < raw%records {
						row.Packets++
					}
					row.PacketsScaled = row.Packets * rate
					row.Bytes, row.BytesScaled = 100*row.Packets, 100*row.PacketsScaled
					rows = append(rows, row)
				}
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
