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
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFastDDoSKeepsEpisodeThroughAnUndersampledWindow(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: errDDoSSampleCoverage, rate: 8})
}

func TestFastDDoSKeepsEpisodeThroughInvalidSamplingWindow(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: errDDoSCounterIntegrity, rate: 8})
}

func TestFastDDoSKeepsEpisodeThroughSparseUnsampledPressure(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: anomaly.ErrDDoSRecordSupport, rate: 1})
}

func TestFastDDoSKeepsEpisodeThroughSparseUnsampledQuiet(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: anomaly.ErrDDoSRecordSupport, rate: 1, sparseQuiet: true})
}

func TestFastDDoSDoesNotReopenOnChangingPressureClass(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{rate: 8})
}

func TestFastDDoSKeepsEpisodeThroughQuietTotalsFromCrossingIntervals(t *testing.T) {
	t.Run("sampled", func(t *testing.T) {
		testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: errDDoSTimingCoverage, rate: 8})
	})
	t.Run("unsampled", func(t *testing.T) {
		testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: errDDoSTimingCoverage, rate: 1})
	})
}

func TestFastDDoSKeepsEpisodeThroughContainedSYNPressure(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: errDDoSTimingCoverage, rate: 1, containedSYN: true})
}

func TestFastDDoSKeepsEpisodeThroughUnclassifiedMixedHistory(t *testing.T) {
	testFastDDoSContinuesEpisode(t, ddosContinuityScenario{gap: anomaly.ErrDDoSMixedHistory, rate: 1})
}

type ddosContinuityScenario struct {
	gap          error
	rate         uint64
	containedSYN bool
	sparseQuiet  bool
}

func testFastDDoSContinuesEpisode(t *testing.T, scenario ddosContinuityScenario) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)

	const period = 5
	const width = period * time.Second
	end := time.Now().UTC().Add(-45 * time.Second).Truncate(width)
	var path string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Sampled protected host")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress",
			PeriodSeconds: period, BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 4, MinObservedAddresses: 2, RequiredExporters: []string{"203.0.113.15"}}
		source := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
		body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": "Sampled protected host", "query_source": source}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(body, &rule); err != nil || rule.ID == "" {
			t.Fatal("could not bind the sampled rule", err)
		}
		seedDDoSContinuityWindows(t, rows, tenant, end, width, lane == 0, scenario)
		wantSamples := 0
		if lane == 0 {
			wantSamples = 1
		}
		for offset := range 4 {
			// Read the current durable state again, as another scheduler would.
			state, due, err := f.server.loadAlertQueryRule(ctx, rule, 1<<20)
			if err != nil || !due || state == nil {
				t.Fatal("could not load the saved rule", offset, err)
			}
			if lane == 0 && offset > 0 {
				wantPrevious := end
				if scenario.gap == nil {
					wantPrevious = end.Add(time.Duration(offset-1) * width)
				}
				if !state.State.At.Equal(wantPrevious) || len(state.State.Keys) != 1 {
					t.Fatal("the evaluation failed to preserve the active episode and its original clock", offset, state.State)
				}
			}
			actor, err := state.Source.CredentialCeiling(tenant)
			if err != nil {
				t.Fatal(err)
			}
			release, err := gate.BeginQuery(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			windowEnd := end.Add(time.Duration(offset) * width)
			got, err := f.server.readAlertDDoSRule(ctx, rule, *state, actor, flowstore.ExplorerQueryBudget(rows),
				AlertTagDependencies{IncidentWindow: time.Minute}, windowEnd.Add(time.Second))
			release()
			if lane == 0 && scenario.gap != nil && (offset == 1 || offset == 2) {
				if !errors.Is(err, scenario.gap) || got.QuerySelection != nil {
					t.Fatal("incomplete observations were interpreted as quiet coverage", offset, err)
				}
				continue
			}
			if err != nil || got.QuerySelection == nil || !got.QuerySelection.At.Equal(windowEnd) || len(got.Samples) != wantSamples {
				t.Fatal("a well-supported window failed to advance the owned rule", lane, offset, err)
			}
		}
		items := getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items
		if len(items) != wantSamples {
			t.Fatal("continuing pressure changed the receipt count", lane, len(items))
		}
		if lane == 0 {
			path = "/v1/alerts/rules/" + rule.ID + "/ddos-receipt?fingerprint=" + items[0].Fingerprint
			body = callSeasonalAPI(t, server, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
			var proof alert.DDoSEvaluationEvidence
			if err := json.Unmarshal(body, &proof); err != nil || !proof.Current.After.To.Equal(end) ||
				proof.Current.After.Sampled != (scenario.rate > 1) || proof.Current.After.ObservedRecords != 4 || proof.Current.After.Packets != "6400" {
				t.Fatal("the original episode receipt lost its sampling or original record evidence", err)
			}
			if scenario.gap == anomaly.ErrDDoSMixedHistory && !hasMixedDDoSDetection(proof.Current) {
				t.Fatal("the initial receipt did not establish mixed pressure", proof.Current)
			}
		}
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, path, nil, http.StatusNotFound)
}

func seedDDoSContinuityWindows(t *testing.T, store flowstore.Store, tenant string, end time.Time, width time.Duration, pressure bool, scenario ddosContinuityScenario) {
	t.Helper()
	var rows []flowstore.Row
	for offset := -1; offset <= 3; offset++ {
		at := end.Add(time.Duration(offset)*width - 2*time.Second)
		for _, historical := range []bool{true, false} {
			clock, count, packets := at, 4, uint64(3200)
			high := pressure && !historical
			if historical {
				clock = at.AddDate(0, 0, -7)
			}
			if high {
				packets = 6400
				if (scenario.gap == errDDoSSampleCoverage || scenario.gap == anomaly.ErrDDoSRecordSupport) && offset == 1 {
					count = 1
					if scenario.sparseQuiet {
						packets = 3200
					}
				}
			}
			crossingQuiet := high && offset == 1 && scenario.gap == errDDoSTimingCoverage
			containedSYN := pressure && offset == 1 && scenario.containedSYN
			mixed := scenario.gap == anomaly.ErrDDoSMixedHistory
			containedCount := 1
			switch {
			case containedSYN:
				// Current and reference totals match. Only the current window's
				// four contained reports carry SYN pressure. Four crossing
				// reports dilute its share when counted in the same window.
				packets = 6400
				containedCount = 4
				if high {
					count = 2 * containedCount
				}
			case crossingQuiet:
				packets = 3200
			case mixed:
				// Both tenants keep the same totals. Only one has sustained
				// mixed pressure and one reference with omitted transport.
				packets = 6400
			}
			for index := range count {
				vector := high && (scenario.gap != nil || offset != 1)
				if crossingQuiet {
					vector = containedSYN && index < containedCount
				}
				row := delayFixtureFlow(tenant, clock, vector)
				row.SrcPort += uint16(index)
				if mixed && high && index >= count/2 {
					row.Transport, row.TCPFlags, row.SrcPort = "udp", 0, 53
					// Preserve two distinct originals with the same UDP service.
					row.DstPort += uint16(index)
				}
				if mixed && pressure && historical && offset == 1 {
					row.Transport, row.TCPFlags = "", 0
				}
				if crossingQuiet && index >= containedCount {
					row.StartTS = clock.Add(-4 * width)
					row.ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
				}
				row.Sampling = scenario.rate
				row.PacketsScaled = packets / uint64(count)
				row.Packets = row.PacketsScaled / scenario.rate
				row.Bytes, row.BytesScaled = 100*row.Packets, 100*row.PacketsScaled
				if high && offset == 1 && index == 0 && scenario.gap == errDDoSCounterIntegrity {
					row.PacketsScaled++
				}
				rows = append(rows, row)
			}
		}
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
}
