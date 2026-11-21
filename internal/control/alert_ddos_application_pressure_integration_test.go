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
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFastDDoSDoesNotAttributeAnotherListenersTrafficToAnHTTPOutage(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	traces := fastDDoSApplicationFixtureStore(t, f.tenants)
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f.server.WithTSDB(tsdb.NewMemory()).WithFlowStore(rows).WithFlowQueryViews(views).WithFairness(gate).WithOTelStore(traces)
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)

	end := time.Now().UTC().Add(-30 * time.Second).Truncate(5 * time.Second)
	clocks, err := ddosClocks(end, 5)
	if err != nil {
		t.Fatal(err)
	}
	var positiveReceipt string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Two listeners on one protected host")
		definition.Time.LookbackSeconds = 60
		definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
			{Field: "exporter", Op: flow.QueryEqual, Values: []string{"203.0.113.15"}},
		}}
		view, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: "192.0.2.1/32", Direction: "ingress", PeriodSeconds: 5,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
			MinObservedRecords: 1, MinObservedAddresses: 2,
			Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
		sourceInput := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
		body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": "Protected host with an application outage", "query_source": sourceInput}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(body, &rule); err != nil || rule.ID == "" {
			t.Fatal("could not configure the protected host", err)
		}
		seedDDoSSplitListenerPressure(t, rows, traces, tenant, clocks, lane == 0)
		source, due, err := f.server.loadAlertQueryRule(ctx, rule, 1<<20)
		if err != nil || !due || source == nil {
			t.Fatal("could not load the due rule", err)
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
		if lane == 0 && (err != nil || got.QuerySelection == nil || len(got.Samples) != 1) {
			t.Fatal("independent pressure on the failed listener lost its episode", err)
		}
		if lane == 1 && (!errors.Is(err, anomaly.ErrDDoSCoverage) || got.QuerySelection != nil) {
			t.Fatal("an unrelated HTTP outage qualified aggregate traffic from another listener", err)
		}
		for _, item := range getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items {
			if item.Reason != "Sustained flow traffic pressure" {
				continue
			}
			if lane != 0 || positiveReceipt != "" {
				t.Fatal("the detector emitted an unrelated or duplicate episode", tenant)
			}
			positiveReceipt = "/v1/alerts/rules/" + rule.ID + "/ddos-receipt?fingerprint=" + item.Fingerprint
		}
		if positiveReceipt == "" {
			t.Fatal("the owning tenant has no pressure episode receipt")
		}
	}
	var proof alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, positiveReceipt, nil, http.StatusOK)
	if err := json.Unmarshal(body, &proof); err != nil || proof.Current.Application == nil ||
		proof.Current.Application.State != anomaly.DDoSApplicationDegraded ||
		proof.Current.Application.Current.FlowBytes != "210000" || proof.Current.Application.Current.FlowPackets != "2700" ||
		proof.Current.Application.Current.Successes != 20 || proof.Current.After.Bytes != "290000" || proof.Current.After.Packets != "3500" {
		t.Fatal("receipt lost the original listener-specific and host-wide evidence", err)
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, positiveReceipt, nil, http.StatusNotFound)
}

func seedDDoSSplitListenerPressure(t *testing.T, rows flowstore.Store, traces otelstore.Store, tenant string, clocks ddosEpisodeClocks, pressureOnListener bool) {
	t.Helper()
	var flows []flowstore.Row
	var observations []otelstore.Span
	for _, pair := range []anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current} {
		for index, window := range []anomaly.TrainingWindow{pair.Before, pair.After} {
			listener := delayFixtureFlow(tenant, window.Start.Add(2*time.Second), false)
			other := listener
			other.DstPort = 8443
			listenerBytes, listenerPackets := uint64(140000), uint64(1700)
			otherBytes, otherPackets := uint64(80000), uint64(800)
			http := benchmarkDDoSApplication{Requests: 30, LatencyMS: 25}
			if index == 1 {
				http.Failures, http.LatencyMS = 10, 80
				if pressureOnListener {
					listenerBytes, listenerPackets = 210000, 2700
				} else {
					otherBytes, otherPackets = 150000, 1800
				}
			}
			listener.Bytes, listener.BytesScaled, listener.Packets, listener.PacketsScaled = listenerBytes, listenerBytes, listenerPackets, listenerPackets
			other.Bytes, other.BytesScaled, other.Packets, other.PacketsScaled = otherBytes, otherBytes, otherPackets, otherPackets
			flows = append(flows, listener, other)
			for i, span := range benchmarkDDoSAppSpans(http, window.Start) {
				span.TenantID = tenant
				span.TraceID = fmt.Sprintf("%016x%016x", window.Start.UnixNano(), i+1)
				observations = append(observations, span)
			}
		}
	}
	if err := rows.Insert(t.Context(), flows); err != nil {
		t.Fatal(err)
	}
	if err := traces.WriteSpans(t.Context(), observations); err != nil {
		t.Fatal(err)
	}
}
