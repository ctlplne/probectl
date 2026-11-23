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
	verifyDDoSApplicationAttribution(t, ddosSplitListenerAttribution)
}

func TestFastDDoSKeepsChangedTraceSamplingSeparateFromListenerPressure(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerTraceSampling)
}

func TestFastDDoSAbstainsOnProportionateDemandDuringServiceOverload(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerDegradedCrowd)
}

func TestFastDDoSKeepsIndependentPressureWithAnUnhealthyApplicationReference(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerDegradedReference)
}

func TestFastDDoSFindsOutsideApplicationPressureWithFlatHostTotals(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerFlatHost)
}

func TestFastDDoSRequiresAReportedPortToProveOutsideApplicationPressure(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerMissingPort)
}

func TestFastDDoSRequiresSocketAttributionToProveOutsideApplicationPressure(t *testing.T) {
	verifyDDoSApplicationAttribution(t, ddosSplitListenerMissingTransport)
}

type ddosSplitListenerHoldout uint8

const (
	ddosSplitListenerAttribution ddosSplitListenerHoldout = iota
	ddosSplitListenerTraceSampling
	ddosSplitListenerDegradedReference
	ddosSplitListenerFlatHost
	ddosSplitListenerMissingPort
	ddosSplitListenerMissingTransport
	ddosSplitListenerDegradedCrowd
)

func (s ddosSplitListenerHoldout) flatHost() bool {
	return s == ddosSplitListenerFlatHost || s == ddosSplitListenerMissingPort || s == ddosSplitListenerMissingTransport
}

func TestFastDDoSSeparatesStableNetworkBackgroundFromGrowingVector(t *testing.T) {
	for _, vector := range []anomaly.DDoSClass{anomaly.DDoSSYN, anomaly.DDoSReflection} {
		t.Run(string(vector), func(t *testing.T) {
			verifyDDoSNetworkBackground(t, vector, growingProtectedTraffic)
		})
	}
}

func TestFastDDoSSeparatesClassificationFieldCoverageFromGrowingVector(t *testing.T) {
	for _, vector := range []anomaly.DDoSClass{anomaly.DDoSSYN, anomaly.DDoSReflection} {
		t.Run(string(vector), func(t *testing.T) {
			verifyDDoSNetworkBackground(t, vector, missingReferenceClassification)
		})
	}
}

func TestFastDDoSSeparatesTransportFieldCoverageFromGrowingVector(t *testing.T) {
	for _, vector := range []anomaly.DDoSClass{anomaly.DDoSSYN, anomaly.DDoSReflection} {
		t.Run(string(vector), func(t *testing.T) {
			verifyDDoSNetworkBackground(t, vector, missingReferenceTransport)
		})
	}
}

func TestFastDDoSSeparatesFallingVolumeFromGrowingVector(t *testing.T) {
	for _, vector := range []anomaly.DDoSClass{anomaly.DDoSSYN, anomaly.DDoSReflection} {
		t.Run(string(vector), func(t *testing.T) {
			verifyDDoSNetworkBackground(t, vector, fallingProtectedTraffic)
		})
	}
}

type ddosNetworkScenario int

const (
	growingProtectedTraffic ddosNetworkScenario = iota
	missingReferenceClassification
	missingReferenceTransport
	fallingProtectedTraffic
)

func verifyDDoSNetworkBackground(t *testing.T, vector anomaly.DDoSClass, scenario ddosNetworkScenario) {
	t.Helper()
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
	var positiveReceipt, positiveRuleID, positiveFingerprint string
	for lane, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := fieldComparisonViewDefinition("Protected host with steady network background")
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
			MinObservedRecords: 2, MinObservedAddresses: 2,
			Application: &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}}
		sourceInput := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
		body := callSeasonalAPI(t, server, f.tokens[tenant], http.MethodPost, "/v1/alerts",
			map[string]any{"name": "Protected service with shared-host traffic", "query_source": sourceInput}, http.StatusCreated)
		var rule alert.Rule
		if err := json.Unmarshal(body, &rule); err != nil || rule.ID == "" {
			t.Fatal("could not configure the protected host", err)
		}
		seedDDoSNetworkBackground(t, rows, traces, tenant, clocks, vector, lane == 0, scenario)
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
		if err != nil || got.QuerySelection == nil || !got.QuerySelection.Complete {
			t.Fatal("both lanes must have complete evaluated windows", err)
		}
		for _, item := range getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items {
			if item.Reason != "Sustained flow traffic pressure" {
				continue
			}
			if lane != 0 || positiveReceipt != "" {
				t.Fatalf("opened an episode on steady vector background or duplicated the growing vector: lane %d", lane)
			}
			positiveRuleID, positiveFingerprint = rule.ID, item.Fingerprint
			positiveReceipt = "/v1/alerts/rules/" + positiveRuleID + "/ddos-receipt?fingerprint=" + positiveFingerprint
		}
		if lane == 0 && (len(got.Samples) != 1 || positiveReceipt == "") {
			t.Fatal("the growing vector lost its episode")
		}
		if lane == 1 && len(got.Samples) != 0 {
			t.Fatal("ordinary service demand with a flat network vector opened an episode")
		}
	}
	reference, current, contributed := "2500", "3100", "2300"
	if scenario == fallingProtectedTraffic {
		reference, current, contributed = "4200", "4000", "2800"
	}
	var proof alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, positiveReceipt, nil, http.StatusOK)
	if err := json.Unmarshal(body, &proof); err != nil {
		t.Fatal("read the scoped vector receipt", err)
	}
	for _, assessment := range []flow.DDoSAssessment{proof.Previous, proof.Current} {
		if assessment.Detection == nil || assessment.Detection.Class != vector || assessment.Detection.ContributingPackets != contributed ||
			assessment.Before.Packets != reference || assessment.After.Packets != current {
			t.Fatalf("receipt lost the tenant's original vector and host counters: %+v", assessment)
		}
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, positiveReceipt, nil, http.StatusNotFound)
	if scenario == missingReferenceTransport {
		report := fmt.Sprintf("/v1/incidents/%s/ddos-report?rule_id=%s&fingerprint=%s", proof.IncidentID, positiveRuleID, positiveFingerprint)
		callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, report, nil, http.StatusOK)
		callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, report, nil, http.StatusNotFound)
	}
}

func seedDDoSNetworkBackground(t *testing.T, rows flowstore.Store, traces otelstore.Store, tenant string,
	clocks ddosEpisodeClocks, vector anomaly.DDoSClass, growing bool, scenario ddosNetworkScenario) {
	t.Helper()
	var flows []flowstore.Row
	var spans []otelstore.Span
	for pairIndex, pair := range []anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current} {
		for index, window := range []anomaly.TrainingWindow{pair.Before, pair.After} {
			listener := delayFixtureFlow(tenant, window.Start.Add(2*time.Second), false)
			background := listener
			background.SrcPort, background.DstPort, background.TCPFlags = 42002, 8443, 2
			if vector == anomaly.DDoSReflection {
				background.Transport, background.SrcPort, background.TCPFlags = "udp", 53, 0
			}
			if index == 0 && scenario == missingReferenceClassification {
				background.SrcPort, background.TCPFlags = 0, 0
			}
			if index == 0 && scenario == missingReferenceTransport {
				background.Transport = [...]string{"", "0"}[pairIndex]
			}
			listenerBytes, listenerPackets := uint64(70000), uint64(600)
			backgroundBytes, backgroundPackets := uint64(120000), uint64(1900)
			requests := 30
			if index == 1 {
				requests = 60
				listenerBytes, listenerPackets = 140000, 1200
				if growing {
					listenerBytes, listenerPackets = 100000, 800
					backgroundBytes, backgroundPackets = 160000, 2300
				}
			}
			if scenario == fallingProtectedTraffic {
				backgroundPackets = 1900
				switch {
				case index == 0:
					listenerPackets = 2300
				case growing:
					listenerPackets, backgroundPackets = 1200, 2800
				default:
					listenerPackets = 2100
				}
				listenerBytes, backgroundBytes = listenerPackets*100, backgroundPackets*100
				requests = int(listenerPackets / 50)
			}
			listener.Bytes, listener.BytesScaled, listener.Packets, listener.PacketsScaled = listenerBytes, listenerBytes, listenerPackets, listenerPackets
			background.Bytes, background.BytesScaled, background.Packets, background.PacketsScaled = backgroundBytes, backgroundBytes, backgroundPackets, backgroundPackets
			flows = append(flows, listener, background)
			for i, span := range benchmarkDDoSAppSpans(benchmarkDDoSApplication{Requests: requests, LatencyMS: 25}, window.Start) {
				span.TenantID = tenant
				span.TraceID = fmt.Sprintf("%016x%016x", window.Start.UnixNano(), i+1)
				spans = append(spans, span)
			}
		}
	}
	if err := rows.Insert(t.Context(), flows); err != nil {
		t.Fatal(err)
	}
	if err := traces.WriteSpans(t.Context(), spans); err != nil {
		t.Fatal(err)
	}
}

func verifyDDoSApplicationAttribution(t *testing.T, scenario ddosSplitListenerHoldout) {
	t.Helper()
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
	var positiveReceipt, positiveRuleID, positiveFingerprint string
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
		seedDDoSSplitListenerPressure(t, rows, traces, tenant, clocks, scenario, lane == 0)
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
			t.Fatal("independent pressure did not open an episode", err)
		}
		if lane == 1 {
			if scenario == ddosSplitListenerFlatHost {
				if err != nil || got.QuerySelection == nil || len(got.Samples) != 0 {
					t.Fatal("stable traffic did not establish quiet coverage", err)
				}
			} else if !errors.Is(err, anomaly.ErrDDoSCoverage) || got.QuerySelection != nil {
				t.Fatal("incomplete application attribution qualified a sibling episode", scenario, err)
			}
		}
		for _, item := range getSeasonalFlowReceipts(t, server, f.tokens[tenant], rule.ID).Items {
			if item.Reason != "Sustained flow traffic pressure" {
				continue
			}
			if lane != 0 || positiveReceipt != "" {
				t.Fatal("the detector emitted an unrelated or duplicate episode", tenant)
			}
			positiveRuleID, positiveFingerprint = rule.ID, item.Fingerprint
			positiveReceipt = "/v1/alerts/rules/" + positiveRuleID + "/ddos-receipt?fingerprint=" + positiveFingerprint
		}
		if positiveReceipt == "" {
			t.Fatal("the owning tenant has no pressure episode receipt")
		}
	}
	var proof alert.DDoSEvaluationEvidence
	body := callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, positiveReceipt, nil, http.StatusOK)
	listenerBytes, listenerPackets, hostBytes, hostPackets := "210000", "2700", "290000", "3500"
	wantState, wantReferenceSuccesses, wantCurrentSuccesses := anomaly.DDoSApplicationDegraded, 30, 20
	switch scenario {
	case ddosSplitListenerTraceSampling, ddosSplitListenerDegradedCrowd:
		listenerBytes, listenerPackets, hostBytes, hostPackets = "560000", "6800", "560000", "6800"
	case ddosSplitListenerDegradedReference:
		listenerBytes, listenerPackets, hostBytes, hostPackets = "140000", "1700", "400000", "4500"
		wantState, wantReferenceSuccesses = anomaly.DDoSApplicationResidual, 22
	case ddosSplitListenerFlatHost, ddosSplitListenerMissingPort, ddosSplitListenerMissingTransport:
		listenerBytes, listenerPackets, hostBytes, hostPackets = "120000", "1200", "400000", "4000"
		wantState, wantReferenceSuccesses, wantCurrentSuccesses = anomaly.DDoSApplicationResidual, 80, 30
	}
	if err := json.Unmarshal(body, &proof); err != nil || proof.Current.Application == nil ||
		proof.Current.Application.State != wantState || proof.Current.Application.Reference.Successes != wantReferenceSuccesses ||
		proof.Current.Application.Current.FlowBytes != listenerBytes || proof.Current.Application.Current.FlowPackets != listenerPackets ||
		proof.Current.Application.Current.Successes != wantCurrentSuccesses || proof.Current.After.Bytes != hostBytes || proof.Current.After.Packets != hostPackets {
		t.Fatal("receipt lost the original listener-specific and host-wide evidence", err)
	}
	if scenario == ddosSplitListenerDegradedCrowd && (proof.Current.Application.Reference.Requests != 30 || proof.Current.Application.Current.Requests != 30) {
		t.Fatal("receipt lost the original completed request counts", proof.Current.Application)
	}
	if scenario.flatHost() {
		if proof.Current.Before.Bytes != hostBytes || proof.Current.Before.Packets != hostPackets || proof.Current.Detection == nil ||
			proof.Current.Detection.Class != anomaly.DDoSVolumetric {
			t.Fatal("receipt lost the flat aggregate and separately qualifying evidence", proof.Current)
		}
		// Reports re-measure raw flows using the original receipt. This must
		// agree even though the report path does not re-read the spans.
		report := fmt.Sprintf("/v1/incidents/%s/ddos-report?rule_id=%s&fingerprint=%s", proof.IncidentID, positiveRuleID, positiveFingerprint)
		callSeasonalAPI(t, server, f.tokens[f.tenants[0]], http.MethodGet, report, nil, http.StatusOK)
		callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, report, nil, http.StatusNotFound)
	}
	callSeasonalAPI(t, server, f.tokens[f.tenants[1]], http.MethodGet, positiveReceipt, nil, http.StatusNotFound)
}

func seedDDoSSplitListenerPressure(t *testing.T, rows flowstore.Store, traces otelstore.Store, tenant string, clocks ddosEpisodeClocks,
	scenario ddosSplitListenerHoldout, positive bool) {
	t.Helper()
	samplingKnown := scenario == ddosSplitListenerTraceSampling
	samplingChanged := samplingKnown && !positive
	listenerOnly := samplingKnown || scenario == ddosSplitListenerDegradedCrowd
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
			if scenario == ddosSplitListenerDegradedReference {
				http.Failures = 8
			}
			threshold := ""
			if samplingKnown {
				threshold = "0"
			}
			switch {
			case scenario.flatHost():
				listenerBytes, listenerPackets = 320000, 3200
				otherBytes, otherPackets = 80000, 800
				http = benchmarkDDoSApplication{Requests: 80, LatencyMS: 25}
				if index == 1 && (positive || scenario != ddosSplitListenerFlatHost) {
					listenerBytes, listenerPackets = 120000, 1200
					otherBytes, otherPackets = 280000, 2800
					http.Requests = 30
					switch {
					case !positive && scenario == ddosSplitListenerMissingPort:
						other.DstPort = 0
					case !positive && scenario == ddosSplitListenerMissingTransport:
						other.Transport, other.DstPort = "0", 443
					}
				}
			case index == 1:
				http.Failures, http.LatencyMS = 10, 80
				if samplingChanged {
					threshold = "c"
					http = benchmarkDDoSApplication{Requests: 120, LatencyMS: 25}
				}
				switch {
				case listenerOnly:
					listenerBytes, listenerPackets = listenerBytes*4, listenerPackets*4
					if scenario == ddosSplitListenerDegradedCrowd && !positive {
						http.Requests, http.Failures = 120, 40
					}
				case scenario == ddosSplitListenerDegradedReference && positive:
					otherBytes, otherPackets = 260000, 2800
				case scenario == ddosSplitListenerAttribution && positive:
					listenerBytes, listenerPackets = 210000, 2700
				default:
					otherBytes, otherPackets = 150000, 1800
				}
			}
			listener.Bytes, listener.BytesScaled, listener.Packets, listener.PacketsScaled = listenerBytes, listenerBytes, listenerPackets, listenerPackets
			flows = append(flows, listener)
			if !listenerOnly {
				other.Bytes, other.BytesScaled, other.Packets, other.PacketsScaled = otherBytes, otherBytes, otherPackets, otherPackets
				flows = append(flows, other)
			}
			spans := benchmarkDDoSAppSpans(http, window.Start)
			if samplingChanged {
				spans = spans[:30]
			}
			for i, span := range spans {
				span.TenantID = tenant
				span.TraceID = fmt.Sprintf("%016x%016x", window.Start.UnixNano(), i+1)
				span.SamplingThreshold = threshold
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
