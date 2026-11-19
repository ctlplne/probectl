// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/json"
	"fmt"
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

type trafficVector struct {
	class               anomaly.DDoSClass
	service, confidence string
	transport, flags    uint8
	port                uint16
	destinations        int
}

var trafficVectors = []trafficVector{
	{anomaly.DDoSSYN, "", "corroborated", 6, 2, 42001, 1},
	{anomaly.DDoSReflection, "dns", "tentative", 17, 0, 53, 1},
	{anomaly.DDoSReflection, "ntp", "tentative", 17, 0, 123, 1},
	{anomaly.DDoSReflection, "memcached", "tentative", 17, 0, 11211, 1},
	{anomaly.DDoSReflection, "cldap", "tentative", 17, 0, 389, 1},
	{anomaly.DDoSReflection, "ssdp", "tentative", 17, 0, 1900, 1},
	{anomaly.DDoSPrefixSpread, "", "corroborated", 6, 16, 42001, 3},
	{anomaly.DDoSVolumetric, "", "tentative", 6, 16, 42001, 1},
}

func TestDDoSVectorsUseOriginalObservationsFromBothShippedCollectors(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "ddosvectors", TenantBand: 4, Env: map[string]string{"PROBECTL_ALERT_EVAL_INTERVAL": "1s"}})
	operator := stack.OnboardOperator(t, "root@msp-traffic-observations.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 183}, {name: "blue", octet: 183}}
	for _, lane := range lanes {
		lane.provision(t, stack, operator, "ddos-"+run)
	}
	windows, err := anomaly.FlowFieldCompletedWindows(flowObservationTestClock(t), anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := anomaly.FlowFieldCompletedWindows(windows.After.Start, anomaly.FlowFieldPreviousWeek, 300)
	if err != nil {
		t.Fatal(err)
	}
	var views [2]flow.SavedQueryView
	for i, lane := range lanes {
		replayOwnedIPFIXObservationVectors(t, lane, previous, windows, i == 0)
		waitOwnedIPFIXObservationVectors(t, stack, lane, previous, windows, i == 0)
		plan := nativeGoldenPlan(lane.octet, windows.After.End, []string{"dst_addr"})
		plan.DataSeries, plan.From, plan.To = "raw", windows.After.Start, windows.After.End
		lane.do(t, stack, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
			Name: "Protected observations " + lane.name, Visibility: "private", Plan: plan, Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 300},
		}}, &views[i], http.StatusCreated)
	}
	path := func(view flow.SavedQueryView) string {
		return "/v1/explorer/flow-views/" + view.ID + "/ddos-assessment"
	}
	for i, vector := range trafficVectors {
		for laneIndex, lane := range lanes {
			view := views[laneIndex]
			input := flow.DDoSAssessmentInput{Version: view.Version, Prefix: fmt.Sprintf("10.%d.%d.0/24", lane.octet, i+1), Direction: "ingress",
				PeriodSeconds: 300, BytesFloor: "250000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
				VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
			var evidence flow.DDoSAssessment
			lane.do(t, stack, http.MethodPost, path(view), input, &evidence, http.StatusOK)
			assertShippedTrafficVector(t, evidence, view, windows, vector, laneIndex == 0 || i == 0)
			lane.do(t, stack, http.MethodPost, path(views[1-laneIndex]), input, nil, http.StatusNotFound)
		}
	}
	assertShippedSustainedReceipt(t, stack, lanes, views, previous, windows)
}

func flowObservationTestClock(t *testing.T) time.Time {
	t.Helper()
	now := time.Now()
	remaining := time.Until(now.Truncate(5 * time.Minute).Add(5 * time.Minute))
	if remaining > 45*time.Second {
		return now
	}
	// Start the fixture after the boundary when it is too close to read all
	// four closed observations and publish through the shipped scheduler.
	timer := time.NewTimer(remaining + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return time.Now()
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
		return time.Time{}
	}
}

func assertShippedSustainedReceipt(t *testing.T, stack *shipped.Stack, lanes []*nativeLane, views [2]flow.SavedQueryView,
	previous, current anomaly.FlowFieldComparisonClocks) {
	t.Helper()
	var rules [2]alert.Rule
	var fingerprints [2]string
	for i, lane := range lanes {
		view := views[i]
		settings := flow.DDoSAssessmentInput{Version: view.Version, Prefix: fmt.Sprintf("10.%d.1.0/24", lane.octet), Direction: "ingress",
			PeriodSeconds: 300, BytesFloor: "250000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
		input := alert.QuerySourceInput{ViewID: view.ID, ViewVersion: view.Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &settings}}
		lane.do(t, stack, http.MethodPost, "/v1/alerts", map[string]any{"name": "Sustained traffic " + lane.name, "query_source": input}, &rules[i], http.StatusCreated)
		path := "/v1/alerts/rules/" + rules[i].ID + "/query-source"
		shipped.Await(t, "traffic observations evaluated in original tenant", 30*time.Second, func() bool {
			code, raw := stack.Do(t, lane.cookie, http.MethodGet, path, nil)
			var source alert.QuerySourceState
			return code == http.StatusOK && json.Unmarshal(raw, &source) == nil && source.NextAt != nil &&
				source.NextAt.Equal(current.After.End.Add(5*time.Minute))
		})
		var receipts alert.EvaluationsResult
		lane.do(t, stack, http.MethodGet, "/v1/alerts/"+rules[i].ID+"/evaluations", nil, &receipts, http.StatusOK)
		for _, receipt := range receipts.Items {
			if receipt.Reason == "Sustained flow traffic pressure" {
				if fingerprints[i] != "" {
					t.Fatal("one pair of observations opened multiple episodes")
				}
				fingerprints[i] = receipt.Fingerprint
			}
		}
	}
	if !alert.ValidFieldDigest(fingerprints[0]) || fingerprints[1] != "" {
		t.Fatal("two adjacent observations and a single burst produced the wrong episode counts")
	}
	path := "/v1/alerts/rules/" + rules[0].ID + "/ddos-receipt?fingerprint=" + fingerprints[0]
	var receipt alert.DDoSEvaluationEvidence
	lanes[0].do(t, stack, http.MethodGet, path, nil, &receipt, http.StatusOK)
	lanes[1].do(t, stack, http.MethodGet, path, nil, nil, http.StatusNotFound)
	assertShippedTrafficVector(t, receipt.Previous, views[0], previous, trafficVectors[0], true)
	assertShippedTrafficVector(t, receipt.Current, views[0], current, trafficVectors[0], true)
	if receipt.IncidentID == "" {
		t.Fatal("the forwarded observations did not retain a cited incident")
	}
	lanes[0].do(t, stack, http.MethodGet, "/v1/incidents/"+receipt.IncidentID, nil, nil, http.StatusOK)
	lanes[1].do(t, stack, http.MethodGet, "/v1/incidents/"+receipt.IncidentID, nil, nil, http.StatusNotFound)
}

func assertShippedTrafficVector(t *testing.T, got flow.DDoSAssessment, view flow.SavedQueryView, clocks anomaly.FlowFieldComparisonClocks, vector trafficVector, changed bool) {
	t.Helper()
	if got.ViewID != view.ID || got.Version != view.Version || !got.Before.From.Equal(clocks.Before.Start) || !got.After.To.Equal(clocks.After.End) ||
		!got.Before.Sampled || !got.After.Sampled || got.Before.Bytes != "10000" || got.Before.Packets != "1000" || got.Before.ObservedRecords != 1 {
		t.Fatal("the enrolled collector lost the tenant, observation clocks or sampling", got.Before, got.After)
	}
	if !changed {
		if got.Detection != nil || got.After.Bytes != "10000" || got.After.Packets != "1000" || got.After.ObservedRecords != 1 {
			t.Fatal("the sibling assessment inherited another collector's measurements", got.After, got.Detection)
		}
		return
	}
	if got.Detection == nil || got.Detection.Class != vector.class || got.Detection.Service != vector.service || got.Detection.Confidence != vector.confidence ||
		got.After.Bytes != strconv.Itoa(vector.destinations*300000) || got.After.Packets != strconv.Itoa(vector.destinations*4000) ||
		got.After.ObservedRecords != vector.destinations || got.After.ObservedAddresses != vector.destinations ||
		got.Detection.CurrentCitation != got.After.Citation || got.Detection.ReferenceCitation != got.Before.Citation {
		t.Fatal("the classified traffic vector lost its received count or citation", vector.class, vector.service, got.After, got.Detection)
	}
}

// These are small flow-export reports sent only to the enrolled loopback
// collector. The traffic described by a report is never sent.
func replayOwnedIPFIXObservationVectors(t *testing.T, lane *nativeLane, previous, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	socket, err := net.Dial("udp", lane.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.Close() }()
	sequence := 0
	for windowIndex, window := range []anomaly.TrainingWindow{previous.Before, windows.Before, previous.After, windows.After} {
		for vectorIndex, vector := range trafficVectors {
			observed := trafficVector{transport: 6, flags: 16, port: 42001, destinations: 1}
			amount, packets := uint64(1000), uint64(100)
			if changed && windowIndex >= 2 || vectorIndex == 0 && windowIndex == 3 {
				observed, amount, packets = vector, 30000, 400
			}
			for destination := range observed.destinations {
				at := window.Start.Add(time.Minute)
				body := controlledTrafficIPFIX(t, lane.octet, vectorIndex, destination, sequence, at, observed, amount, packets)
				n, err := socket.Write(body)
				if err != nil || n != len(body) {
					t.Fatal("writing the complete controlled observation failed", err)
				}
				sequence++
			}
		}
	}
}

func controlledTrafficIPFIX(t *testing.T, octet, vector, destination, sequence int, at time.Time, observed trafficVector, amount, packets uint64) []byte {
	t.Helper()
	source := [4]byte{10, byte(octet), 30, 1}
	protected := [4]byte{10, byte(octet), byte(vector + 1), byte(destination + 1)}
	fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 6, 1, 1, 8, 2, 8, 34, 4, 152, 8, 153, 8}
	template := nativeWire(t, uint16(291), uint16(len(fields)/2), fields)
	body := append(nativeWire(t, uint16(2), uint16(4+len(template))), template...)
	start, end := uint64(at.Add(-time.Second).UnixMilli()), uint64(at.UnixMilli())
	record := nativeWire(t, source, protected, observed.port, uint16(443), observed.transport, observed.flags, amount, packets, uint32(10), start, end)
	body = append(body, nativeWire(t, uint16(291), uint16(4+len(record)), record)...)
	return append(nativeWire(t, uint16(10), uint16(16+len(body)), uint32(time.Now().Unix()), uint32(sequence), uint32(18)), body...)
}

func waitOwnedIPFIXObservationVectors(t *testing.T, stack *shipped.Stack, lane *nativeLane, previous, clocks anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	for i, window := range []anomaly.TrainingWindow{previous.Before, clocks.Before, previous.After, clocks.After} {
		plan := nativeGoldenPlan(lane.octet, window.End, []string{"dst_addr"})
		plan.DataSeries, plan.From, plan.To = "raw", window.Start, window.End
		count, bytes := len(trafficVectors), len(trafficVectors)*10000
		if changed && i >= 2 {
			count = 0
			for _, vector := range trafficVectors {
				count += vector.destinations
			}
			bytes = count * 300000
		} else if i == 3 {
			bytes += 290000 // the sibling has one qualifying window for the first prefix
		}
		shipped.Await(t, "complete tenant-owned flow-export observations", 45*time.Second, func() bool {
			code, raw := stack.Do(t, lane.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
			var result struct {
				Flow *flowstore.PlanResult `json:"flow"`
			}
			return code == http.StatusOK && json.Unmarshal(raw, &result) == nil && result.Flow != nil && result.Flow.Coverage != nil &&
				result.Flow.Coverage.CompleteInputs && result.Flow.Source == "raw" && result.Flow.TotalGroups == count && result.Flow.Totals["bytes:total"] == strconv.Itoa(bytes)
		})
	}
}
