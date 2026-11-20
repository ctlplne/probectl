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
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The lab seeds the previous week's synthetic reference in raw ClickHouse.
// The timed observations enter through the two enrolled shipped collectors.
func TestFastDDoSMeasuresIPFIXRecordDeliveryThroughTheShippedIncident(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "ddos-wire-timing", TenantBand: 4})
	operator := stack.OnboardOperator(t, "root@msp-timing.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 183, useDefaultFlush: true}, {name: "blue", octet: 183, useDefaultFlush: true}}
	var views [2]flow.SavedQueryView
	var rules [2]alert.Rule
	var clients [2]net.Conn
	for i, lane := range lanes {
		lane.provision(t, stack, operator, "ddos-timing-"+run)
		client, err := net.Dial("udp", lane.listeners["IPFIX"])
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		t.Cleanup(func() { _ = client.Close() })
		at := time.Now().UTC()
		plan := nativeGoldenPlan(lane.octet, at, []string{"dst_addr"})
		plan.DataSeries, plan.BucketSeconds, plan.From, plan.To = "raw", 5, at.Add(-time.Minute), at
		lane.do(t, stack, http.MethodPost, "/v1/explorer/flow-views", flow.SaveQueryView{Definition: flow.QueryViewDefinition{
			Name: "Protected timing observations", Visibility: "private", Plan: plan,
			Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 60},
		}}, &views[i], http.StatusCreated)
		settings := flow.DDoSAssessmentInput{Version: views[i].Version, Prefix: fmt.Sprintf("10.%d.1.1/32", lane.octet), Direction: "ingress",
			PeriodSeconds: 5, BytesFloor: "250000", PacketsFloor: "2500", GrowthBasisPoints: 2000,
			VectorShareBasisPoints: 6000, MinObservedRecords: 1, MinObservedAddresses: 2}
		input := alert.QuerySourceInput{ViewID: views[i].ID, ViewVersion: views[i].Version,
			Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &settings}}
		lane.do(t, stack, http.MethodPost, "/v1/alerts", map[string]any{"name": "Early traffic episode " + lane.name, "query_source": input}, &rules[i], http.StatusCreated)
	}
	const width = 5 * time.Second
	start := time.Now().UTC().Truncate(width).Add(4 * width)
	first, err := anomaly.DDoSCompletedWindows(start.Add(width), 5)
	if err != nil {
		t.Fatal(err)
	}
	second, err := anomaly.DDoSCompletedWindows(start.Add(2*width), 5)
	if err != nil {
		t.Fatal(err)
	}
	quiet := trafficVector{transport: 6, flags: 16, port: 42001, destinations: 1}
	write := func(lane, sequence int, at time.Time, pressurized bool) time.Time {
		t.Helper()
		vector, bytes, packets := quiet, uint64(1000), uint64(100)
		if pressurized {
			vector, bytes, packets = trafficVectors[0], 30000, 400
		}
		frame := controlledTrafficIPFIX(t, lanes[lane].octet, 0, 0, sequence, at, vector, bytes, packets)
		sent := time.Now()
		if size, err := clients[lane].Write(frame); err != nil || size != len(frame) {
			t.Fatal("write owned synthetic flow export record", err)
		}
		return sent
	}
	history, err := flowstore.NewClickHouseWithClient(shipped.CHURL(), 90, nil)
	if err != nil {
		t.Fatal("open isolated historical fixture", err)
	}
	t.Cleanup(func() {
		if err := history.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, lane := range lanes {
		var reference []flowstore.Row
		for _, window := range []anomaly.TrainingWindow{first.Before, second.Before} {
			at := window.Start.Add(time.Second)
			reference = append(reference, flowstore.Row{TenantID: lane.id, AgentID: lane.agent,
				Exporter: "127.0.0.1", ObsDomain: 18, Protocol: "ipfix", TS: at, StartTS: at.Add(-time.Second),
				SrcAddr: fmt.Sprintf("10.%d.30.1", lane.octet), DstAddr: fmt.Sprintf("10.%d.1.1", lane.octet),
				SrcPort: 42001, DstPort: 443, Transport: "tcp", TCPFlags: 16,
				Bytes: 1000, Packets: 100, Sampling: 10, BytesScaled: 10000, PacketsScaled: 1000})
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.id))
		if err := history.Insert(ctx, reference); err != nil {
			t.Fatal("seed original synthetic reference", err)
		}
	}
	readWindow := func(lane int, window anomaly.TrainingWindow) (flowstore.PlanResult, int) {
		t.Helper()
		plan := nativeGoldenPlan(lanes[lane].octet, window.End, []string{"dst_addr"})
		plan.DataSeries, plan.BucketSeconds, plan.From, plan.To = "raw", 5, window.Start, window.End
		if now := time.Now().UTC(); plan.To.After(now) {
			plan.To = now
		}
		code, raw := stack.Do(t, lanes[lane].cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var result struct {
			Flow flowstore.PlanResult `json:"flow"`
		}
		if code == http.StatusOK {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal("read original timing observation", err)
			}
		}
		return result.Flow, code
	}
	shipped.Await(t, "both tenant-owned reference pairs reached raw storage ahead of the timing trial", 15*time.Second, func() bool {
		for lane := range lanes {
			for _, window := range []anomaly.TrainingWindow{first.Before, second.Before} {
				result, code := readWindow(lane, window)
				if code != http.StatusOK || result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs ||
					result.Totals["bytes:total"] != "10000" || result.Totals["flows:total"] != "1" {
					return false
				}
			}
		}
		return true
	})
	if time.Now().After(start) {
		t.Fatal("reference readiness exceeded its preroll")
	}
	t.Logf("reference ready for both tenants, original observed windows end at %s and %s", first.After.End, second.After.End)
	var sent [2]time.Time
	for window, clock := range []anomaly.TrainingWindow{first.After, second.After} {
		at := clock.Start.Add(time.Second)
		wait := time.NewTimer(time.Until(at))
		select {
		case <-wait.C:
		case <-t.Context().Done():
			wait.Stop()
			t.Fatal(t.Context().Err())
		}
		sent[window] = write(0, 2+window, at, true)
		write(1, 2+window, at, window == 1)
	}
	var available, firstReceipt time.Time
	shipped.Await(t, "second synthetic export visible in its original tenant", 30*time.Second, func() bool {
		result, code := readWindow(0, second.After)
		if code != http.StatusOK || result.Source != "raw" || result.Totals["bytes:total"] != "300000" || result.Totals["flows:total"] != "1" {
			return false
		}
		available = time.Now()
		return true
	})
	var fingerprint string
	shipped.Await(t, "paired tenants reached the original incident clock", 35*time.Second, func() bool {
		for lane, actor := range lanes {
			var source alert.QuerySourceState
			actor.do(t, stack, http.MethodGet, "/v1/alerts/rules/"+rules[lane].ID+"/query-source", nil, &source, http.StatusOK)
			if source.NextAt == nil || source.NextAt.Before(second.After.End.Add(width)) {
				return false
			}
			var list alert.EvaluationsResult
			actor.do(t, stack, http.MethodGet, "/v1/alerts/"+rules[lane].ID+"/evaluations", nil, &list, http.StatusOK)
			found := ""
			for _, item := range list.Items {
				if item.Reason == "Sustained flow traffic pressure" {
					if found != "" || lane != 0 {
						t.Fatal("synthetic wire replay created a duplicate or sibling episode")
					}
					found = item.Fingerprint
				}
			}
			if lane == 0 {
				if !alert.ValidFieldDigest(found) {
					return false
				}
				if firstReceipt.IsZero() {
					firstReceipt = time.Now()
				}
				fingerprint = found
			}
		}
		return true
	})
	path := "/v1/alerts/rules/" + rules[0].ID + "/ddos-receipt?fingerprint=" + fingerprint
	var receipt alert.DDoSEvaluationEvidence
	lanes[0].do(t, stack, http.MethodGet, path, nil, &receipt, http.StatusOK)
	lanes[1].do(t, stack, http.MethodGet, path, nil, nil, http.StatusNotFound)
	assertShippedTrafficVector(t, receipt.Previous, views[0], first, trafficVectors[0], true)
	assertShippedTrafficVector(t, receipt.Current, views[0], second, trafficVectors[0], true)
	lanes[0].do(t, stack, http.MethodGet, "/v1/incidents/"+receipt.IncidentID, nil, nil, http.StatusOK)
	lanes[1].do(t, stack, http.MethodGet, "/v1/incidents/"+receipt.IncidentID, nil, nil, http.StatusNotFound)
	t.Logf("synthetic IPFIX timing with %s collector flush: second write to first query with stored data=%s, first write to first visible receipt=%s, second window close to first visible receipt=%s",
		flow.Default().FlushInterval, available.Sub(sent[1]), firstReceipt.Sub(sent[0]), firstReceipt.Sub(second.After.End))
}
