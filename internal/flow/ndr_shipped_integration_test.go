// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/threat"
)

const (
	ndrMiB            = uint64(1 << 20)
	ndrSharedSource   = "10.183.30.1"
	ndrControlSource  = "10.183.30.2"
	ndrFixtureTarget  = "198.51.100.50"
	ndrVolumeDetector = "ndr-egress-volume-default"
)

type ndrDetections struct {
	Running bool               `json:"detections_running"`
	Items   []threat.Detection `json:"items"`
}

type ndrReceiptObservation struct {
	source byte
	at     time.Time
	bytes  uint64
}

// Each loopback datagram is a synthetic telemetry report. It represents an
// observed byte counter and sends no corresponding traffic to the embedded
// documentation address. The shipped agents, bus, control plane, incident
// store and TLS API interpret these receipts independently per tenant.
func TestShippedNDREgressKeepsOwnBaselineSuppressionAndIncidents(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "ndr-volume-receipts", TenantBand: 4})
	operator := stack.OnboardOperator(t, "root@msp-ndr.example")
	run := "ndr-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []*nativeLane{{name: "red", octet: 183, useDefaultFlush: true}, {name: "blue", octet: 183, useDefaultFlush: true}}
	var senders [2]net.Conn
	for lane, scope := range lanes {
		scope.provision(t, stack, operator, run)
		scope.apiToken = stack.APIToken(t, scope.cookie, "threat.read")
		conn, err := net.DialTimeout("udp", scope.listeners["IPFIX"], 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		senders[lane] = conn
		t.Cleanup(func() { _ = conn.Close() })
	}
	shipped.Await(t, "the shipped control plane loaded its default NDR volume rule", 15*time.Second, func() bool {
		code, raw := stack.Do(t, lanes[0].cookie, http.MethodGet, "/v1/threat/rules", nil)
		return code == http.StatusOK && bytes.Contains(raw, []byte(ndrVolumeDetector))
	})

	first := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	sharedAt, controlAt := first.Add(12*time.Second), first.Add(26*time.Second)
	baselines := [2]uint64{ndrMiB, 24 * ndrMiB}
	for lane, baseline := range baselines {
		observations := make([]ndrReceiptObservation, 0, 27)
		for sample := range 12 {
			observations = append(observations, ndrReceiptObservation{1, first.Add(time.Duration(sample) * time.Second), baseline})
		}
		observations = append(observations, ndrReceiptObservation{1, sharedAt, 24 * ndrMiB},
			ndrReceiptObservation{1, sharedAt.Add(time.Second), 96 * ndrMiB})
		// This independent positive uses the same partition and arrives after
		// the shared-source input. It proves the quiet sibling was processed.
		for sample := range 12 {
			observations = append(observations, ndrReceiptObservation{2, first.Add(time.Duration(14+sample) * time.Second), 2 * ndrMiB})
		}
		observations = append(observations, ndrReceiptObservation{2, controlAt, 48 * ndrMiB})
		// Keep each tenant's training, candidate and suppression observations
		// in one ordered data set. Separate UDP reports can reach processing
		// before the last baseline record and change the first eligible sample.
		frame := ndrFlowReceipt(t, observations)
		if n, err := senders[lane].Write(frame); err != nil || n != len(frame) {
			t.Fatal("write the tenant's ordered synthetic observations", lane, n, err)
		}
	}

	var captured [2]ndrDetections
	for lane, scope := range lanes {
		plan := nativeGoldenPlan(scope.octet, controlAt, []string{"src_addr"})
		plan.DataSeries, plan.From, plan.To = "raw", first.Add(-time.Second), controlAt.Add(time.Second)
		wantBytes := map[string]string{
			ndrSharedSource:  strconv.FormatUint(12*baselines[lane]+120*ndrMiB, 10),
			ndrControlSource: strconv.FormatUint(72*ndrMiB, 10),
		}
		shipped.Await(t, "both logical sources reached raw ClickHouse", 40*time.Second, func() bool {
			observations := scope.query(t, stack, plan)
			if observations.Totals["flows:total"] != "27" || len(observations.Rows) != len(wantBytes) {
				return false
			}
			gotBytes := make(map[string]string, len(observations.Rows))
			for _, row := range observations.Rows {
				gotBytes[row.Group["src_addr"]] = row.Metrics["bytes:total"]
			}
			return reflect.DeepEqual(gotBytes, wantBytes)
		})
		shipped.Await(t, "the ordered independent NDR positive reached the incident store", 30*time.Second, func() bool {
			captured[lane] = readNDRDetections(t, stack, scope)
			for _, item := range captured[lane].Items {
				if item.Entity == ndrControlSource && item.ObservedAt.Equal(controlAt) {
					return true
				}
			}
			return false
		})
	}

	for lane, scope := range lanes {
		items := captured[lane].Items
		if !captured[lane].Running || len(items) != 2-lane {
			t.Fatal("the shared-source comparison or suppression produced an unexpected receipt count", lane, items)
		}
		assertNDRSignal(t, stack, scope, items[0], ndrControlSource, controlAt, 48*ndrMiB, 2*ndrMiB)
		if lane == 0 {
			assertNDRSignal(t, stack, scope, items[1], ndrSharedSource, sharedAt, 24*ndrMiB, ndrMiB)
		}
		for _, foreign := range captured[1-lane].Items {
			scope.do(t, stack, http.MethodGet, "/v1/incidents/"+foreign.IncidentID, nil, nil, http.StatusNotFound)
		}
		assertNDRCLIDetections(t, stack, scope, captured[lane])
	}

	stack.RestartControl(t, "ndr-volume-restart", nil)
	for lane, scope := range lanes {
		if current := readNDRDetections(t, stack, scope); !reflect.DeepEqual(captured[lane], current) {
			t.Fatal("a control restart changed the durable tenant NDR receipts", lane)
		}
		expect, absent := []string{ndrControlSource, ndrVolumeDetector}, []string{}
		if lane == 0 {
			expect = append(expect, ndrSharedSource)
		} else {
			absent = append(absent, ndrSharedSource)
		}
		for _, theme := range []string{"light", "dark"} {
			testsupport.RenderUI(t, testsupport.RenderSpec{
				URL:            stack.BaseURL + "/ui/security",
				Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: scope.cookie}},
				TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile, Theme: theme, Accessibility: true,
				Expect: expect, Absent: absent,
				Controls: []testsupport.RenderControl{{Role: "table", Name: "Threat detections"}},
			})
		}
	}
}

func ndrFlowReceipt(t *testing.T, observations []ndrReceiptObservation) []byte {
	t.Helper()
	const templateID = uint16(347)
	fields := [...]uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 6, 1, 1, 8, 2, 8, 34, 4, 152, 8, 153, 8}
	exported := time.Now().Unix()
	if exported < 0 || exported > math.MaxUint32 {
		t.Fatal("fixture clocks are outside the export fields")
	}
	template := nativeWire(t, templateID, uint16(len(fields)/2), fields)
	var records []byte
	for _, observation := range observations {
		start, end := observation.at.Add(-500*time.Millisecond).UnixMilli(), observation.at.UnixMilli()
		if start < 0 || end < 0 {
			t.Fatal("fixture clocks are outside the export fields")
		}
		from, to := [4]byte{10, 183, 30, observation.source}, [4]byte{198, 51, 100, 50}
		records = append(records, nativeWire(t, from, to, uint16(42001), uint16(443), uint8(6), uint8(16),
			observation.bytes, uint64(1), uint32(1), uint64(start), uint64(end))...)
	}
	packetSize := 24 + len(template) + len(records)
	if packetSize > math.MaxUint16 || len(template) > math.MaxUint16-4 || len(records) > math.MaxUint16-4 {
		t.Fatal("fixture report exceeds an IPFIX envelope")
	}
	body := nativeWire(t, uint16(10), uint16(packetSize), uint32(exported), uint32(0), uint32(43),
		uint16(2), uint16(4+len(template)), template)
	return append(body, nativeWire(t, templateID, uint16(4+len(records)), records)...)
}

func readNDRDetections(t *testing.T, stack *shipped.Stack, scope *nativeLane) ndrDetections {
	t.Helper()
	var output ndrDetections
	scope.do(t, stack, http.MethodGet, "/v1/threat/detections", nil, &output, http.StatusOK)
	return output
}

func assertNDRSignal(t *testing.T, stack *shipped.Stack, scope *nativeLane, item threat.Detection,
	source string, at time.Time, amount, baseline uint64) {
	t.Helper()
	if item.Kind != "ndr.egress_volume" || item.Source != ndrVolumeDetector || item.Confidence != 65 ||
		item.Entity != source || item.IncidentID == "" || !item.ObservedAt.Equal(at) {
		t.Fatal("detection lost the exact scoped source, clock, confidence, or incident", item)
	}
	var detail incident.Incident
	scope.do(t, stack, http.MethodGet, "/v1/incidents/"+item.IncidentID, nil, &detail, http.StatusOK)
	if detail.TenantID != scope.id || detail.ID != item.IncidentID || len(detail.Signals) != 1 {
		t.Fatal("the durable receipt did not select exactly one tenant-owned signal", detail.ID, detail.SignalCount)
	}
	signal := detail.Signals[0]
	if signal.Kind != item.Kind || !signal.OccurredAt.Equal(at) ||
		signal.Attributes["egress.destination"] != ndrFixtureTarget ||
		signal.Attributes["egress.bytes"] != strconv.FormatUint(amount, 10) ||
		signal.Attributes["egress.baseline_bytes"] != strconv.FormatUint(baseline, 10) ||
		signal.Attributes["egress.ratio"] != fmt.Sprintf("%.1f", float64(amount)/float64(baseline)) {
		t.Fatal("the original counter or independent baseline changed in the incident receipt", signal.Attributes)
	}
}

func assertNDRCLIDetections(t *testing.T, stack *shipped.Stack, scope *nativeLane, expected ndrDetections) {
	t.Helper()
	var current ndrDetections
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": scope.apiToken}, &current, "threat", "detections")
	if !reflect.DeepEqual(expected, current) {
		t.Fatal("the CLI changed the tenant-owned NDR receipts", scope.name)
	}
	if !strings.Contains(current.Items[0].Summary, ndrFixtureTarget) {
		t.Fatal("the summarized evidence lost its original reported destination")
	}
}
