// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/siem"
)

// ING-17: a plain BMP route observation (origin unchanged from baseline) must
// NOT page the SIEM and must NOT open an incident. Genuine routing anomalies
// (origin_change, possible_hijack, possible_leak, rpki_invalid) still do — see
// TestBGPRoutingSignalIsForwardedToTheSIEM. Before the fix the BMP listener
// emitted every announcement as origin_change/info, so handleLane forwarded and
// correlated every route in a full-table dump.
func TestBGPRouteObservationIsNotForwardedOrIncident(t *testing.T) {
	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{BufferSize: 8, RetryBackoff: time.Millisecond}, testLog())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Run(ctx); close(done) }()

	store := incident.NewMemoryStore()
	cs := NewBGPIncidentConsumer(nil, incident.NewCorrelator(store, time.Hour, testLog()), testLog()).WithSIEM(fw)
	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId:           "t1",
		EventType:          bgpv1.EventType_EVENT_TYPE_ROUTE_OBSERVATION,
		Severity:           bgpv1.Severity_SEVERITY_INFO,
		Prefix:             "203.0.113.0/24",
		Message:            "BMP route announcement observed for 203.0.113.0/24 from AS64500",
		NewOriginAsn:       64500,
		Collector:          "bmp/router-a",
		DetectedAtUnixNano: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.handleLane(ctx, bus.Message{Value: raw}, "t1"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond) // give any (erroneous) forward time to land
	if n := len(snk.records()); n != 0 {
		t.Fatalf("route observation forwarded to the SIEM: got %d records, want 0 (ING-17)", n)
	}
	cancel()
	<-done

	open, err := store.OpenIncidents(ctx, "t1")
	if err != nil {
		t.Fatalf("open incidents: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("route observation opened %d incidents, want 0 (ING-17)", len(open))
	}
}
