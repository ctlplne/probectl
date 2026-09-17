// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/siem"
)

// DPR-079: a BGP hijack reached the incident timeline but never the SIEM;
// routing signals now go out like every other threat-plane signal, and the
// incident is still correlated.
func TestBGPRoutingSignalIsForwardedToTheSIEM(t *testing.T) {
	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{BufferSize: 8, RetryBackoff: time.Millisecond}, testLog())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Run(ctx); close(done) }()

	store := incident.NewMemoryStore()
	cs := NewBGPIncidentConsumer(nil, incident.NewCorrelator(store, time.Hour, testLog()), testLog()).WithSIEM(fw)
	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId: "t1", EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK, Severity: bgpv1.Severity_SEVERITY_CRITICAL,
		Prefix: "216.75.128.0/25", Message: "sub-prefix 216.75.128.0/25 announced by unexpected AS65010", NewOriginAsn: 65010,
		Collector: "rrc00", DetectedAtUnixNano: time.Now().UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.handleLane(ctx, bus.Message{Value: raw}, "t1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(snk.records()) == 1 })
	cancel()
	<-done
	rec := string(snk.records()[0])
	if !strings.Contains(rec, "bgp.possible_hijack") || !strings.Contains(rec, "216.75.128.0/25") || !strings.Contains(rec, "cat=threat") {
		t.Fatalf("unexpected SIEM record: %s", rec)
	}
	open, err := store.OpenIncidents(ctx, "t1")
	if err != nil || len(open) != 1 {
		t.Fatalf("the incident must still be correlated: %v %d", err, len(open))
	}
}
