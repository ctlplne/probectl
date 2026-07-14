// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/threat"
)

// TestNDRConsumerFairnessBounded is the SCALE-005 acceptance test: the NDR
// consumer is a SECOND consumer group on the flow lane and previously ran with
// no fairness gate. Flood one tenant's flow lane and assert the NDR consumer
// sheds + counts the over-rate records, while a quiet tenant's detection still
// fires (its lane is not starved).
func TestNDRConsumerFairnessBounded(t *testing.T) {
	intel := loadedIOCStore() // 192.0.2.66 = feodo botnet C2
	detections := threat.NewDetectionStore(0)
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())

	// A tiny per-tenant flow bound: a few records per second, burst 1s.
	gate := fairness.NewGate(fairness.Policy{FlowEventsPerSec: 5, BurstSeconds: 1}, nil)
	cs := NewNDRConsumer(nil, ndrEngine(t, intel), correlator, intelTestLog()).
		WithFairness(gate).
		WithDetections(detections)

	flood := func(tenant string, n int) {
		flows := make([]*flowv1.FlowRecord, 0, n)
		for i := 0; i < n; i++ {
			flows = append(flows, &flowv1.FlowRecord{
				TenantId:           tenant,
				SourceAddress:      "10.0.0.4",
				DestinationAddress: "192.0.2.66",
				DestinationPort:    443,
				Bytes:              2048,
				ObservedAtUnixNano: time.Now().UnixNano(),
			})
		}
		raw, err := proto.Marshal(&flowv1.FlowBatch{Flows: flows})
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.handleFlowBatch(context.Background(), bus.Message{Value: raw}); err != nil {
			t.Fatal(err)
		}
	}

	// Noisy tenant: blast many batches — the first drains the burst bucket, the
	// rest are over-rate and must be shed (token-bucket deficit semantics).
	for i := 0; i < 20; i++ {
		flood("noisy", 50)
	}
	if cs.Shed() == 0 {
		t.Fatalf("NDR consumer shed 0 records for a tenant flooding 200 flows at a 5/s bound (SCALE-005 gate not wired)")
	}

	// Quiet tenant: a single in-bounds record still produces its detection — the
	// noisy neighbor did not starve it.
	flood("quiet", 1)
	if got := len(detections.List("quiet")); got == 0 {
		t.Fatalf("quiet tenant produced no detection — starved by the noisy neighbor (isolation broken)")
	}
}
