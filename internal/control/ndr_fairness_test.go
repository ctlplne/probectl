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
	"github.com/ctlplne/probectl/internal/fairness"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/threat"
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
		withDetections(detections)

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
	if cs.shedCount() == 0 {
		t.Fatalf("NDR consumer shed 0 records for a tenant flooding 200 flows at a 5/s bound (SCALE-005 gate not wired)")
	}

	// Quiet tenant: a single in-bounds record still produces its detection — the
	// noisy neighbor did not starve it.
	flood("quiet", 1)
	if got := len(detections.List("quiet")); got == 0 {
		t.Fatalf("quiet tenant produced no detection — starved by the noisy neighbor (isolation broken)")
	}
}

// TestNDRFairnessDoesNotSpendStorageFlowBudget checks the shared-gate wiring
// used by both real consumer groups. Independent work stages keep the same
// per-tenant ceiling, but may not consume each other's admission credits.
func TestNDRFairnessDoesNotSpendStorageFlowBudget(t *testing.T) {
	for _, order := range []string{"storage-first", "ndr-first"} {
		t.Run(order, func(t *testing.T) {
			ctx := t.Context()
			gate := fairness.NewGate(fairness.Policy{FlowEventsPerSec: 1, BurstSeconds: 1}, nil)
			ndr := NewNDRConsumer(nil, nil, nil, intelTestLog()).WithFairness(gate)
			storage := func(tenant string, n int) bool { return gate.AdmitN(ctx, tenant, fairness.MeterFlowEvents, int64(n)) }
			detect := func(tenant string, n int) bool { return !ndr.admitFlows(ctx, map[string]int{tenant: n})[tenant] }
			first, second := storage, detect
			if order == "ndr-first" {
				first, second = detect, storage
			}
			// An oversized first batch is admitted on the existing deficit contract;
			// the long deficit makes the assertions independent of scheduler timing.
			if !first("red", 10000) {
				t.Fatal("fresh first stage refused its initial batch")
			}
			if !second("red", 10000) {
				t.Fatal("secondary consumer spent the other stage's flow budget")
			}
			if storage("red", 1) || detect("red", 1) {
				t.Fatal("independent stage budget became unbounded after deficit")
			}
			if !storage("blue", 1) || !detect("blue", 1) {
				t.Fatal("noisy tenant or sibling stage starved the quiet tenant")
			}
			state := gate.SnapshotTenant(ctx, "red").Ingest
			for _, meter := range []string{fairness.MeterFlowEvents, "ndr_flow_events"} {
				counts := state[meter]
				if counts.AdmittedUnits != 10000 || counts.ShedUnits != 1 {
					t.Fatalf("%s lost independent stage accounting: %+v", meter, counts)
				}
			}
		})
	}
}
