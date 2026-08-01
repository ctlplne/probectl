// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// TestFairnessShedsBeforeDecode is S-49d7cf45's proof. A tenant over its byte
// bound is refused BEFORE protobuf unmarshal, so the flood buys no decode CPU
// and no verification-cache pressure from other tenants. The discriminator is
// deliberate: the payload is GARBAGE, so if the pipeline ever decoded it the
// malformed counter would move. Shed pre-decode, it never does.
func TestFairnessShedsBeforeDecode(t *testing.T) {
	ctx := context.Background()
	// One byte per second with no burst headroom: the first message consumes
	// the bucket, everything after it is over-rate.
	gate := fairness.NewGate(fairness.Policy{IngestBytesPerSec: 1, BurstSeconds: 1}, nil)
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "preadmit", testLogger()).WithFairness(gate)

	garbage := bus.Message{Key: []byte("tenant-flood"), Value: []byte("not-a-protobuf-at-all")}
	lane := topicGroup{topic: bus.NetworkResultsTopic}

	// Drain the bucket, then flood.
	for i := 0; i < 50; i++ {
		if err := c.handleLane(ctx, garbage, lane); err != nil {
			t.Fatalf("handler must not error the stream: %v", err)
		}
	}
	stats := c.IntegrityStats()
	if stats.FairnessShed == 0 {
		t.Fatal("no messages were shed — the byte bound never engaged")
	}
	if stats.Malformed >= 50 {
		t.Fatalf("every message reached the decoder (%d malformed of 50): admission still runs AFTER unmarshal", stats.Malformed)
	}
	if stats.Malformed > stats.FairnessShed {
		t.Fatalf("more messages decoded (%d) than shed (%d): the flood is still buying decode work",
			stats.Malformed, stats.FairnessShed)
	}
}

// TestFairnessPreAdmissionIsolatesTenants proves the bound is PER TENANT: a
// flooding tenant's shed does not consume another tenant's admission.
func TestFairnessPreAdmissionIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	gate := fairness.NewGate(fairness.Policy{IngestBytesPerSec: 8, BurstSeconds: 1}, nil)
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "preadmit-iso", testLogger()).WithFairness(gate)
	lane := topicGroup{topic: bus.NetworkResultsTopic}

	flood := bus.Message{Key: []byte("tenant-noisy"), Value: make([]byte, 64)}
	for i := 0; i < 20; i++ {
		_ = c.handleLane(ctx, flood, lane)
	}

	// The quiet tenant's first message must still be admitted past pre-check.
	quiet := bus.Message{Key: []byte("tenant-quiet"), Value: []byte("x")}
	if !c.preAdmit(ctx, quiet, lane) {
		t.Fatal("a quiet tenant was shed by a different tenant's flood — the bound is not per-tenant")
	}
}

// TestPreAdmitFallsThroughWithoutIdentity: an unkeyed message carries no
// identity to bound, so it must NOT be charged to some arbitrary tenant; it
// falls through to the post-decode admission.
func TestPreAdmitFallsThroughWithoutIdentity(t *testing.T) {
	gate := fairness.NewGate(fairness.Policy{IngestBytesPerSec: 1, BurstSeconds: 1}, nil)
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "preadmit-nokey", testLogger()).WithFairness(gate)
	msg := bus.Message{Value: make([]byte, 4096)}
	for i := 0; i < 5; i++ {
		if !c.preAdmit(context.Background(), msg, topicGroup{topic: bus.NetworkResultsTopic}) {
			t.Fatal("an unkeyed message was shed: it was charged to a tenant it never named")
		}
	}
}

// TestPreAdmitUsesTheLaneTenantWhenSet: on a namespaced (siloed) lane the lane
// identity is authoritative and must be what the pre-check charges.
func TestPreAdmitUsesTheLaneTenantWhenSet(t *testing.T) {
	gate := fairness.NewGate(fairness.Policy{IngestBytesPerSec: 1, BurstSeconds: 1}, nil)
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "preadmit-lane", testLogger()).WithFairness(gate)
	lane := topicGroup{topic: "probectl.t-acme.network.results", laneTenant: "tenant-acme"}
	msg := bus.Message{Key: []byte("tenant-someone-else"), Value: make([]byte, 512)}

	ctx := context.Background()
	admitted := 0
	deadline := time.Now().Add(time.Second)
	for i := 0; i < 20 && time.Now().Before(deadline); i++ {
		if c.preAdmit(ctx, msg, lane) {
			admitted++
		}
	}
	if admitted == 0 || admitted == 20 {
		t.Fatalf("lane-tenant pre-admission admitted %d/20 — expected the bound to engage after the burst", admitted)
	}
}
