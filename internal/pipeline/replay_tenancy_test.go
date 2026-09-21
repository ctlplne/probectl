// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// twoTenantBinding registers exactly agent-a under tenant-a — tenant-b has no
// agents, mirroring a two-tenant registry.
type twoTenantBinding struct{}

func (twoTenantBinding) Verify(_ context.Context, tenantID, agentID string) error {
	if tenantID == "tenant-a" && agentID == "agent-a" {
		return nil
	}
	return ErrTenantNotBound
}

func forgedEndpointResult(t *testing.T) bus.Message {
	t.Helper()
	// agent-a (bound to tenant-a) publishes a payload CLAIMING tenant-b.
	v, err := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-b", AgentId: "agent-a",
		CanaryType: "icmp", ServerAddress: "192.0.2.1", Success: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Key: []byte("tenant-b"), Value: v}
}

// TestDeadLetterKeepsLaneAuthorityAndReplayRefusesForgery is S-f02d4e59's
// proof. A forged endpoint-lane record dead-letters onto the ENDPOINT lane's
// own DLQ topic — never the shared one that replays into the trusted network
// lane — and its replay re-enters the endpoint lane, whose registry
// verification refuses the forged tenant before anything persists.
func TestDeadLetterKeepsLaneAuthorityAndReplayRefusesForgery(t *testing.T) {
	ctx := context.Background()
	b := bus.NewMemory()
	defer b.Close()

	// Stage 1: first ingest on the endpoint lane with a broken store — the
	// record survives verification ONLY because verification rejects it
	// outright; to exercise the DLQ path we use a record the lane admits
	// (correct tenant) and prove topic routing, then replay the forged one.
	c := NewConsumer(b, alwaysFailWriter{}, "test", testLogger())
	c.retryBase = time.Microsecond
	c.sleep = func(context.Context, time.Duration) {}
	c.binding = twoTenantBinding{}

	endpointLane := topicGroup{topic: bus.EndpointResultsTopic, group: "test-endpoint", verify: true}

	// 1a. The forged record is refused at FIRST ingest (never dead-lettered).
	if err := c.handleLane(ctx, forgedEndpointResult(t), endpointLane); err != nil {
		t.Fatalf("forged record must be dropped, not error the stream: %v", err)
	}
	if got := c.Stats().DeadLettered; got != 0 {
		t.Fatalf("forged record was dead-lettered (%d); it must be rejected outright", got)
	}

	// 1b. A LEGITIMATE endpoint record that exhausts the store parks on the
	// ENDPOINT DLQ topic — its lane authority travels with it.
	endpointDLQ := make(chan bus.Message, 1)
	sharedDLQ := make(chan bus.Message, 1)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_ = b.Subscribe(subCtx, bus.DeadLetterResultsTopic+".endpoint", "t1", func(_ context.Context, m bus.Message) error {
			endpointDLQ <- m
			return nil
		})
	}()
	go func() {
		_ = b.Subscribe(subCtx, bus.DeadLetterResultsTopic, "t2", func(_ context.Context, m bus.Message) error {
			sharedDLQ <- m
			return nil
		})
	}()
	if !b.WaitForSubscribers(ctx, bus.DeadLetterResultsTopic+".endpoint", 1) ||
		!b.WaitForSubscribers(ctx, bus.DeadLetterResultsTopic, 1) {
		t.Fatal("DLQ subscribers never attached")
	}

	legit, err := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-a", AgentId: "agent-a",
		CanaryType: "icmp", ServerAddress: "192.0.2.1", Success: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.handleLane(ctx, bus.Message{Key: []byte("tenant-a"), Value: legit}, endpointLane); err != nil {
		t.Fatalf("legit record handling: %v", err)
	}
	select {
	case <-endpointDLQ: // parked on the lane's own DLQ ✓
	case m := <-sharedDLQ:
		t.Fatalf("endpoint-lane dead letter landed on the SHARED results DLQ (pooled): %q", m.Topic)
	case <-time.After(2 * time.Second):
		t.Fatal("dead letter never published")
	}

	// Stage 2: replay of the endpoint DLQ maps back to the ENDPOINT lane, so
	// re-ingest re-applies registry verification by construction.
	src, ok := bus.SourceTopicForDeadLetter(bus.DeadLetterResultsTopic + ".endpoint")
	if !ok || src != bus.EndpointResultsTopic {
		t.Fatalf("endpoint DLQ replays into %q, want %q", src, bus.EndpointResultsTopic)
	}

	// Stage 3: a forged record planted in the endpoint DLQ (worst case:
	// something wrote garbage there) replays into the endpoint lane and a
	// FRESH consumer with a WORKING store still refuses it — nothing persists
	// under tenant-b.
	store := tsdb.NewMemory()
	c2 := NewConsumer(b, store, "replayed", testLogger())
	c2.binding = twoTenantBinding{}
	if err := c2.handleLane(ctx, forgedEndpointResult(t), endpointLane); err != nil {
		t.Fatalf("replayed forged record must be dropped, not error: %v", err)
	}
	if got := c2.rejectedTenant.Load(); got != 1 {
		t.Fatalf("replayed forged record rejections = %d, want 1", got)
	}
	for _, series := range store.Snapshot() {
		if strings.Contains(series.Labels["tenant_id"], "tenant-b") {
			t.Fatalf("forged tenant reached storage: %+v", series)
		}
	}
}

// TestLegacySharedDLQReplayRefusesForgedResidue covers the pre-upgrade
// residue: records parked on the SHARED results DLQ replay into the TRUSTED
// network lane, so the replayer itself re-verifies each record against the
// registry and refuses what cannot prove its identity.
func TestLegacySharedDLQReplayRefusesForgedResidue(t *testing.T) {
	ctx := context.Background()
	b := bus.NewMemory()
	defer b.Close()

	leaked := make(chan bus.Message, 4)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_ = b.Subscribe(subCtx, bus.NetworkResultsTopic, "capture", func(_ context.Context, m bus.Message) error {
			leaked <- m
			return nil
		})
	}()
	if !b.WaitForSubscribers(ctx, bus.NetworkResultsTopic, 1) {
		t.Fatal("capture subscriber never attached")
	}

	// Start the replayer FIRST (the memory bus has no retention), then seed
	// the legacy topic with a forged residue record and a legit one.
	r := NewDeadLetterReplayer(b, testLogger()).WithBinding(twoTenantBinding{})
	done := make(chan ReplayResult, 1)
	go func() {
		res, err := r.Replay(ctx, ReplayConfig{DLQTopic: bus.DeadLetterResultsTopic, IdleTimeout: 500 * time.Millisecond})
		if err != nil {
			t.Errorf("replay: %v", err)
		}
		done <- res
	}()
	time.Sleep(50 * time.Millisecond)

	forged := forgedEndpointResult(t)
	if err := b.Publish(ctx, bus.DeadLetterResultsTopic, forged.Key, forged.Value); err != nil {
		t.Fatal(err)
	}
	legit, _ := proto.Marshal(&resultv1.Result{TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "icmp", ServerAddress: "192.0.2.1", Success: true})
	if err := b.Publish(ctx, bus.DeadLetterResultsTopic, []byte("tenant-a"), legit); err != nil {
		t.Fatal(err)
	}
	var res ReplayResult
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("replay never finished")
	}
	if res.Replayed != 1 || res.Refused != 1 {
		t.Fatalf("replay = (replayed %d, refused %d), want (1, 1)", res.Replayed, res.Refused)
	}
	select {
	case m := <-leaked:
		var rec resultv1.Result
		if err := proto.Unmarshal(m.Value, &rec); err != nil {
			t.Fatal(err)
		}
		if rec.GetTenantId() != "tenant-a" {
			t.Fatalf("record with tenant %q replayed into the trusted lane", rec.GetTenantId())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("legit record never replayed")
	}

	// Without a binding the legacy topic refuses to replay AT ALL.
	if _, err := NewDeadLetterReplayer(b, testLogger()).Replay(ctx, ReplayConfig{
		DLQTopic: bus.DeadLetterResultsTopic, IdleTimeout: 100 * time.Millisecond,
	}); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("legacy shared DLQ replay without a binding must fail closed, got %v", err)
	}
}

// TestSiloedLaneDeadLettersStayNamespaced proves a siloed tenant's dead
// letters rest on its namespaced (tenant-bound ACL) DLQ topic, never pooled.
func TestSiloedLaneDeadLettersStayNamespaced(t *testing.T) {
	nsTopic, err := bus.TopicFor("t-acme", bus.EndpointResultsTopic)
	if err != nil {
		t.Fatal(err)
	}
	dlq, err := bus.DeadLetterTopicFor(nsTopic)
	if err != nil {
		t.Fatal(err)
	}
	want := "probectl.t-acme.deadletter.results.endpoint"
	if dlq != want {
		t.Fatalf("siloed endpoint DLQ = %q, want %q", dlq, want)
	}
	src, ok := bus.SourceTopicForDeadLetter(dlq)
	if !ok || src != nsTopic {
		t.Fatalf("siloed DLQ replays into %q, want %q (the tenant-bound lane)", src, nsTopic)
	}
	if _, err := bus.DeadLetterTopicFor("probectl.unknown.topic.shape.x"); err == nil {
		t.Fatal("unknown lane must have NO dead-letter topic (fail closed)")
	}
}
