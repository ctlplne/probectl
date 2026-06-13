// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	flowv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/flow/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// captureFlowStore records inserted rows so tests can assert per-tenant
// placement.
type captureFlowStore struct {
	flowstore.Store
	rows []flowstore.Row
}

func (c *captureFlowStore) Insert(ctx context.Context, rows []flowstore.Row) error {
	c.rows = append(c.rows, rows...)
	return c.Store.Insert(ctx, rows)
}

func (c *captureFlowStore) RowsForTenant(tenant string) []flowstore.Row {
	var out []flowstore.Row
	for _, r := range c.rows {
		if r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out
}

// fakeBinding is a TenantBinding over a fixed registry: only listed
// (tenant, agent) pairs verify. failWith simulates a registry outage.
type fakeBinding struct {
	pairs    map[[2]string]bool
	failWith error
	calls    int
}

func (f *fakeBinding) Verify(_ context.Context, tenant, agent string) error {
	f.calls++
	if f.failWith != nil {
		return f.failWith
	}
	if f.pairs[[2]string{tenant, agent}] {
		return nil
	}
	return ErrTenantNotBound
}

// ── VerifyBatchTenant: the decision table (TENANT-101) ──────────────────────

func TestVerifyBatchTenant(t *testing.T) {
	ctx := context.Background()
	b := &fakeBinding{pairs: map[[2]string]bool{
		{"tenant-a", "agent-1"}: true,
	}}

	t.Run("pooled: registered pair accepted", func(t *testing.T) {
		got, ow, err := VerifyBatchTenant(ctx, b, "", []Identity{{Tenant: "tenant-a", Agent: "agent-1"}})
		if err != nil || got != "tenant-a" || ow {
			t.Fatalf("got=%q ow=%v err=%v", got, ow, err)
		}
	})

	t.Run("pooled: INJECTION — claimed tenant not bound to agent is rejected", func(t *testing.T) {
		// agent-1 belongs to tenant-a; the payload claims tenant-b.
		_, _, err := VerifyBatchTenant(ctx, b, "", []Identity{{Tenant: "tenant-b", Agent: "agent-1"}})
		if !errors.Is(err, ErrTenantNotBound) {
			t.Fatalf("cross-tenant claim must be rejected, got %v", err)
		}
	})

	t.Run("pooled: unknown agent rejected", func(t *testing.T) {
		_, _, err := VerifyBatchTenant(ctx, b, "", []Identity{{Tenant: "tenant-a", Agent: "ghost"}})
		if !errors.Is(err, ErrTenantNotBound) {
			t.Fatalf("unknown agent must be rejected, got %v", err)
		}
	})

	t.Run("registry outage rejects (fail closed)", func(t *testing.T) {
		down := &fakeBinding{failWith: ErrBindingUnavailable}
		_, _, err := VerifyBatchTenant(ctx, down, "", []Identity{{Tenant: "tenant-a", Agent: "agent-1"}})
		if !errors.Is(err, ErrBindingUnavailable) {
			t.Fatalf("registry outage must reject, got %v", err)
		}
	})

	t.Run("lane: namespaced lane overrides the payload tenant", func(t *testing.T) {
		got, ow, err := VerifyBatchTenant(ctx, b, "tenant-a", []Identity{{Tenant: "tenant-b", Agent: "agent-1"}})
		if err != nil || got != "tenant-a" || !ow {
			t.Fatalf("lane must be authoritative: got=%q ow=%v err=%v", got, ow, err)
		}
	})

	t.Run("lane: agent must be registered in the LANE tenant", func(t *testing.T) {
		_, _, err := VerifyBatchTenant(ctx, b, "tenant-z", []Identity{{Tenant: "tenant-z", Agent: "agent-1"}})
		if !errors.Is(err, ErrTenantNotBound) {
			t.Fatalf("agent foreign to the lane tenant must be rejected, got %v", err)
		}
	})

	t.Run("mixed batch rejected", func(t *testing.T) {
		_, _, err := VerifyBatchTenant(ctx, b, "", []Identity{
			{Tenant: "tenant-a", Agent: "agent-1"},
			{Tenant: "tenant-b", Agent: "agent-1"},
		})
		if !errors.Is(err, ErrMixedBatch) {
			t.Fatalf("mixed batch must be rejected, got %v", err)
		}
	})

	t.Run("empty tenant rejected", func(t *testing.T) {
		_, _, err := VerifyBatchTenant(ctx, b, "", []Identity{{Tenant: "", Agent: "agent-1"}})
		if !errors.Is(err, ErrNoTenant) {
			t.Fatalf("empty tenant must be rejected, got %v", err)
		}
	})

	t.Run("empty batch rejected", func(t *testing.T) {
		if _, _, err := VerifyBatchTenant(ctx, b, "", nil); !errors.Is(err, ErrNoTenant) {
			t.Fatalf("empty batch must be rejected, got %v", err)
		}
	})

	// WIRE-001: the residual forgery surface was the SHARED pooled lane — a
	// credential holder who knows a victim's registered (tenant, agent) pair
	// could publish a record that the registry check happily vouches for. In
	// strict-lane mode the shared lane is refused outright, so the only
	// authoritative path is a tenant-namespaced (broker-ACL isolated) lane.
	t.Run("WIRE-001 strict: a registry-VALID pair on the shared lane is REFUSED", func(t *testing.T) {
		// {tenant-a, agent-1} is a perfectly valid registered pair — non-strict
		// accepts it. Strict mode must still refuse it on the shared lane.
		_, _, err := VerifyBatchTenantStrict(ctx, b, "", true, []Identity{{Tenant: "tenant-a", Agent: "agent-1"}})
		if !errors.Is(err, ErrSharedLaneForbidden) {
			t.Fatalf("strict mode must refuse the shared lane even for a valid pair, got %v", err)
		}
		// Sanity: non-strict still accepts the same valid pair (proves the test
		// is exercising the strict path, not a pre-existing rejection).
		if got, _, err := VerifyBatchTenant(ctx, b, "", []Identity{{Tenant: "tenant-a", Agent: "agent-1"}}); err != nil || got != "tenant-a" {
			t.Fatalf("non-strict must still accept the valid pair: got=%q err=%v", got, err)
		}
	})

	t.Run("WIRE-001 strict: the namespaced lane stays authoritative", func(t *testing.T) {
		// Strict mode does not change namespaced lanes — they were never the
		// forgery surface. The lane tenant wins and the agent must be bound to it.
		got, ow, err := VerifyBatchTenantStrict(ctx, b, "tenant-a", true, []Identity{{Tenant: "tenant-b", Agent: "agent-1"}})
		if err != nil || got != "tenant-a" || !ow {
			t.Fatalf("strict namespaced lane must stay authoritative: got=%q ow=%v err=%v", got, ow, err)
		}
	})
}

// ── End-to-end through the flow consumer: the red-team scenario ─────────────

func TestFlowConsumerCrossTenantInjection(t *testing.T) {
	ctx := context.Background()
	st := &captureFlowStore{Store: flowstore.NewMemory()}
	b := &fakeBinding{pairs: map[[2]string]bool{
		{"tenant-a", "agent-1"}: true,
	}}
	c := NewFlowConsumer(nil, st, nil, testLogger()).WithTenantBinding(b)

	mkBatch := func(tenant, agent string) bus.Message {
		batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
			TenantId: tenant, AgentId: agent,
			SourceAddress: "10.0.0.1", DestinationAddress: "192.0.2.9", Bytes: 100,
		}}}
		v, _ := proto.Marshal(batch)
		return bus.Message{Key: []byte(tenant), Value: v}
	}

	// RED TEAM: tenant A's agent claims tenant B in the payload — the record
	// must NEVER land under tenant B.
	if err := c.handleLane(ctx, mkBatch("tenant-b", "agent-1"), ""); err != nil {
		t.Fatalf("handler must drop, not error the stream: %v", err)
	}
	if got := c.RejectedBatches(); got != 1 {
		t.Fatalf("rejected = %d, want 1", got)
	}
	if rows := st.RowsForTenant("tenant-b"); len(rows) != 0 {
		t.Fatalf("INJECTION SUCCEEDED: %d rows landed under tenant-b", len(rows))
	}

	// The legitimate pair flows through and is stored under the verified tenant.
	if err := c.handleLane(ctx, mkBatch("tenant-a", "agent-1"), ""); err != nil {
		t.Fatalf("legit batch: %v", err)
	}
	if rows := st.RowsForTenant("tenant-a"); len(rows) != 1 {
		t.Fatalf("legit rows = %d, want 1", len(rows))
	}

	// Namespaced lane: payload claims tenant-b, but the lane belongs to
	// tenant-a — the stored row must carry tenant-a (lane authoritative).
	if err := c.handleLane(ctx, mkBatch("tenant-b", "agent-1"), "tenant-a"); err != nil {
		t.Fatalf("lane batch: %v", err)
	}
	if rows := st.RowsForTenant("tenant-a"); len(rows) != 2 {
		t.Fatalf("lane-stamped rows = %d, want 2", len(rows))
	}
	if rows := st.RowsForTenant("tenant-b"); len(rows) != 0 {
		t.Fatalf("lane override leaked %d rows to tenant-b", len(rows))
	}
}

// WIRE-001 end-to-end: with strict-lane mode on, a forged-but-registry-valid
// record on the SHARED lane is dropped and stored nowhere; the SAME record on
// the agent's own namespaced lane flows through. Proves the residual shared-
// lane forgery surface is closed in the default multi-tenant/regulated posture.
func TestFlowConsumerStrictLaneClosesSharedLaneForgery(t *testing.T) {
	ctx := context.Background()
	st := &captureFlowStore{Store: flowstore.NewMemory()}
	b := &fakeBinding{pairs: map[[2]string]bool{
		{"tenant-a", "agent-1"}: true, // a real, registered pair
	}}
	// Strict mode ON (the multi-tenant/regulated default).
	c := NewFlowConsumer(nil, st, nil, testLogger()).
		WithTenantBinding(b).WithStrictTenantLanes(true)

	mkBatch := func(tenant, agent string) bus.Message {
		batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
			TenantId: tenant, AgentId: agent,
			SourceAddress: "10.0.0.1", DestinationAddress: "192.0.2.9", Bytes: 100,
		}}}
		v, _ := proto.Marshal(batch)
		return bus.Message{Key: []byte(tenant), Value: v}
	}

	// FORGERY on the shared lane: a registry-VALID pair (the residual gap) is
	// now refused outright — strict mode does not even consult the registry.
	if err := c.handleLane(ctx, mkBatch("tenant-a", "agent-1"), ""); err != nil {
		t.Fatalf("handler must drop, not error: %v", err)
	}
	if got := c.RejectedBatches(); got != 1 {
		t.Fatalf("shared-lane batch must be refused in strict mode, rejected=%d", got)
	}
	if rows := st.RowsForTenant("tenant-a"); len(rows) != 0 {
		t.Fatalf("strict mode stored %d rows from the shared lane (must be 0)", len(rows))
	}

	// The SAME record on the agent's namespaced lane flows through (the lane is
	// the authoritative, forgery-proof path).
	if err := c.handleLane(ctx, mkBatch("tenant-a", "agent-1"), "tenant-a"); err != nil {
		t.Fatalf("namespaced lane batch: %v", err)
	}
	if rows := st.RowsForTenant("tenant-a"); len(rows) != 1 {
		t.Fatalf("namespaced lane rows = %d, want 1", len(rows))
	}
}

// FuzzVerifyBatchTenant: whatever identities arrive, the verifier must never
// return a tenant the binding doesn't vouch for (pooled) or differ from the
// lane (namespaced) — and must never panic.
func FuzzVerifyBatchTenant(f *testing.F) {
	f.Add("tenant-a", "agent-1", "")
	f.Add("tenant-b", "agent-1", "")
	f.Add("tenant-b", "agent-1", "tenant-a")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, tenant, agent, lane string) {
		b := &fakeBinding{pairs: map[[2]string]bool{{"tenant-a", "agent-1"}: true}}
		got, _, err := VerifyBatchTenant(context.Background(), b, lane, []Identity{{Tenant: tenant, Agent: agent}})
		if err != nil {
			return // rejected — always safe
		}
		if lane != "" && got != lane {
			t.Fatalf("lane %q but authoritative %q", lane, got)
		}
		if lane == "" && (got != "tenant-a" || agent != "agent-1") {
			t.Fatalf("pooled accepted unvouched pair (%q,%q) -> %q", tenant, agent, got)
		}
	})
}
