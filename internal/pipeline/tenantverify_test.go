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
		if lane == "" && !(got == "tenant-a" && agent == "agent-1") {
			t.Fatalf("pooled accepted unvouched pair (%q,%q) -> %q", tenant, agent, got)
		}
	})
}
