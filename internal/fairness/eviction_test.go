// SPDX-License-Identifier: LicenseRef-probectl-TBD

package fairness

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// tenantsTracked counts the tenants the gate is holding state for, across all
// shards — the memory the unbounded-map DoS (SCALE-002 / RED-003b) would grow
// without bound. SnapshotAll walks every shard's tenant map, so its length is
// exactly that count.
func tenantsTracked(g *Gate) int { return len(g.SnapshotAll()) }

// shardOf mirrors Gate.shardFor's FNV-1a so a test can pick ids that land on a
// specific shard — used to deterministically trigger every shard's amortized
// sweep (a sweep runs only on a shard that receives a call).
func shardOf(tenantID string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(tenantID); i++ {
		h ^= uint32(tenantID[i])
		h *= 16777619
	}
	return h % gateShards
}

// oneIDPerShard returns gateShards ids, exactly one mapping to each shard, all
// sharing a prefix so the test can identify them. It guarantees a subsequent
// admit of each id visits — and therefore sweeps — every shard.
func oneIDPerShard(prefix string) []string {
	out := make([]string, gateShards)
	filled := 0
	for i := 0; filled < gateShards; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		sh := shardOf(id)
		if out[sh] == "" {
			out[sh] = id
			filled++
		}
	}
	return out
}

// TestIdleTenantsAreEvicted is the SCALE-002 / RED-003b acceptance test: inject
// N tenants, advance a FAKE clock past the idle TTL, trigger the amortized
// sweep, and assert the per-tenant state map drains back to ~0. Pre-fix the
// gate never evicts, so the map only ever grows; post-fix idle tenants are
// reclaimed.
func TestIdleTenantsAreEvicted(t *testing.T) {
	clk := newFakeClock()
	g := NewGate(Policy{ResultsPerSec: 1000}, nil).
		WithNow(clk.now).
		WithIdleTTL(time.Hour)
	ctx := context.Background()

	const n = 5000
	for i := range n {
		g.AdmitN(ctx, fmt.Sprintf("idle-%05d", i), MeterResults, 1)
	}
	if got := tenantsTracked(g); got != n {
		t.Fatalf("after injecting %d tenants the gate must track them all, tracked %d", n, got)
	}

	// Advance well past the idle TTL (and the per-shard sweep interval).
	clk.advance(2 * time.Hour)

	// Trigger every shard's amortized sweep deterministically: a sweep runs only
	// on a shard that receives a call, so admit exactly one fresh id per shard.
	// These trigger ids are active at the advanced time, so they SURVIVE.
	triggers := oneIDPerShard("trigger")
	for _, id := range triggers {
		g.AdmitN(ctx, id, MeterResults, 1)
	}

	// Every one of the 5000 idle tenants must be gone — only the gateShards
	// trigger tenants (all admitted at the advanced time) remain.
	tracked := tenantsTracked(g)
	if g.Evicted() != uint64(n) {
		t.Fatalf("the sweep must have reclaimed exactly the %d idle tenants, Evicted()=%d", n, g.Evicted())
	}
	if tracked != len(triggers) {
		t.Fatalf("the per-tenant map did not drain to just the live set: tracking %d, want %d", tracked, len(triggers))
	}
	for _, snap := range g.SnapshotAll() {
		if len(snap.TenantID) >= 5 && snap.TenantID[:5] == "idle-" {
			t.Fatalf("idle tenant %s survived the sweep", snap.TenantID)
		}
	}
}

// TestActiveTenantNeverEvicted: a tenant that keeps admitting refreshes its
// lastSeen on every call, so it survives indefinitely even as the clock and
// the sweeps advance far past the idle TTL — a busy tenant is never reclaimed.
func TestActiveTenantNeverEvicted(t *testing.T) {
	clk := newFakeClock()
	g := NewGate(Policy{ResultsPerSec: 1_000_000}, nil).
		WithNow(clk.now).
		WithIdleTTL(time.Hour)
	ctx := context.Background()

	const busy = "tenant-busy"
	// Admit once per "interval" across many idle-TTLs of wall time.
	for range 200 {
		g.AdmitN(ctx, busy, MeterResults, 1)
		clk.advance(2 * time.Minute) // each step crosses the sweep interval
	}
	found := false
	for _, snap := range g.SnapshotAll() {
		if snap.TenantID == busy {
			found = true
		}
	}
	if !found {
		t.Fatal("a continuously-active tenant must never be evicted")
	}
	if g.Evicted() != 0 {
		t.Fatalf("no eviction expected for a single always-active tenant, Evicted()=%d", g.Evicted())
	}
}

// TestEvictionThenReadmitReenforcesDefaults: after an idle tenant is evicted,
// its next message re-creates state and re-enforces the deployment bound
// immediately (fail-safe: eviction never opens an unbounded gate for a
// returning tenant).
func TestEvictionThenReadmitReenforcesDefaults(t *testing.T) {
	clk := newFakeClock()
	g := NewGate(Policy{ResultsPerSec: 100, BurstSeconds: 1}, nil). // capacity 100
									WithNow(clk.now).
									WithIdleTTL(time.Hour)
	ctx := context.Background()

	const tn = "tenant-returning"
	g.AdmitN(ctx, tn, MeterResults, 1)

	// Go idle long enough to be reclaimed, then trigger every shard's sweep
	// (one fresh id per shard) so tn's shard runs one and reclaims tn.
	clk.advance(2 * time.Hour)
	for _, id := range oneIDPerShard("other") {
		if id == tn {
			continue
		}
		g.AdmitN(ctx, id, MeterResults, 1)
	}
	// Confirm tn was actually evicted (so the re-admit below exercises the
	// re-creation path, not a surviving bucket).
	for _, snap := range g.SnapshotAll() {
		if snap.TenantID == tn {
			t.Fatalf("precondition: tn should have been evicted before re-admit")
		}
	}

	// tn returns: it must be bounded again from the first burst (defaults
	// re-enforced), not admitted without limit.
	admitted := 0
	for range 1000 {
		if g.AdmitN(ctx, tn, MeterResults, 1) {
			admitted++
		}
	}
	if admitted > 101 {
		t.Fatalf("a returning (re-created) tenant must be bounded by the default policy, admitted %d", admitted)
	}
}
