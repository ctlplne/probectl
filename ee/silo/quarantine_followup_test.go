// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-381: the audit trail is per tenant transition, not per process. Two
// replicas quarantining the same tenant, and a restart of one of them, record
// ONE entered event; the release is recorded once, when the LAST holder lets
// go — never while another replica still refuses the tenant.
func TestQuarantineAuditIsPerTransitionAcrossReplicasAndRestarts(t *testing.T) {
	store := newFakeStore()
	tenants := []IsolatedTenant{{ID: "t-x", Model: "siloed", Status: "active", Residency: "eu"}}
	broken := &fakeChecks{planes: map[string]bool{"eu": true}, reader: map[string]error{"t-x": errTransport}}
	boot := func(replica string, checks *fakeChecks) (*QuarantineSupervisor, *tenancy.Quarantine, *[]recordedNotice) {
		q := tenancy.NewQuarantine()
		s, chain := newTestSupervisor(checks, q, store, replica, &tenants)
		if _, err := s.Boot(context.Background()); err != nil {
			t.Fatal(err)
		}
		s.flush(context.Background())
		return s, q, chain
	}
	s1, _, chain1 := boot("host-a/p1", broken)
	s2, _, chain2 := boot("host-b/p1", broken)
	s1again, _, chain1again := boot("host-a/p2", broken) // host-a's process restarts: a new per-process identity
	if n := store.count(AuditTenantQuarantined, "t-x"); n != 1 {
		t.Fatalf("entered events = %d after two replicas and a restart, want 1", n)
	}
	if len(*chain1)+len(*chain2)+len(*chain1again) != 1 {
		t.Fatalf("tenant-chain receipts = %d, want one entered receipt", len(*chain1)+len(*chain2)+len(*chain1again))
	}
	_ = s1
	store.mu.Lock()
	store.stopped["host-a/p1"] = true // the first process on host-a is gone
	store.mu.Unlock()

	fixed := &fakeChecks{planes: map[string]bool{"eu": true}}
	s1again.checks, s2.checks = fixed, fixed
	s1again.Recheck(context.Background())
	if n := store.count(AuditTenantReleased, "t-x"); n != 0 {
		t.Fatalf("released while replica-2 still holds the tenant (%d events)", n)
	}
	s2.Recheck(context.Background())
	if n := store.count(AuditTenantReleased, "t-x"); n != 1 {
		t.Fatalf("released events = %d once the last holder let go, want 1", n)
	}
	if got := len(*chain1) + len(*chain2) + len(*chain1again); got != 2 {
		t.Fatalf("tenant-chain receipts = %d, want entered + released", got)
	}
}

// DPR-368 / DPR-381: a tenant-chain receipt that can never land is not
// retried forever. A missing silo schema sends it to the provider stream
// at once (it is never written to the pooled table); any other failure is
// retried a bounded number of times, then recorded on the provider stream
// and counted.
func TestQuarantineNoticesAreBoundedAndNeverForcedIntoPooled(t *testing.T) {
	tenants := []IsolatedTenant{
		{ID: "t-nosilo", Model: "siloed", Status: "active", Residency: "mars"},
		{ID: "t-flaky", Model: "siloed", Status: "active", Residency: "mars"},
	}
	q, store := tenancy.NewQuarantine(), newFakeStore()
	s, _ := newTestSupervisor(&fakeChecks{planes: map[string]bool{}}, q, store, "replica-1", &tenants)
	calls := map[string]int{}
	var mu sync.Mutex
	s.tenant = func(_ context.Context, n tenantNotice) error {
		mu.Lock()
		defer mu.Unlock()
		calls[n.entry.TenantID]++
		if n.entry.TenantID == "t-nosilo" {
			return fmt.Errorf("%w: schema t_nosilo does not exist", tenancy.ErrSiloSchemaMissing)
		}
		return errors.New("audit table locked")
	}
	if _, err := s.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxNoticeAttempts+5; i++ {
		s.flush(context.Background())
	}
	if calls["t-nosilo"] != 1 || store.count(AuditQuarantineNoticeProviderOnly, "t-nosilo") != 1 {
		t.Fatalf("missing-silo receipt: %d attempts, provider-only %d; want 1 attempt then the provider stream", calls["t-nosilo"], store.count(AuditQuarantineNoticeProviderOnly, "t-nosilo"))
	}
	if calls["t-flaky"] != maxNoticeAttempts || store.count(AuditQuarantineNoticeProviderOnly, "t-flaky") != 1 || q.NoticesDropped() != 1 {
		t.Fatalf("flaky receipt: %d attempts, provider-only %d, dropped %d; want %d attempts then one provider record, counted",
			calls["t-flaky"], store.count(AuditQuarantineNoticeProviderOnly, "t-flaky"), q.NoticesDropped(), maxNoticeAttempts)
	}
	s.mu.Lock()
	left := len(s.notices)
	s.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d receipts still pending, want none", left)
	}
}

// slowChecks: tenant t-a-slow's catch-up and proof take `slow`; every other
// tenant's proof answers at once.
type slowChecks struct {
	slowCatchUp, slowProof time.Duration
	mu                     sync.Mutex
	proofs                 map[string]int
}

func (*slowChecks) ValidResidency(string) bool { return true }
func (*slowChecks) MissingSiloTables(context.Context, []string) (map[string][]string, error) {
	return nil, nil
}
func (c *slowChecks) CatchUp(ctx context.Context, id string) error {
	if id == "t-a-slow" {
		return wait(ctx, c.slowCatchUp)
	}
	return nil
}
func (c *slowChecks) CatchUpReaderScope(ctx context.Context, id, _ string) error {
	c.mu.Lock()
	if c.proofs == nil {
		c.proofs = map[string]int{}
	}
	c.proofs[id]++
	c.mu.Unlock()
	if id == "t-a-slow" {
		return wait(ctx, c.slowProof)
	}
	return wait(ctx, 20*time.Millisecond)
}

func wait(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DPR-380 (the reviewer's ADV4-3 probe, generalized): each check has its own
// budget, so a slow but successful catch-up does not starve the proof; a
// check that overruns its budget is that TENANT's fault — never "plane
// unreachable" — and a healthy neighbor on the same plane is checked, not
// quarantined from a memo.
func TestSlowTenantNeverQuarantinesItsPlaneNeighbours(t *testing.T) {
	tenants := []IsolatedTenant{
		{ID: "t-a-slow", Model: "siloed", Status: "active", Residency: "eu"},
		{ID: "t-b-healthy", Model: "siloed", Status: "active", Residency: "eu"},
	}
	run := func(checks *slowChecks, budget time.Duration) []tenancy.QuarantineEntry {
		q := tenancy.NewQuarantine()
		s := NewQuarantineSupervisor(QuarantineConfig{Checks: checks, Registry: q, ReaderScoped: true, Planes: []string{"eu"},
			CheckTimeout: budget, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		s.list = func(context.Context) ([]IsolatedTenant, error) { return tenants, nil }
		held, err := s.Boot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return held
	}
	// The catch-up takes 95% of a budget, the proof 20 ms: both pass.
	if held := run(&slowChecks{slowCatchUp: 190 * time.Millisecond}, 200*time.Millisecond); len(held) != 0 {
		t.Fatalf("a slow but successful catch-up quarantined %+v", held)
	}
	// The catch-up overruns: only that tenant, as a slow catch-up with a
	// timeout remedy.
	held := run(&slowChecks{slowCatchUp: time.Second}, 100*time.Millisecond)
	if len(held) != 1 || held[0].TenantID != "t-a-slow" || held[0].Reason != tenancy.QuarantineSchemaCatchUpFailed ||
		!strings.Contains(held[0].Remedy, "PROBECTL_SILO_QUARANTINE_CHECK_TIMEOUT") {
		t.Fatalf("catch-up overrun quarantined %+v; want only t-a-slow, schema catch-up, with the timeout remedy", held)
	}
	// The proof overruns (a lock wait): that tenant is unproven, not its
	// plane unreachable, and its neighbor is still proven.
	checks := &slowChecks{slowProof: time.Second}
	held = run(checks, 100*time.Millisecond)
	if len(held) != 1 || held[0].TenantID != "t-a-slow" || held[0].Reason != tenancy.QuarantineReaderScopeUnproven {
		t.Fatalf("proof overrun quarantined %+v; want only t-a-slow as reader_scope_unproven", held)
	}
	if checks.proofs["t-b-healthy"] != 1 {
		t.Fatalf("the neighbor's proof ran %d times; it must be checked, not memoized", checks.proofs["t-b-healthy"])
	}
}

// Only a refused connection (or an open breaker) condemns a plane for the
// rest of the pass; a timeout or a plane that answered never does.
func TestPlaneRefusedMemoizesOnlyRefusals(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errTransport, true},
		{&net.DNSError{Err: "no such host", Name: "ch-eu", IsNotFound: true}, true},
		{timeout, false},
		{context.DeadlineExceeded, false},
		{errors.New("ACCESS_DENIED"), false},
	} {
		if got := planeRefused(tc.err); got != tc.want {
			t.Errorf("planeRefused(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// DPR-385: a siloed tenant whose schema lacks a tenant-owned table is
// quarantined (silo_schema_incomplete) at boot and when it loses one later;
// the recheck never repairs it behind the operator's back (no catch-up),
// and releases it once the table is back.
func TestIncompleteSiloIsQuarantinedAndNeverSilentlyRepaired(t *testing.T) {
	checks := &fakeChecks{planes: map[string]bool{"eu": true}}
	tenants := []IsolatedTenant{
		{ID: "t-ok", Model: "siloed", Status: "active", Residency: "eu"},
		{ID: "t-hollow", Model: "siloed", Status: "active", Residency: "eu"},
	}
	q, store := tenancy.NewQuarantine(), newFakeStore()
	s, _ := newTestSupervisor(checks, q, store, "replica-1", &tenants)
	if held, err := s.Boot(context.Background()); err != nil || len(held) != 0 {
		t.Fatalf("Boot = %+v %v; both silos are complete", held, err)
	}
	// After boot, someone drops a table from t-hollow's silo.
	checks.mu.Lock()
	checks.missing = map[string][]string{"t-hollow": {"tests"}}
	checks.mu.Unlock()
	s.Recheck(context.Background())
	e, ok := held(q, "t-hollow")
	if !ok || e.Reason != tenancy.QuarantineSchemaIncomplete || !strings.Contains(e.Detail, "tests") ||
		!strings.Contains(e.Remedy, "restore tests") {
		t.Fatalf("t-hollow = %+v %v; want quarantined as silo_schema_incomplete naming the table and the fix", e, ok)
	}
	if err := q.Check("t-ok"); err != nil {
		t.Fatalf("the complete neighbor was quarantined: %v", err)
	}
	checks.mu.Lock()
	before := checks.catchUps
	checks.mu.Unlock()
	s.Recheck(context.Background())
	checks.mu.Lock()
	ran := checks.catchUps - before
	checks.missing = nil // the operator restored the table
	checks.mu.Unlock()
	if ran != 0 {
		t.Fatalf("the recheck ran %d catch-up(s), which would recreate the dropped table empty", ran)
	}
	if _, still := held(q, "t-hollow"); !still {
		t.Fatal("an incomplete silo was released before its table came back")
	}
	s.Recheck(context.Background())
	if _, still := held(q, "t-hollow"); still {
		t.Fatal("the silo is complete again but the tenant is still quarantined")
	}
}

func (*slowChecks) CatchUpSchema(context.Context, string) error { return nil }
