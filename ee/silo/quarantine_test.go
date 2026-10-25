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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/breaker"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func quarantineRouter(q *tenancy.Quarantine) *Router {
	r := NewRouter(nil, map[string]DataPlane{"eu": {CHURL: "https://ch-eu:8443"}, "us": {CHURL: "https://ch-us:8443"}}, 0).WithQuarantine(q)
	r.fetch = func(context.Context) (map[string]registryRow, error) {
		return map[string]registryRow{
			"t-x":      {slug: "x", status: "active", model: tenancy.IsolationSiloed, residency: "eu"},
			"t-y":      {slug: "y", status: "active", model: tenancy.IsolationSiloed, residency: "us"},
			"t-pooled": {slug: "p", status: "active", model: tenancy.IsolationPooled},
		}, nil
	}
	return r
}

// D-62: the router refuses EVERY routed target of a quarantined tenant (the
// Postgres schema, the ClickHouse plane and database, the object prefix, the
// bus lane) and leaves every other tenant's routing untouched.
func TestRouterRefusesAQuarantinedTenantOnly(t *testing.T) {
	q := tenancy.NewQuarantine()
	r := quarantineRouter(q)
	q.Enter(tenancy.QuarantineEntry{TenantID: "t-x", Reason: tenancy.QuarantinePlaneUnreachable, Plane: "eu"})
	ctx := context.Background()

	got, err := r.TargetsFor(ctx, "t-x")
	if !errors.Is(err, tenancy.ErrTenantQuarantined) || got != (tenancy.Targets{}) {
		t.Fatalf("TargetsFor(quarantined) = %+v, %v; want no target and the quarantine refusal", got, err)
	}
	y, err := r.TargetsFor(ctx, "t-y")
	if err != nil || y.CHBaseURL != "https://ch-us:8443" || y.PGSchema == "" || y.CHDatabase == "" {
		t.Fatalf("TargetsFor(other siloed) = %+v, %v; want its own targets", y, err)
	}
	if p, err := r.TargetsFor(ctx, "t-pooled"); err != nil || p.Model != tenancy.IsolationPooled {
		t.Fatalf("TargetsFor(pooled) = %+v, %v", p, err)
	}
	lanes, err := r.BusNamespaces(ctx)
	if err != nil || strings.Contains(strings.Join(lanes, ","), "t-x") || !strings.Contains(strings.Join(lanes, ","), "t-y") {
		t.Fatalf("BusNamespaces = %v, %v; want the quarantined tenant's lane left unconsumed", lanes, err)
	}
	owners, err := r.BusNamespaceTenants(ctx)
	if err != nil || owners[BusNamespace("x")] != "" || owners[BusNamespace("y")] != "t-y" {
		t.Fatalf("BusNamespaceTenants = %v, %v", owners, err)
	}

	// The supervisor's tenant-chain notice gets the Postgres schema and
	// nothing that reaches a ClickHouse plane.
	notice, err := r.TargetsFor(contextWithNotice(ctx, t), "t-x")
	if err != nil || notice.PGSchema != SchemaName("t-x") || notice.CHBaseURL != "" || notice.CHDatabase != "" || notice.ObjectPrefix != "" || notice.BusNamespace != "" {
		t.Fatalf("notice targets = %+v, %v; want the Postgres schema only", notice, err)
	}

	q.Release("t-x")
	if x, err := r.TargetsFor(ctx, "t-x"); err != nil || x.CHBaseURL != "https://ch-eu:8443" {
		t.Fatalf("released tenant = %+v, %v; want its targets back", x, err)
	}
}

// contextWithNotice captures the context InTenantQuarantineNotice hands to
// schema resolution (the marker is unexported in tenancy).
func contextWithNotice(ctx context.Context, t *testing.T) context.Context {
	t.Helper()
	var marked context.Context
	prev := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(prev) })
	tenancy.SetRouter(captureRouter{fn: func(c context.Context) { marked = c }})
	_ = tenancy.InTenantQuarantineNotice(tenancy.WithTenant(ctx, "t-capture"), nil, func(context.Context, tenancy.Scope) error { return nil })
	if marked == nil || !tenancy.QuarantineNoticeContext(marked) {
		t.Fatal("InTenantQuarantineNotice did not mark its schema-resolution context")
	}
	return marked
}

type captureRouter struct{ fn func(context.Context) }

var errCaptured = errors.New("captured")

func (c captureRouter) TargetsFor(ctx context.Context, _ string) (tenancy.Targets, error) {
	c.fn(ctx)
	return tenancy.Targets{}, errCaptured
}
func (captureRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }
func (captureRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

// fakeChecks is a scripted Provisioner: per-tenant results for each check.
type fakeChecks struct {
	mu        sync.Mutex
	planes    map[string]bool
	catchUp   map[string]error
	reader    map[string]error
	readerHit map[string]int
	missing   map[string][]string // tenant -> tables its silo lacks
	catchUps  int
}

func (f *fakeChecks) MissingSiloTables(_ context.Context, ids []string) (map[string][]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]string{}
	for _, id := range ids {
		if m := f.missing[id]; len(m) > 0 {
			out[id] = m
		}
	}
	return out, nil
}

func (f *fakeChecks) ValidResidency(name string) bool { return name == "" || f.planes[name] }
func (f *fakeChecks) CatchUp(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.catchUps++
	return f.catchUp[id]
}
func (f *fakeChecks) CatchUpReaderScope(_ context.Context, id, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readerHit == nil {
		f.readerHit = map[string]int{}
	}
	f.readerHit[id]++
	return f.reader[id]
}

type recordedNotice struct {
	tenant, action string
	reason         tenancy.QuarantineReason
}

// fakeStore is tenant_quarantine in memory, with the same holder semantics
// as the Postgres store: an entered event only when the first holder
// appears, a released event only when the last one goes.
type fakeStore struct {
	mu      sync.Mutex
	rows    map[string]map[string]tenancy.QuarantineEntry // tenant -> replica -> entry
	events  []recordedNotice
	stopped map[string]bool // replicas that stopped refreshing
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[string]map[string]tenancy.QuarantineEntry{}, stopped: map[string]bool{}}
}

func (f *fakeStore) hold(_ context.Context, replica string, e tenancy.QuarantineEntry, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rows[e.TenantID] == nil {
		f.rows[e.TenantID] = map[string]tenancy.QuarantineEntry{}
	}
	before := len(f.rows[e.TenantID])
	prev, had := f.rows[e.TenantID][replica]
	f.rows[e.TenantID][replica] = e
	switch {
	case before == 0:
		f.events = append(f.events, recordedNotice{e.TenantID, AuditTenantQuarantined, e.Reason})
		return true, nil
	case had && prev.Reason != e.Reason:
		f.events = append(f.events, recordedNotice{e.TenantID, AuditQuarantineCauseChanged, e.Reason})
	}
	return false, nil
}

func (f *fakeStore) drop(_ context.Context, replica string, e tenancy.QuarantineEntry, _ time.Duration, _ string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	before := len(f.rows[e.TenantID])
	delete(f.rows[e.TenantID], replica)
	if before == 0 || len(f.rows[e.TenantID]) > 0 {
		return false, nil
	}
	f.events = append(f.events, recordedNotice{e.TenantID, AuditTenantReleased, e.Reason})
	return true, nil
}

// predecessors: the fake has no clock; a test marks a replica stopped (its
// rows idle). The SQL idle window is proven on real Postgres.
func (f *fakeStore) predecessors(_ context.Context, host, me string, _ time.Duration) ([]heldRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []heldRow
	for tenant, byReplica := range f.rows {
		for replica, e := range byReplica {
			if replica != me && strings.HasPrefix(replica, host+"/") && f.stopped[replica] {
				e.TenantID = tenant
				out = append(out, heldRow{entry: e, replica: replica})
			}
		}
	}
	return out, nil
}

func (f *fakeStore) prune(context.Context, time.Duration) ([]tenancy.QuarantineEntry, error) {
	return nil, nil
}

func (f *fakeStore) record(_ context.Context, action, tenantID string, _ map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recordedNotice{tenant: tenantID, action: action})
	return nil
}

func (f *fakeStore) count(action, tenant string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.action == action && (tenant == "" || e.tenant == tenant) {
			n++
		}
	}
	return n
}

func newTestSupervisor(checks TenantChecks, q *tenancy.Quarantine, store *fakeStore, replica string, tenants *[]IsolatedTenant) (*QuarantineSupervisor, *[]recordedNotice) {
	gap := func(plane string) error {
		if plane == "nocred" {
			return fmt.Errorf("a siloed or hybrid tenant lives on data plane %q ... add nocred=/path/to/reader-credential.json to PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES", plane)
		}
		return nil
	}
	s := NewQuarantineSupervisor(QuarantineConfig{Checks: checks, Registry: q, ReaderScoped: true, ReaderGap: gap,
		Planes: []string{"eu", "us", "nocred"}, Replica: replica, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s.list = func(context.Context) ([]IsolatedTenant, error) { return *tenants, nil }
	s.store = store
	var tenant []recordedNotice
	var mu sync.Mutex
	s.tenant = func(_ context.Context, n tenantNotice) error {
		mu.Lock()
		defer mu.Unlock()
		tenant = append(tenant, recordedNotice{n.entry.TenantID, n.action(), n.entry.Reason})
		return nil
	}
	return s, &tenant
}

func testSupervisor(t *testing.T, checks *fakeChecks, tenants []IsolatedTenant) (*QuarantineSupervisor, *tenancy.Quarantine, *fakeStore, *[]recordedNotice) {
	t.Helper()
	q, store := tenancy.NewQuarantine(), newFakeStore()
	list := tenants
	s, tenant := newTestSupervisor(checks, q, store, "replica-1", &list)
	return s, q, store, tenant
}

var errTransport = &url.Error{Op: "Post", URL: "https://ch-eu:8443/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}

// One test per D-62 trigger: each failing precondition quarantines exactly the
// affected tenant with the right reason and an actionable fix, and every other
// tenant boots routable. In stop mode the same tenant set refuses startup for
// everyone (siloResidencyPreflight / siloCatchUpAll / siloReaderCatchUpAll).
func TestQuarantineBootQuarantinesOnlyTheFailingTenantPerTrigger(t *testing.T) {
	healthy := IsolatedTenant{ID: "t-ok", Model: "siloed", Status: "active", Residency: "us"}
	cases := []struct {
		name     string
		tenant   IsolatedTenant
		catchUp  map[string]error
		reader   map[string]error
		reason   tenancy.QuarantineReason
		inRemedy string
	}{
		{"residency plane missing", IsolatedTenant{ID: "t-bad", Model: "hybrid", Status: "active", Residency: "mars"},
			nil, nil, tenancy.QuarantinePlaneMissing, "PROBECTL_DATAPLANES"},
		{"residency plane unreachable", IsolatedTenant{ID: "t-bad", Model: "siloed", Status: "active", Residency: "eu"},
			nil, map[string]error{"t-bad": fmt.Errorf("silo: reader scope for tenant t-bad: %w", errTransport)},
			tenancy.QuarantinePlaneUnreachable, "restore connectivity"},
		{"reader credential missing", IsolatedTenant{ID: "t-bad", Model: "siloed", Status: "active", Residency: "nocred"},
			nil, nil, tenancy.QuarantineReaderCredentialMissing, "PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES"},
		{"reader scope unprovable", IsolatedTenant{ID: "t-bad", Model: "hybrid", Status: "active", Residency: "eu"},
			nil, map[string]error{"t-bad": fmt.Errorf("%w: reads rows of t.flows that belong to no tenant", chclient.ErrReaderUnsafe)},
			tenancy.QuarantineReaderScopeUnproven, "WITH GRANT OPTION"},
		{"silo schema catch-up", IsolatedTenant{ID: "t-bad", Model: "siloed", Status: "active", Residency: "eu"},
			map[string]error{"t-bad": errors.New("permission denied for schema t_bad")}, nil,
			tenancy.QuarantineSchemaCatchUpFailed, "catch-up"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks := &fakeChecks{catchUp: tc.catchUp, reader: tc.reader, planes: map[string]bool{"eu": true, "us": true, "nocred": true}}
			s, q, store, tenant := testSupervisor(t, checks, []IsolatedTenant{tc.tenant, healthy})
			held, err := s.Boot(context.Background())
			if err != nil {
				t.Fatalf("Boot = %v; a per-tenant fault must never refuse startup in quarantine mode", err)
			}
			if len(held) != 1 || held[0].TenantID != "t-bad" || held[0].Reason != tc.reason {
				t.Fatalf("quarantined = %+v, want only t-bad with %s", held, tc.reason)
			}
			if !strings.Contains(held[0].Remedy, tc.inRemedy) || held[0].Detail == "" {
				t.Fatalf("entry %+v lacks the actionable fix %q or the cause", held[0], tc.inRemedy)
			}
			if err := q.Check("t-ok"); err != nil {
				t.Fatalf("the healthy tenant was refused: %v", err)
			}
			if err := q.Check("t-bad"); !errors.Is(err, tenancy.ErrTenantQuarantined) {
				t.Fatalf("the failing tenant is routable: %v", err)
			}
			s.flush(context.Background())
			if store.count(AuditTenantQuarantined, "t-bad") != 1 || len(store.events) != 1 || len(*tenant) != 1 || (*tenant)[0].tenant != "t-bad" {
				t.Fatalf("audit = provider %+v tenant %+v, want one entered event on each stream", store.events, *tenant)
			}
		})
	}
}

// The supervisor releases a tenant once its check passes, with no restart,
// and audits the release; a still-failing tenant stays quarantined.
func TestQuarantineRecheckReleasesOnceFixed(t *testing.T) {
	checks := &fakeChecks{planes: map[string]bool{"eu": true},
		reader: map[string]error{"t-a": errTransport, "t-b": errTransport}}
	s, q, store, tenant := testSupervisor(t, checks, []IsolatedTenant{
		{ID: "t-a", Model: "siloed", Status: "active", Residency: "eu"},
		{ID: "t-b", Model: "hybrid", Status: "active", Residency: "eu"},
	})
	if _, err := s.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Both share the dead plane: the second is quarantined from the memo
	// without waiting out another proof.
	if checks.readerHit["t-b"] != 0 {
		t.Fatalf("t-b re-probed a plane already found unreachable in this pass (%d)", checks.readerHit["t-b"])
	}
	if got := len(q.List()); got != 2 {
		t.Fatalf("quarantined %d, want 2", got)
	}
	s.Recheck(context.Background()) // still down
	if got := len(q.List()); got != 2 {
		t.Fatalf("a still-failing tenant was released (%d held)", got)
	}
	checks.mu.Lock()
	checks.reader = map[string]error{"t-b": fmt.Errorf("%w: write-capable reader", chclient.ErrReaderUnsafe)}
	checks.mu.Unlock()
	s.Recheck(context.Background())
	if err := q.Check("t-a"); err != nil {
		t.Fatalf("t-a's plane is back but it is still quarantined: %v", err)
	}
	if e, ok := held(q, "t-b"); !ok || e.Reason != tenancy.QuarantineReaderScopeUnproven {
		t.Fatalf("t-b = %+v %v; want it kept, with its cause refreshed to the unproven scope", e, ok)
	}
	if store.count(AuditTenantReleased, "") != 1 || store.count(AuditTenantReleased, "t-a") != 1 ||
		store.count(AuditTenantQuarantined, "") != 2 || store.count(AuditQuarantineCauseChanged, "t-b") != 1 || len(*tenant) != 3 {
		t.Fatalf("audit = provider %+v tenant %+v, want 2 entered + 1 released on each stream and t-b's cause change on the provider stream", store.events, *tenant)
	}
}

// A tenant that is deleted (or no longer isolated) while quarantined is
// released, its release recorded on the provider stream only (it has no
// chain); a canceled recheck (shutdown) never releases anyone; a notice that
// fails is retried until it lands.
func TestQuarantineRecheckEdges(t *testing.T) {
	checks := &fakeChecks{planes: map[string]bool{}}
	tenants := []IsolatedTenant{{ID: "t-gone", Model: "siloed", Status: "active", Residency: "mars"}}
	s, q, store, _ := testSupervisor(t, checks, tenants)
	if _, err := s.Boot(context.Background()); err != nil {
		t.Fatal(err)
	}
	failures := 2
	var landed int
	s.tenant = func(context.Context, tenantNotice) error {
		if failures > 0 {
			failures--
			return errors.New("audit table busy")
		}
		landed++
		return nil
	}
	s.flush(context.Background()) // Start's first flush: the entered receipt fails once
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	s.recheckHeld(canceled, q.List(), nil)
	if _, ok := held(q, "t-gone"); !ok {
		t.Fatal("a canceled recheck released a tenant")
	}
	s.list = func(context.Context) ([]IsolatedTenant, error) { return nil, nil } // the tenant was deleted
	s.Recheck(context.Background())
	if _, ok := held(q, "t-gone"); ok {
		t.Fatal("a deleted tenant stayed quarantined")
	}
	s.Recheck(context.Background())
	s.Recheck(context.Background())
	if landed != 1 || store.count(AuditQuarantineNoticeProviderOnly, "t-gone") != 1 || store.count(AuditTenantReleased, "t-gone") != 1 {
		t.Fatalf("landed %d tenant-chain receipts, provider %+v; want the entered receipt retried until it lands and the erased tenant's release on the provider stream only", landed, store.events)
	}
}

func TestPlaneUnreachableClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errTransport, true},
		{fmt.Errorf("wrapped: %w", breaker.ErrOpen), true},
		{context.DeadlineExceeded, false}, // a budget, never a plane verdict (DPR-380)
		{fmt.Errorf("%w: foreign rows", chclient.ErrReaderUnsafe), false},
		{errors.New("clickhouse: Code: 497. ACCESS_DENIED: not enough privileges"), false},
	} {
		if got := planeUnreachable(tc.err); got != tc.want {
			t.Errorf("planeUnreachable(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func held(q *tenancy.Quarantine, tenantID string) (tenancy.QuarantineEntry, bool) {
	for _, e := range q.List() {
		if e.TenantID == tenantID {
			return e, true
		}
	}
	return tenancy.QuarantineEntry{}, false
}

func (f *fakeChecks) CatchUpSchema(ctx context.Context, id string) error { return f.CatchUp(ctx, id) }
