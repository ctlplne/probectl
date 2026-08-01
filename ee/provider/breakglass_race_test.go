// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
)

// pauseFirstMutationStore opens a deterministic scheduling window immediately
// before the first audited transaction. Both the vulnerable implementation and
// the fixed implementation cross this seam, but only the vulnerable one makes
// its authorization decision before it.
type pauseFirstMutationStore struct {
	Store
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func newPauseFirstMutationStore(store Store) *pauseFirstMutationStore {
	return &pauseFirstMutationStore{
		Store:   store,
		entered: make(chan struct{}),
		resume:  make(chan struct{}),
	}
}

func (s *pauseFirstMutationStore) WithAuditedMutation(
	ctx context.Context,
	sink AuditSink,
	fn AuditedMutation,
) error {
	pause := false
	s.once.Do(func() {
		pause = true
		close(s.entered)
	})
	if pause {
		select {
		case <-s.resume:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.WithAuditedMutation(ctx, sink, fn)
}

type breakGlassRaceFixture struct {
	store     *MemStore
	pausing   *pauseFirstMutationStore
	service   *Service
	audit     *memAudit
	telemetry *countingTelemetry
	operator  Operator
	grant     Grant
	now       *time.Time
}

func newBreakGlassRaceFixture(t *testing.T) *breakGlassRaceFixture {
	t.Helper()
	ctx := context.Background()
	store := NewMemStore()
	pausing := newPauseFirstMutationStore(store)
	t.Cleanup(func() {
		select {
		case <-pausing.resume:
		default:
			close(pausing.resume)
		}
	})
	audit := &memAudit{}
	telemetry := &countingTelemetry{}
	now := time.Now().UTC()
	service, err := NewService(
		pausing,
		audit,
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		telemetry,
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.withClock(func() time.Time { return now })

	operator, err := store.CreateOperator(ctx, Operator{
		Email: "race-operator@msp.example",
		Name:  "Race Operator",
		Role:  RoleOperator,
	}, crypto.Hash([]byte("race-enrollment-token")))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(ctx, "race-tenant", "Race Tenant", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	consentedAt := now.Add(-time.Minute)
	grant, err := store.CreateGrant(ctx, Grant{
		OperatorID:  operator.ID,
		TenantID:    tenant.ID,
		Reason:      "deterministic authorization race regression",
		Scope:       "read",
		GrantedBy:   operator.Email,
		GrantedAt:   now.Add(-2 * time.Minute),
		ExpiresAt:   now.Add(time.Minute),
		ConsentedBy: "tenant-admin@example.test",
		ConsentedAt: &consentedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	return &breakGlassRaceFixture{
		store:     store,
		pausing:   pausing,
		service:   service,
		audit:     audit,
		telemetry: telemetry,
		operator:  operator,
		grant:     grant,
		now:       &now,
	}
}

type breakGlassRaceResult struct {
	data any
	err  error
}

func awaitBreakGlassRaceSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for break-glass access to reach the audited mutation")
	}
}

func awaitBreakGlassRaceResult(t *testing.T, result <-chan breakGlassRaceResult) breakGlassRaceResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for break-glass access result")
		return breakGlassRaceResult{}
	}
}

func (f *breakGlassRaceFixture) startAccess() <-chan breakGlassRaceResult {
	out := make(chan breakGlassRaceResult, 1)
	go func() {
		data, err := f.service.BreakGlassResults(context.Background(), f.operator, f.grant.ID)
		out <- breakGlassRaceResult{data: data, err: err}
	}()
	return out
}

func (f *breakGlassRaceFixture) assertDeniedWithoutUse(t *testing.T, result breakGlassRaceResult) {
	t.Helper()
	if !errors.Is(result.err, ErrNotConsented) {
		t.Fatalf("BreakGlassResults error = %v, want %v", result.err, ErrNotConsented)
	}
	if result.data != nil {
		t.Fatalf("BreakGlassResults data = %#v, want nil", result.data)
	}
	if f.telemetry.calls != 0 {
		t.Fatalf("telemetry reads = %d, want 0", f.telemetry.calls)
	}
	if got := f.audit.count("provider.breakglass_access"); got != 0 {
		t.Fatalf("break-glass access audits = %d, want 0", got)
	}
	stored, err := f.store.GetGrant(context.Background(), f.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UseCount != 0 {
		t.Fatalf("grant use_count = %d, want 0", stored.UseCount)
	}
}

func TestBreakGlassAccessLosesRevokeRace(t *testing.T) {
	f := newBreakGlassRaceFixture(t)
	result := f.startAccess()
	awaitBreakGlassRaceSignal(t, f.pausing.entered)

	if _, err := f.service.Revoke(context.Background(), "incident-commander@msp.example", f.grant.ID); err != nil {
		t.Fatal(err)
	}
	close(f.pausing.resume)

	f.assertDeniedWithoutUse(t, awaitBreakGlassRaceResult(t, result))
	if got := f.audit.count("provider.breakglass_revoke"); got != 1 {
		t.Fatalf("break-glass revoke audits = %d, want 1", got)
	}
}

func TestBreakGlassAccessLosesExpiryRace(t *testing.T) {
	f := newBreakGlassRaceFixture(t)
	result := f.startAccess()
	awaitBreakGlassRaceSignal(t, f.pausing.entered)

	*f.now = f.grant.ExpiresAt
	close(f.pausing.resume)

	f.assertDeniedWithoutUse(t, awaitBreakGlassRaceResult(t, result))
}
