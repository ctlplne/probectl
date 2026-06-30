// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package silo

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// U-090: on registry errors the router may serve a stale snapshot for at most
// ONE extra TTL, counted and surfaced; beyond the cap it fails closed with an
// explicit error naming the snapshot age.
func TestRouterStaleCapOneTTL(t *testing.T) {
	ttl := 10 * time.Second
	r := NewRouter(nil, nil, ttl)

	clock := time.Unix(1_750_000_000, 0)
	r.now = func() time.Time { return clock }

	healthy := map[string]registryRow{
		"t-silo": {slug: "acme", status: "active", model: tenancy.IsolationSiloed, residency: "eu"},
	}
	registryDown := errors.New("connection refused")
	failing := false
	r.fetch = func(context.Context) (map[string]registryRow, error) {
		if failing {
			return nil, registryDown
		}
		return healthy, nil
	}

	// t0: healthy fetch seeds the snapshot.
	if _, err := r.TargetsFor(context.Background(), "t-silo"); err != nil {
		t.Fatalf("healthy load: %v", err)
	}

	// t+15s (stale, within the 1×TTL grace): registry down → stale snapshot
	// served, counted, last error recorded.
	failing = true
	clock = clock.Add(15 * time.Second)
	tg, err := r.TargetsFor(context.Background(), "t-silo")
	if err != nil {
		t.Fatalf("within stale cap should serve the snapshot: %v", err)
	}
	if tg.Model != tenancy.IsolationSiloed {
		t.Fatalf("stale snapshot lost the silo model: %+v", tg)
	}
	st := r.Stats()
	if st.StaleServes != 1 || !strings.Contains(st.LastError, "connection refused") {
		t.Fatalf("stale serving must be surfaced: %+v", st)
	}

	// t+25s (beyond fetched+2×TTL): fail closed with an explicit error.
	clock = clock.Add(10 * time.Second)
	if _, err := r.TargetsFor(context.Background(), "t-silo"); err == nil {
		t.Fatal("beyond the stale cap the router must refuse, not route on ancient state")
	} else if !strings.Contains(err.Error(), "stale cap") {
		t.Fatalf("error should name the stale cap: %v", err)
	}

	// Recovery: registry back → fresh snapshot, error cleared.
	failing = false
	if _, err := r.TargetsFor(context.Background(), "t-silo"); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if st := r.Stats(); st.LastError != "" {
		t.Fatalf("recovery should clear the last error: %+v", st)
	}
}

// A cold router (no snapshot ever) gets NO stale grace: first failure is
// already an explicit error (fail closed from boot).
func TestRouterColdStartFailsClosed(t *testing.T) {
	r := NewRouter(nil, nil, time.Second)
	r.fetch = func(context.Context) (map[string]registryRow, error) {
		return nil, errors.New("registry down")
	}
	if _, err := r.TargetsFor(context.Background(), "any"); err == nil {
		t.Fatal("cold start with a down registry must error, never default-route")
	}
}

func TestRouterUnknownTenantFailsClosed(t *testing.T) {
	r := NewRouter(nil, nil, time.Second)
	r.fetch = func(context.Context) (map[string]registryRow, error) {
		return map[string]registryRow{
			"t-pool": {slug: "pool", status: "active", model: tenancy.IsolationPooled},
		}, nil
	}

	targets, err := r.TargetsFor(context.Background(), "t-pool")
	if err != nil {
		t.Fatalf("explicit pooled registry row should route: %v", err)
	}
	if targets.Model != tenancy.IsolationPooled || targets.PGSchema != "" || targets.CHDatabase != "" {
		t.Fatalf("explicit pooled row routed unexpectedly: %+v", targets)
	}

	if _, err := r.TargetsFor(context.Background(), "missing"); !errors.Is(err, ErrUnknownTenant) {
		t.Fatalf("unknown tenant must fail closed with ErrUnknownTenant, got %v", err)
	}
}
