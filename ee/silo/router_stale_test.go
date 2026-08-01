// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
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

func TestRouterCanceledOrExpiredRefreshNeverServesStale(t *testing.T) {
	for _, tc := range []struct {
		name    string
		context func(t *testing.T) context.Context
		wantErr error
	}{
		{
			name: "canceled",
			context: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			context: func(t *testing.T) context.Context {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
			wantErr: context.DeadlineExceeded,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ttl := time.Minute
			r := NewRouter(nil, nil, ttl)
			now := time.Unix(1_750_000_000, 0)
			r.now = func() time.Time { return now }
			r.fetch = func(context.Context) (map[string]registryRow, error) {
				return map[string]registryRow{
					"tenant-a": {slug: "a", status: "active", model: tenancy.IsolationSiloed},
				}, nil
			}
			if _, err := r.TargetsFor(context.Background(), "tenant-a"); err != nil {
				t.Fatalf("seed snapshot: %v", err)
			}

			now = now.Add(ttl + time.Second) // stale, but still within stale grace.
			r.fetch = func(ctx context.Context) (map[string]registryRow, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			if _, err := r.TargetsFor(tc.context(t), "tenant-a"); !errors.Is(err, tc.wantErr) {
				t.Fatalf("refresh error = %v, want %v rather than stale fallback", err, tc.wantErr)
			}
			if stats := r.Stats(); stats.StaleServes != 0 {
				t.Fatalf("canceled refresh counted as stale success: %+v", stats)
			}
		})
	}
}

func TestRouterBlockedRefreshDoesNotBlockSecondTenantOrOverwriteNewerSnapshot(t *testing.T) {
	r := NewRouter(nil, nil, time.Minute)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var fetches atomic.Int32
	r.fetch = func(context.Context) (map[string]registryRow, error) {
		switch fetches.Add(1) {
		case 1:
			close(firstStarted)
			<-releaseFirst
			// This older snapshot must not overwrite the newer second fetch.
			return map[string]registryRow{
				"tenant-a": {slug: "a", status: "active", model: tenancy.IsolationSiloed},
			}, nil
		default:
			return map[string]registryRow{
				"tenant-a": {slug: "a", status: "active", model: tenancy.IsolationSiloed},
				"tenant-b": {slug: "b", status: "active", model: tenancy.IsolationPooled},
			}, nil
		}
	}

	type result struct {
		targets tenancy.Targets
		err     error
	}
	firstDone := make(chan result, 1)
	go func() {
		targets, err := r.TargetsFor(context.Background(), "tenant-a")
		firstDone <- result{targets: targets, err: err}
	}()
	<-firstStarted

	secondDone := make(chan result, 1)
	go func() {
		targets, err := r.TargetsFor(context.Background(), "tenant-b")
		secondDone <- result{targets: targets, err: err}
	}()

	var second result
	select {
	case second = <-secondDone:
	case <-time.After(200 * time.Millisecond):
		close(releaseFirst)
		<-firstDone
		<-secondDone
		t.Fatal("tenant-b routing blocked behind tenant-a's unbounded registry refresh")
	}
	if second.err != nil || second.targets.Model != tenancy.IsolationPooled {
		close(releaseFirst)
		<-firstDone
		t.Fatalf("tenant-b route = %+v, %v", second.targets, second.err)
	}

	close(releaseFirst)
	first := <-firstDone
	if first.err != nil || first.targets.Model != tenancy.IsolationSiloed {
		t.Fatalf("tenant-a route = %+v, %v", first.targets, first.err)
	}
	if fetches.Load() < 2 {
		t.Fatalf("blocked refresh serialized all tenants: fetches=%d", fetches.Load())
	}
	if targets, err := r.TargetsFor(context.Background(), "tenant-b"); err != nil || targets.Model != tenancy.IsolationPooled {
		t.Fatalf("older refresh overwrote newer tenant-b snapshot: targets=%+v err=%v", targets, err)
	}
}
