// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type laneTestRouter struct {
	mu      sync.Mutex
	tenants map[string]string
}

func (r *laneTestRouter) TargetsFor(context.Context, string) (tenancy.Targets, error) {
	return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
}

func (r *laneTestRouter) BusNamespaces(context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.tenants))
	for ns := range r.tenants {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}

func (r *laneTestRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.tenants))
	for ns, tenant := range r.tenants {
		out[ns] = tenant
	}
	return out, nil
}

func (r *laneTestRouter) set(tenants map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants = tenants
}

func TestHotSubscribeNewSiloLane(t *testing.T) {
	oldInterval := busLaneRefreshInterval
	busLaneRefreshInterval = 10 * time.Millisecond
	t.Cleanup(func() { busLaneRefreshInterval = oldInterval })

	router := &laneTestRouter{tenants: map[string]string{"acme": "tenant-a"}}
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan map[string]string, 4)
	done := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		done <- superviseBusLaneRestart(ctx, "test-lane-consumer", log, func(ctx context.Context, snap busLaneSnapshot) error {
			started <- cloneTenantMap(snap.tenants)
			<-ctx.Done()
			return nil
		})
	}()

	first := waitLaneStart(t, started)
	if len(first) != 1 || first["acme"] != "tenant-a" {
		t.Fatalf("initial lane snapshot = %+v", first)
	}
	router.set(map[string]string{"acme": "tenant-a", "beta": "tenant-b"})
	second := waitLaneStart(t, started)
	if len(second) != 2 || second["beta"] != "tenant-b" {
		t.Fatalf("refreshed lane snapshot = %+v", second)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervisor returned error on cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop after context cancellation")
	}
}

func waitLaneStart(t *testing.T, ch <-chan map[string]string) map[string]string {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lane subscriber restart")
		return nil
	}
}

// quarantineAwareLaneRouter leaves a quarantined tenant's lane out, as the
// silo router does.
type quarantineAwareLaneRouter struct{ laneTestRouter }

func (r *quarantineAwareLaneRouter) BusNamespaceTenants(ctx context.Context) (map[string]string, error) {
	all, _ := r.laneTestRouter.BusNamespaceTenants(ctx)
	out := map[string]string{}
	for ns, tenant := range all {
		if tenancy.CheckQuarantine(tenant) == nil {
			out[ns] = tenant
		}
	}
	return out, nil
}

func (r *quarantineAwareLaneRouter) BusNamespaces(ctx context.Context) ([]string, error) {
	m, _ := r.BusNamespaceTenants(ctx)
	out := make([]string, 0, len(m))
	for ns := range m {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out, nil
}

// DPR-389: a quarantine entered at runtime drops the tenant's lane from the
// subscription AT ONCE — not on the next refresh tick — so its records stay
// on the bus instead of reaching a consumer that would have to refuse them.
func TestRuntimeQuarantineUnsubscribesTheLaneAtOnce(t *testing.T) {
	oldInterval := busLaneRefreshInterval
	busLaneRefreshInterval = time.Hour // only the quarantine change can trigger it
	t.Cleanup(func() { busLaneRefreshInterval = oldInterval })
	prevQ := tenancy.CurrentQuarantine()
	q := tenancy.NewQuarantine()
	tenancy.SetQuarantine(q)
	t.Cleanup(func() { tenancy.SetQuarantine(prevQ) })
	router := &quarantineAwareLaneRouter{laneTestRouter{tenants: map[string]string{"acme": "tenant-a", "beta": "tenant-b"}}}
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan map[string]string, 4)
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done }) // runs first: the supervisor stops before the globals reset
	go func() {
		defer close(done)
		_ = superviseBusLaneRestart(ctx, "test-lane-consumer", slog.New(slog.NewTextHandler(io.Discard, nil)),
			func(ctx context.Context, snap busLaneSnapshot) error {
				started <- cloneTenantMap(snap.tenants)
				<-ctx.Done()
				return nil
			})
	}()
	if first := waitLaneStart(t, started); len(first) != 2 {
		t.Fatalf("initial lanes = %+v", first)
	}
	q.Enter(tenancy.QuarantineEntry{TenantID: "tenant-b", Reason: tenancy.QuarantineSchemaIncomplete})
	if next := waitLaneStart(t, started); len(next) != 1 || next["beta"] != "" {
		t.Fatalf("lanes after a runtime quarantine = %+v, want tenant-b's lane dropped", next)
	}
	q.Release("tenant-b")
	if next := waitLaneStart(t, started); len(next) != 2 {
		t.Fatalf("lanes after release = %+v, want tenant-b's lane back", next)
	}
}
