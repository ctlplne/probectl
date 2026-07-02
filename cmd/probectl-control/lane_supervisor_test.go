// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
