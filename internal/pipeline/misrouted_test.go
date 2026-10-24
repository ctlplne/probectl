// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// misrouteRouter routes "tenant-silo" to its own lane and "tenant-pool" to
// the shared one; any other tenant is unknown to the registry.
type misrouteRouter struct{ tenancy.PooledRouter }

func (misrouteRouter) TargetsFor(_ context.Context, tenant string) (tenancy.Targets, error) {
	switch tenant {
	case "tenant-silo":
		return tenancy.Targets{Model: tenancy.IsolationSiloed, BusNamespace: "t-silo"}, nil
	case "tenant-pool":
		return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
	}
	return tenancy.Targets{}, errors.New("unknown tenant")
}

func withMisrouteRouter(t *testing.T) {
	t.Helper()
	tenancy.SetRouter(misrouteRouter{})
	t.Cleanup(func() { tenancy.SetRouter(nil) })
}

// The G9 siloed leg's plant 2 (siloed results published on the shared lane)
// was accepted under the record's tenant. A shared-lane record of a tenant
// the router sends to its own lane is refused and counted; a pooled tenant's
// shared-lane record, and anything the router cannot place, passes to the
// consumer's own verification.
func TestRefuseMisroutedShared(t *testing.T) {
	withMisrouteRouter(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		key  []byte
		want bool
	}{
		{"siloed tenant on the shared lane", bus.TenantKey("tenant-silo", "agent-1"), true},
		{"siloed tenant, unbucketed key", []byte("tenant-silo"), true},
		{"pooled tenant on the shared lane", bus.TenantKey("tenant-pool", "agent-1"), false},
		{"a key that names no tenant", []byte("perf-warmup"), false},
		{"no key", nil, false},
	} {
		before := TenantRejectedTotal()
		got := refuseMisroutedShared(ctx, nil, "test", bus.Message{Topic: bus.NetworkResultsTopic, Key: tc.key})
		if got != tc.want {
			t.Errorf("%s: refused = %t, want %t", tc.name, got, tc.want)
		}
		if counted := TenantRejectedTotal() - before; (counted == 1) != tc.want {
			t.Errorf("%s: tenant-rejected counter moved by %d", tc.name, counted)
		}
	}
}

// RunLanes refuses the misrouted record on the shared lane and still delivers
// the siloed tenant's own lane and the pooled tenant's shared-lane record.
func TestRunLanesRefusesASiloedTenantOnTheSharedLane(t *testing.T) {
	withMisrouteRouter(t)
	b := bus.NewMemory()
	base := bus.NetworkResultsTopic
	lane, err := bus.TopicFor("t-silo", base)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := map[string]string{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = RunLanes(ctx, b, base, "test-grp", map[string]string{"t-silo": "tenant-silo"}, func(_ context.Context, m bus.Message, laneTenant string) error {
			mu.Lock()
			got[string(m.Value)] = laneTenant
			mu.Unlock()
			return nil
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_ = b.Publish(ctx, base, bus.TenantKey("tenant-silo", "a"), []byte("silo-on-shared"))
		_ = b.Publish(ctx, base, bus.TenantKey("tenant-pool", "a"), []byte("pool-on-shared"))
		_ = b.Publish(ctx, lane, bus.TenantKey("tenant-silo", "a"), []byte("silo-on-own-lane"))
		mu.Lock()
		_, pooled := got["pool-on-shared"]
		_, own := got["silo-on-own-lane"]
		mu.Unlock()
		if pooled && own {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lanes did not deliver: %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if lt, delivered := got["silo-on-shared"]; delivered {
		t.Fatalf("a siloed tenant's record on the shared lane reached the handler (lane tenant %q)", lt)
	}
	if got["silo-on-own-lane"] != "tenant-silo" || got["pool-on-shared"] != "" {
		t.Fatalf("lane tenants = %v, want the siloed lane bound to tenant-silo and the pooled record on the shared lane", got)
	}
}

// The three consumers that fan out over lanes themselves refuse the same
// record before decoding it, and count it as a tenant rejection.
func TestBespokeLaneConsumersRefuseASiloedTenantOnTheSharedLane(t *testing.T) {
	withMisrouteRouter(t)
	ctx := context.Background()
	b := bus.NewMemory()
	msg := bus.Message{Topic: bus.NetworkResultsTopic, Key: bus.TenantKey("tenant-silo", "a"), Value: []byte("not decoded")}

	results := NewConsumer(b, nil, "", nil)
	if err := results.handleLane(ctx, msg, topicGroup{topic: bus.NetworkResultsTopic}); err != nil || results.rejectedTenant.Load() != 1 {
		t.Errorf("result consumer: err %v, tenant rejections %d, want the record refused", err, results.rejectedTenant.Load())
	}
	flows := NewFlowConsumer(b, nil, nil, nil)
	if err := flows.handleLane(ctx, msg, bus.FlowEventsTopic, ""); err != nil || flows.RejectedBatches() != 1 {
		t.Errorf("flow consumer: err %v, rejections %d, want the batch refused", err, flows.RejectedBatches())
	}
	devices := NewDeviceConsumer(b, nil, nil)
	if err := devices.handleLane(ctx, msg, bus.DeviceMetricsTopic, ""); err != nil || devices.rejected.Load() != 1 {
		t.Errorf("device consumer: err %v, rejections %d, want the batch refused", err, devices.rejected.Load())
	}
}
