// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-369 (the reviewer's ADV4-2 probe): a quarantined SILOED tenant's record on the SHARED lane, keyed the
// way production keys it (bus.TenantKey(tenant, agent) -> "t-x|bN").
func runQuarantineSharedLane(t *testing.T, quarantined bool, key []byte) []string {
	q := tenancy.NewQuarantine()
	if quarantined {
		q.Enter(tenancy.QuarantineEntry{TenantID: "t-x", Reason: tenancy.QuarantinePlaneUnreachable, Plane: "eu"})
	}
	prevQ := tenancy.CurrentQuarantine()
	prevR := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetQuarantine(prevQ); tenancy.SetRouter(prevR) })
	tenancy.SetQuarantine(q)
	tenancy.SetRouter(quarantineRouter(q))

	b := bus.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var handled []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = pipeline.RunLanes(ctx, b, bus.NetworkResultsTopic, "d62-shared", nil, func(_ context.Context, m bus.Message, _ string) error {
			mu.Lock()
			handled = append(handled, string(m.Key))
			mu.Unlock()
			return nil
		})
	}()
	time.Sleep(100 * time.Millisecond)
	if err := b.Publish(ctx, bus.NetworkResultsTopic, key, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), handled...)
}

func TestQuarantinedTenantsSharedLaneRecordIsRefusedThroughRunLanes(t *testing.T) {
	key := bus.TenantKey("t-x", "agent-1")
	t.Logf("production key shape: %q", key)
	if h := runQuarantineSharedLane(t, false, key); len(h) != 0 {
		t.Errorf("NOT quarantined: siloed tenant's shared-lane record reached the handler %v (want rejected as misrouted)", h)
	} else {
		t.Logf("NOT quarantined: shared-lane record rejected as misrouted (expected)")
	}
	if h := runQuarantineSharedLane(t, true, key); len(h) != 0 {
		t.Errorf("QUARANTINED: the quarantined tenant's shared-lane record reached the handler: %v", h)
	}
	if h := runQuarantineSharedLane(t, true, []byte("t-x")); len(h) != 0 {
		t.Errorf("QUARANTINED plain key: reached handler %v", h)
	} else {
		t.Logf("QUARANTINED plain key (the shape the unit test uses): guarded")
	}
}
