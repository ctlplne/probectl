// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type quarantineTSDB struct {
	mu      sync.Mutex
	tenants []string
}

func (w *quarantineTSDB) Write(_ context.Context, s []tsdb.Series) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, x := range s {
		w.tenants = append(w.tenants, x.Labels["tenant_id"])
	}
	return nil
}
func (w *quarantineTSDB) Close() error { return nil }

func runQuarantineResultConsumer(t *testing.T, quarantined bool) []string {
	q := tenancy.NewQuarantine()
	if quarantined {
		q.Enter(tenancy.QuarantineEntry{TenantID: "t-x", Reason: tenancy.QuarantinePlaneUnreachable, Plane: "eu"})
	}
	prevQ, prevR := tenancy.CurrentQuarantine(), tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetQuarantine(prevQ); tenancy.SetRouter(prevR) })
	tenancy.SetQuarantine(q)
	tenancy.SetRouter(quarantineRouter(q))
	b := bus.NewMemory()
	w := &quarantineTSDB{}
	c := pipeline.NewConsumer(b, w, "d62-results", slog.New(slog.NewTextHandler(io.Discard, nil))).WithTenantBinding(acceptAllBinding{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := c.Run(ctx); err != nil {
			t.Logf("Run: %v", err)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	payload, _ := proto.Marshal(&resultv1.Result{TenantId: "t-x", AgentId: "a1", CanaryType: "noop", Success: true})
	_ = b.Publish(ctx, bus.NetworkResultsTopic, bus.TenantKey("t-x", "a1"), payload)
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.tenants...)
}

// DPR-369 (the reviewer's ADV4-2 probe): the results consumer, which does
// not run through RunLanes, writes nothing to the metrics store for a
// quarantined tenant's shared-lane result.
func TestQuarantinedTenantsSharedLaneResultWritesNoSeries(t *testing.T) {
	if got := runQuarantineResultConsumer(t, false); len(got) != 0 {
		t.Errorf("not quarantined: siloed tenant's shared-lane result wrote TSDB series %v (want misrouted refusal)", got)
	} else {
		t.Log("not quarantined: shared-lane result refused, no TSDB write (expected)")
	}
	if got := runQuarantineResultConsumer(t, true); len(got) != 0 {
		t.Errorf("QUARANTINED: the quarantined tenant's shared-lane result wrote %d TSDB series for tenants %v", len(got), got)
	}
}

type acceptAllBinding struct{}

func (acceptAllBinding) Verify(context.Context, string, string) error { return nil }
