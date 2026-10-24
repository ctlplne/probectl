// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// D-62: a quarantined tenant's record on a shared lane is acknowledged
// without reaching the handler (no write, no SIEM forward, no export), and a
// handler's quarantine refusal never stalls the lane; every other tenant's
// record and every other error pass through unchanged.
func TestLaneGuardAcksQuarantinedTenantsOnly(t *testing.T) {
	prev := tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetQuarantine(prev) })
	q := tenancy.NewQuarantine()
	tenancy.SetQuarantine(q)
	q.Enter(tenancy.QuarantineEntry{TenantID: "t-q", Reason: tenancy.QuarantineReaderScopeUnproven})

	var handled []string
	transient := errors.New("store timeout")
	h := guardQuarantined("g", func(_ context.Context, m bus.Message, lane string) error {
		handled = append(handled, string(m.Key)+"/"+lane)
		switch string(m.Key) {
		case "t-late":
			return fmt.Errorf("persist: %w", &tenancy.QuarantinedError{})
		case "t-err":
			return transient
		}
		return nil
	})
	before := QuarantineDroppedTotal()
	ctx := context.Background()
	if err := h(ctx, bus.Message{Key: []byte("t-q")}, ""); err != nil {
		t.Fatalf("shared-lane quarantined record: %v", err)
	}
	if err := h(ctx, bus.Message{Key: []byte("x")}, "t-q"); err != nil {
		t.Fatalf("lane-bound quarantined record: %v", err)
	}
	if err := h(ctx, bus.Message{Key: []byte("t-late")}, ""); err != nil {
		t.Fatalf("a handler's quarantine refusal must be acknowledged, got %v", err)
	}
	if err := h(ctx, bus.Message{Key: []byte("t-err")}, ""); !errors.Is(err, transient) {
		t.Fatalf("another tenant's transient error must still refuse the ack, got %v", err)
	}
	if err := h(ctx, bus.Message{Key: []byte("t-ok")}, ""); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(handled) != "[t-late/ t-err/ t-ok/]" {
		t.Fatalf("handled = %v, want the quarantined tenant's records never handled", handled)
	}
	if got := QuarantineDroppedTotal() - before; got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}
}
