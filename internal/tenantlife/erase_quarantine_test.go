// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// D-62: erasing a quarantined tenant is refused before any store is touched.
// The stores the quarantine cannot reach would fail while the ones it can
// (objects, series, keys) would be destroyed — a half-erased tenant.
func TestEraseRefusesAQuarantinedTenantBeforeTouchingAnyStore(t *testing.T) {
	prev := tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetQuarantine(prev) })
	q := tenancy.NewQuarantine()
	tenancy.SetQuarantine(q)
	q.Enter(tenancy.QuarantineEntry{TenantID: "victim", Reason: tenancy.QuarantinePlaneMissing, Plane: "mars"})

	ctx := context.Background()
	flows := flowstore.NewMemory()
	if err := flows.Insert(ctx, []flowstore.Row{{TenantID: "victim", AgentID: "a", Exporter: "e",
		TS: time.Now(), SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", Bytes: 1, Packets: 1}}); err != nil {
		t.Fatal(err)
	}
	e := New(nil, flows, nil, nil, nil, "", nil)
	att, err := e.Erase(ctx, "victim", "victim-slug", "operator")
	if !errors.Is(err, tenancy.ErrTenantQuarantined) || att.Complete {
		t.Fatalf("Erase = %+v, %v; want the quarantine refusal and an incomplete attestation", att, err)
	}
	if n := flows.Len(); n != 1 {
		t.Fatalf("flows after a refused erasure = %d; want untouched", n)
	}
	q.Release("victim")
	if _, err := e.Erase(ctx, "victim", "victim-slug", "operator"); err != nil {
		t.Fatalf("erasure after release: %v", err)
	}
}
