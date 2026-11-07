// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func proveRoutingReportPublicationScope(t *testing.T, f *roleInputsFixture, lane int, raw [32]byte, input BGPRoutingFlowInput, ref BGPRoutingCaptureReference) {
	t.Helper()
	tenant := f.tenants[lane]
	reads := []flowstore.RoutingCaptureRead{{Sender: "routing-flow", Witness: entity.FlowCaptureWitness{RawDigest: raw, Input: input}, Ref: ref}}
	calls := 0
	authorize := func(_ context.Context, record entity.ContextRecord) error {
		calls++
		if record.TenantID != tenant || record.ContextID != f.contextID {
			t.Fatal("report source authorized a foreign context")
		}
		return nil
	}
	err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if rows, err := (BGPRouting{}).FlowCaptureQueryProjectionsForReportInScope(ctx, sc, reads, routingViewBudget(), authorize); !errors.Is(err, errBGPRoutingReadSnapshot) || rows != nil || calls != 0 {
			t.Fatal("report routing reader accepted an unheld publication audit lock", calls, err)
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, f.tenants[1-lane]); err != nil {
			return err
		}
		if rows, err := (BGPRouting{}).FlowCaptureQueryProjectionsForReportInScope(ctx, sc, reads, routingViewBudget(), authorize); !errors.Is(err, errBGPRoutingReadSnapshot) || rows != nil || calls != 0 {
			t.Fatal("report routing reader borrowed a sibling tenant audit lock", calls, err)
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		// The narrow report method does not weaken ordinary reader admission.
		if rows, err := (BGPRouting{}).FlowCaptureQueryProjectionsInScope(ctx, sc, reads, routingViewBudget(), authorize); !errors.Is(err, errBGPRoutingReadSnapshot) || rows != nil || calls != 0 {
			t.Fatal("report publication authority escaped into an ordinary routing read", calls, err)
		}
		rows, err := (BGPRouting{}).FlowCaptureQueryProjectionsForReportInScope(ctx, sc, reads, routingViewBudget(), authorize)
		if err != nil || len(rows) != 1 || calls != 1 || rows[0].Key != ref.Key || rows[0].Clock != ref.CapturedAt.UnixNano() || rows[0].Fields["src_bgp_provenance"] != "router_selected" {
			t.Fatal("locked report routing read lost its exact original current source", calls, err)
		}
		denied := errors.New("current report routing context denied")
		if rows, err := (BGPRouting{}).FlowCaptureQueryProjectionsForReportInScope(ctx, sc, reads, routingViewBudget(), func(context.Context, entity.ContextRecord) error { return denied }); !errors.Is(err, denied) || rows != nil {
			t.Fatal("locked report routing read bypassed current context authority", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
