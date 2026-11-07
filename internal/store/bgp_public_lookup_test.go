// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPublicSnapshotLookupRequiresTenantAndWholeAdmissionBeforeStorage(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	input, profile := publicSnapshotFixture()
	source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, ObservedAt: input.ObservedAt}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	sc := tenancy.Scope{Tenant: tenancy.ID(tenant)}
	address := netip.MustParseAddr("192.0.2.9")
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		change func(*BGPPublicRoutingSource, *string, *netip.Addr, *BGPRoutingBudget)
		want   error
	}{
		{"missing-tenant", t.Context(), nil, entity.ErrScopeMismatch},
		{"foreign-source", ctx, func(s *BGPPublicRoutingSource, _ *string, _ *netip.Addr, _ *BGPRoutingBudget) {
			s.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}, entity.ErrScopeMismatch},
		{"missing-context", ctx, func(s *BGPPublicRoutingSource, _ *string, _ *netip.Addr, _ *BGPRoutingBudget) { s.ContextID = "" }, entity.ErrInvalidScope},
		{"missing-collector", ctx, func(s *BGPPublicRoutingSource, _ *string, _ *netip.Addr, _ *BGPRoutingBudget) {
			s.CollectorAgentID = ""
		}, entity.ErrInvalidClaim},
		{"invalid-snapshot", ctx, func(_ *BGPPublicRoutingSource, id *string, _ *netip.Addr, _ *BGPRoutingBudget) { *id = "snapshot" }, ErrBGPRoutingView},
		{"invalid-address", ctx, func(_ *BGPPublicRoutingSource, _ *string, a *netip.Addr, _ *BGPRoutingBudget) { *a = netip.Addr{} }, ErrBGPRoutingView},
		{"unadmitted", ctx, func(_ *BGPPublicRoutingSource, _ *string, _ *netip.Addr, p *BGPRoutingBudget) { p.MemoryBytes = 1 }, ErrBGPRoutingBudget},
		{"unavailable-store", ctx, nil, ErrBGPRoutingSourceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, id, a, p := source, input.ObservationID, address, profile
			if tc.change != nil {
				tc.change(&s, &id, &a, &p)
			}
			got, err := (BGPRouting{}).LookupPublicSnapshotInScope(tc.ctx, sc, s, id, a, p, time.Hour)
			if !errors.Is(err, tc.want) || got.Paths != nil || got.Source.TenantID != "" {
				t.Fatal("public lookup exposed partial data before tenant and admission", got, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (BGPRouting{}).LookupPublicSnapshotInScope(canceled, sc, source, input.ObservationID, address, profile, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal("public lookup ignored cancellation", err)
	}
}
