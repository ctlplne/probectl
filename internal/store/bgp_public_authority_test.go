// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPublicRoutingAuthorityRequiresTenantBeforeStorageAndCompleteAssignment(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const foreign = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	sc := tenancy.Scope{Tenant: tenancy.ID(tenant)}
	source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, CollectorAgentID: "collector", SourceRef: "ris/mrt_table_dump_v2/rrc00", SenderSerial: "issued", ObservedAt: time.Now()}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		sc     tenancy.Scope
		change func(*BGPPublicRoutingSource)
		want   error
	}{
		{"missing-tenant", t.Context(), sc, nil, entity.ErrScopeMismatch},
		{"foreign-transaction", ctx, tenancy.Scope{Tenant: tenancy.ID(foreign)}, nil, entity.ErrScopeMismatch},
		{"foreign-source", ctx, sc, func(s *BGPPublicRoutingSource) { s.TenantID = foreign }, entity.ErrScopeMismatch},
		{"invalid-context", ctx, sc, func(s *BGPPublicRoutingSource) { s.ContextID = "context" }, entity.ErrInvalidScope},
		{"missing-collector", ctx, sc, func(s *BGPPublicRoutingSource) { s.CollectorAgentID = "" }, entity.ErrInvalidClaim},
		{"missing-source", ctx, sc, func(s *BGPPublicRoutingSource) { s.SourceRef = "" }, entity.ErrInvalidClaim},
		{"noncanonical-source", ctx, sc, func(s *BGPPublicRoutingSource) { s.SourceRef += " " }, entity.ErrInvalidClaim},
		{"missing-sender", ctx, sc, func(s *BGPPublicRoutingSource) { s.SenderSerial = "" }, entity.ErrInvalidClaim},
		{"missing-clock", ctx, sc, func(s *BGPPublicRoutingSource) { s.ObservedAt = time.Time{} }, entity.ErrInvalidClaim},
		{"unavailable-storage", ctx, sc, nil, ErrBGPRoutingSourceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := source
			if tc.change != nil {
				tc.change(&input)
			}
			got, err := (BGPRouting{}).publicSourceAuthorityInScope(tc.ctx, tc.sc, input, false)
			if !errors.Is(err, tc.want) || got != (BGPRoutingSourceAuthority{}) {
				t.Fatal("public routing source accepted incomplete or foreign authority before storage", got, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (BGPRouting{}).publicSourceAuthorityInScope(canceled, sc, source, false); !errors.Is(err, context.Canceled) {
		t.Fatal("public routing source ignored cancellation", err)
	}
}
