// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBGPRoutingAuthorityRequiresTenantAndCompleteSourceBeforeStorage(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	foreign := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	scope := tenancy.Scope{Tenant: tenancy.ID(tenant)}
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"},
		RouterID: "33333333-3333-4333-8333-333333333333", CollectorAgentID: "collector", SourceRef: "router", SenderSerial: "abc", OriginSerial: "def", ObservedAt: time.Now()}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		scope  tenancy.Scope
		change func(*BGPRoutingSource)
		want   error
	}{
		{"missing-tenant", t.Context(), scope, nil, entity.ErrScopeMismatch},
		{"foreign-transaction", ctx, tenancy.Scope{Tenant: tenancy.ID(foreign)}, nil, entity.ErrScopeMismatch},
		{"foreign-source", ctx, scope, func(s *BGPRoutingSource) { s.TenantID = foreign }, entity.ErrScopeMismatch},
		{"invalid-context", ctx, scope, func(s *BGPRoutingSource) { s.ContextID = "context" }, entity.ErrInvalidScope},
		{"noncanonical-router", ctx, scope, func(s *BGPRoutingSource) { s.RouterID = strings.ReplaceAll(s.RouterID, "-", "") }, entity.ErrInvalidScope},
		{"missing-collector", ctx, scope, func(s *BGPRoutingSource) { s.CollectorAgentID = "" }, entity.ErrInvalidClaim},
		{"missing-source", ctx, scope, func(s *BGPRoutingSource) { s.SourceRef = "" }, entity.ErrInvalidClaim},
		{"missing-sender", ctx, scope, func(s *BGPRoutingSource) { s.SenderSerial = "" }, entity.ErrInvalidClaim},
		{"missing-origin", ctx, scope, func(s *BGPRoutingSource) { s.OriginSerial = "" }, entity.ErrInvalidClaim},
		{"missing-clock", ctx, scope, func(s *BGPRoutingSource) { s.ObservedAt = time.Time{} }, entity.ErrInvalidClaim},
		{"unavailable-storage", ctx, scope, nil, ErrBGPRoutingSourceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := source
			if tc.change != nil {
				tc.change(&input)
			}
			got, err := (BGPRouting{}).sourceAuthorityInScope(tc.ctx, tc.scope, input)
			if !errors.Is(err, tc.want) || got != (BGPRoutingSourceAuthority{}) {
				t.Fatal("routing authority admitted incomplete or foreign scope before storage", got, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (BGPRouting{}).sourceAuthorityInScope(canceled, scope, source); !errors.Is(err, context.Canceled) {
		t.Fatal("routing authority ignored cancellation before storage", err)
	}
}
