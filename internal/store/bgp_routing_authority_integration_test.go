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
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role Postgres and current identity/assignment rows; sender
// serials are modeled through the existing registry fixture, not a TLS proof.
func TestBGPRoutingAuthorityKeepsCurrentTenantOriginPurposeAndAssignmentEpoch(t *testing.T) {
	f := newRoleInputsFixture(t)
	read := func(source BGPRoutingSource) (BGPRoutingSourceAuthority, error) {
		var result BGPRoutingSourceAuthority
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (BGPRouting{}).sourceAuthorityInScope(ctx, sc, source)
			return err
		})
		return result, err
	}
	sources := make([]BGPRoutingSource, len(f.tenants))
	for lane, tenant := range f.tenants {
		var observed time.Time
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed)
		})
		sources[lane] = BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, RouterID: f.routerID,
			CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[tenant+"role-listener"], OriginSerial: f.serials[tenant+"role-router"], ObservedAt: observed}
		got, err := read(sources[lane])
		if err != nil || got.AsOf.Before(observed) || !got.ValidUntil.After(got.AsOf) {
			t.Fatal("owned current routing source was refused", got, err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*BGPRoutingSource)
	}{
		{"foreign-sender", func(s *BGPRoutingSource) { s.SenderSerial = sources[1].SenderSerial }},
		{"foreign-origin", func(s *BGPRoutingSource) { s.OriginSerial = sources[1].OriginSerial }},
		{"wrong-purpose", func(s *BGPRoutingSource) { s.OriginSerial = f.serials[s.TenantID+"role-snmp"] }},
		{"foreign-context", func(s *BGPRoutingSource) { s.ContextID = uuid.NewString() }},
		{"unassigned-router", func(s *BGPRoutingSource) { s.RouterID = f.otherRouter }},
		{"wrong-collector", func(s *BGPRoutingSource) { s.CollectorAgentID = "role-snmp" }},
		{"wrong-origin", func(s *BGPRoutingSource) { s.SourceRef = "other-origin" }},
		{"future-observation", func(s *BGPRoutingSource) { s.ObservedAt = s.ObservedAt.Add(time.Hour) }},
		{"before-issuance", func(s *BGPRoutingSource) { s.ObservedAt = s.ObservedAt.Add(-time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := sources[0]
			tc.change(&source)
			got, err := read(source)
			if !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got != (BGPRoutingSourceAuthority{}) {
				t.Fatal("routing source authority leaked or accepted a foreign/stale credential", got, err)
			}
		})
	}
	rollback := errors.New("roll back modeled source mutation")
	for _, tc := range []struct{ name, sql string }{
		{"sender-revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"origin-revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"sender-purpose", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/wrong-purpose' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"origin-purpose", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/wrong-purpose' WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"sender-expired", `UPDATE agent_identities SET not_after=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"origin-expired", `UPDATE agent_identities SET not_after=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"anchor-cleared", `UPDATE entity_source_contexts SET anchor_entity_id=NULL WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"anchor-changed", `UPDATE entity_source_contexts SET anchor_entity_id=$2 WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"source-rebound", `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"collector-reassigned", `UPDATE entity_agent_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"source-expired", `UPDATE entity_source_contexts SET expires_at=transaction_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"collector-expired", `UPDATE entity_agent_contexts SET expires_at=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"source-removed", `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := sources[0]
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
			err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
				return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					args := []any{source.TenantID}
					if tc.name == "anchor-changed" {
						args = append(args, f.otherRouter)
					}
					if _, err := sc.Q.Exec(ctx, tc.sql, args...); err != nil {
						return err
					}
					got, err := (BGPRouting{}).sourceAuthorityInScope(ctx, sc, source)
					if !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got != (BGPRoutingSourceAuthority{}) {
						t.Fatal("changed source/credential retained routing authority", got, err)
					}
					return rollback
				})
			})
			if !errors.Is(err, rollback) {
				t.Fatal("source mutation proof failed", err)
			}
			for _, original := range sources {
				if _, err := read(original); err != nil {
					t.Fatal("source mutation escaped rollback or changed sibling", err)
				}
			}
		})
	}
}
