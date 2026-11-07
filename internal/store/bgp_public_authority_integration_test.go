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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Application-role PostgreSQL/RLS with modeled issued collector credentials;
// this does not claim actual public-source transport or complete RIB proof.
func TestPublicRoutingAuthorityKeepsTenantPurposeCurrentCredentialAndAssignmentBirth(t *testing.T) {
	f := newRoleInputsFixture(t)
	const ref = "ris/mrt_table_dump_v2/rrc00"
	sources := make([]BGPPublicRoutingSource, len(f.tenants))
	read := func(source BGPPublicRoutingSource) (BGPRoutingSourceAuthority, error) {
		var out BGPRoutingSourceAuthority
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).publicSourceAuthorityInScope(ctx, sc, source, false)
			return err
		})
		return out, err
	}
	for lane, tenant := range f.tenants {
		source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, CollectorAgentID: "role-listener", SenderSerial: f.serials[tenant+"role-listener"], SourceRef: ref}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id)
 VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, ref, f.contextID); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&source.ObservedAt)
		})
		sources[lane] = source
		got, err := read(source)
		if err != nil || got.AsOf.Before(source.ObservedAt) || !got.ValidUntil.After(got.AsOf) {
			t.Fatal("current owned public collector was refused", got, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_source_contexts WHERE source_kind='public_bgp' AND source_ref=$1`, ref).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Fatal("public source assignment crossed storage tenant isolation", count)
			}
			return nil
		})
	}
	for _, change := range []func(*BGPPublicRoutingSource){
		func(s *BGPPublicRoutingSource) { s.SenderSerial = sources[1].SenderSerial },
		func(s *BGPPublicRoutingSource) { s.SenderSerial = f.serials[s.TenantID+"role-router"] },
		func(s *BGPPublicRoutingSource) { s.ContextID = uuid.NewString() },
		func(s *BGPPublicRoutingSource) { s.SourceRef = "routeviews/mrt_table_dump_v2/rrc00" },
		func(s *BGPPublicRoutingSource) { s.ObservedAt = s.ObservedAt.AddDate(0, 0, 1) },
		func(s *BGPPublicRoutingSource) { s.ObservedAt = s.ObservedAt.AddDate(0, 0, -1) },
	} {
		source := sources[0]
		change(&source)
		if got, err := read(source); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got != (BGPRoutingSourceAuthority{}) {
			t.Fatal("foreign, wrong-purpose, unassigned or stale public source retained authority", got, err)
		}
	}
	rollback := errors.New("rollback public source mutation")
	for _, tc := range []struct{ name, sql string }{
		{"revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"purpose", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/wrong-purpose' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"expired", `UPDATE agent_identities SET not_after=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"rebound", `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='public_bgp'`},
		{"assignment-replaced", `UPDATE entity_agent_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"withdrawn", `UPDATE entity_source_contexts SET expires_at=transaction_timestamp() WHERE tenant_id=$1 AND source_kind='public_bgp'`},
		{"collector-withdrawn", `UPDATE entity_agent_contexts SET expires_at=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"deleted", `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND source_kind='public_bgp'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := sources[0]
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
			err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
				return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := sc.Q.Exec(ctx, tc.sql, source.TenantID); err != nil {
						return err
					}
					got, err := (BGPRouting{}).publicSourceAuthorityInScope(ctx, sc, source, false)
					if !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got != (BGPRoutingSourceAuthority{}) {
						t.Fatal("revoked or replaced public source retained current routing authority", got, err)
					}
					return rollback
				})
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			for _, original := range sources {
				if _, err := read(original); err != nil {
					t.Fatal("public source mutation escaped rollback or changed sibling", err)
				}
			}
		})
	}
	for _, statement := range []string{
		`UPDATE entity_source_contexts SET anchor_entity_id=$2 WHERE tenant_id=$1 AND source_kind='public_bgp'`,
		`UPDATE entity_source_contexts SET routing_epoch=$2,routing_assigned_at=clock_timestamp(),routing_bindings='[]' WHERE tenant_id=$1 AND source_kind='public_bgp'`,
	} {
		f.in(sources[0].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `SAVEPOINT public_source_shape`)
			if err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, statement, sources[0].TenantID, f.routerID); err == nil {
				t.Fatal("public assignment acquired router/BMP authority")
			}
			_, err = sc.Q.Exec(ctx, `ROLLBACK TO SAVEPOINT public_source_shape`)
			return err
		})
	}
}
