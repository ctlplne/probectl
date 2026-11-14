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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real app-role/RLS with modeled certificate rotation. Original validity and
// current active identities are separate; no physical sender is claimed here.
func TestHistoricalRoutingOriginalExpiryKeepsCurrentIdentityRevocationAndSourceBoundary(t *testing.T) {
	f := newRoleInputsFixture(t)
	originals := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	for _, source := range originals {
		f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities(tenant_id,agent_id,spiffe_id,serial,not_after,issued_at,rotated_from)
 SELECT tenant_id,agent_id,spiffe_id,serial||'aa',clock_timestamp()+interval '1 hour',clock_timestamp(),serial
 FROM agent_identities WHERE tenant_id=$1 AND serial=ANY($2::text[])`, source.TenantID, []string{source.SenderSerial, source.OriginSerial}); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=$3::timestamptz+interval '1 microsecond' WHERE tenant_id=$1 AND serial=ANY($2::text[])`, source.TenantID, []string{source.SenderSerial, source.OriginSerial}, source.ObservedAt)
			return err
		})
	}
	read := func(source BGPRoutingSource, historical bool) error {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
		return tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			if !historical {
				_, err := (BGPRouting{}).sourceAuthorityInScope(ctx, sc, source)
				return err
			}
			result, err := (BGPRouting{}).historicalSourceAuthorityInScope(ctx, sc, source)
			if err == nil && !result.ValidUntil.After(time.Now().UTC()) {
				t.Fatal("old expired certificate supplied current validity")
			}
			return err
		})
	}
	for _, source := range originals {
		if err := read(source, true); err != nil {
			t.Fatal("valid original expired receipt lost fresh current source authority", err)
		}
		if err := read(source, false); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
			t.Fatal("historical policy weakened live routing authority", err)
		}
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID(originals[1].TenantID))
	if err := tenancy.InTenantReadSnapshot(foreign, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		result, err := (BGPRouting{}).historicalSourceAuthorityInScope(ctx, sc, originals[0])
		if !errors.Is(err, entity.ErrScopeMismatch) || result != (BGPRoutingSourceAuthority{}) {
			t.Fatal("historical reader replaced the tenant boundary", result, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback owned historical source control")
	for _, mutation := range []struct{ name, sql string }{
		{"original revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND serial=$2`},
		{"current identity unavailable", `UPDATE agent_identities SET not_after=transaction_timestamp() WHERE tenant_id=$1 AND rotated_from=$2`},
		{"current purpose changed", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/invalid' WHERE tenant_id=$1 AND rotated_from=$2`},
		{"source rebound", `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer' AND $2<>''`},
		{"source removed", `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND source_kind='bmp_peer' AND $2<>''`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			for _, serial := range []string{originals[0].SenderSerial, originals[0].OriginSerial} {
				source := originals[0]
				ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
				err := tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := sc.Q.Exec(ctx, mutation.sql, source.TenantID, serial); err != nil {
						return err
					}
					if _, err := (BGPRouting{}).historicalSourceAuthorityInScope(ctx, sc, source); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
						t.Fatal("historical original bypassed current/original boundary", err)
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatal("historical boundary control failed", err)
				}
			}
			if err := read(originals[1], true); err != nil {
				t.Fatal("source control damaged sibling tenant", err)
			}
		})
	}
}
