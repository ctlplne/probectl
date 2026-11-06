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
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role TLS Postgres. Credentials are modeled registry rows;
// this proves target delegation, not the physical router or its transport.
func TestBGPRoutingBoundAuthorityKeepsBaseCredentialsEpochBirthAndTenant(t *testing.T) {
	f := newRoleInputsFixture(t)
	targetContext, targetRouter := uuid.NewString(), uuid.NewString()
	sources := make([]BGPRoutingSource, len(f.tenants))
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'owned','routing-target')`, tenant, targetContext, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','delegated-router')`, tenant, targetContext, targetRouter)
			return err
		})
		base := routingFixtureSource(f, lane)
		if err := routingFixtureWrite(t, f, base, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := putRoutingBindings(ctx, sc, base.CollectorAgentID, base.SourceRef, base.ContextID, "",
				[]routingSourceBinding{{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "0000000000001234", BGPIdentifier: "192.0.2.1", Families: []uint16{1, 2}}}, routingViewBudget())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, routingViewBudget())
			if err != nil {
				return err
			}
			peer := BGPRoutingPeer{Type: 3, BGPIdentifier: netip.MustParseAddr("192.0.2.1"), Distinguisher: [8]byte{0, 0, 0, 0, 0, 0, 0x12, 0x34}}
			selection, err := selectRoutingSource(ctx, sc, config, peer, []uint16{1, 2})
			if err != nil {
				return err
			}
			base.ContextID, base.RouterID, base.routingSelection = selection.ContextID, selection.RouterID, &selection
			sources[lane] = base
			return nil
		})
		sources[lane].ObservedAt = routingFixtureTime(f)
	}
	read := func(source BGPRoutingSource, lock bool) error {
		return routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			var got BGPRoutingSourceAuthority
			var err error
			if lock {
				got, err = (BGPRouting{}).sourceAuthorityForWriteInScope(ctx, sc, source)
			} else {
				got, err = (BGPRouting{}).sourceAuthorityInScope(ctx, sc, source)
			}
			if err == nil && (!got.ValidUntil.After(got.AsOf) || got.AsOf.Before(source.ObservedAt)) {
				t.Fatal("bound routing authority did not retain current credential deadline", got)
			}
			return err
		})
	}
	for _, source := range sources {
		for _, lock := range []bool{false, true} {
			if err := read(source, lock); err != nil {
				t.Fatal("current explicitly bound target was refused", lock, err)
			}
		}
	}
	for _, change := range []func(*BGPRoutingSource){
		func(s *BGPRoutingSource) { s.OriginSerial = sources[1].OriginSerial },
		func(s *BGPRoutingSource) { s.SenderSerial = sources[1].SenderSerial },
		func(s *BGPRoutingSource) { s.ObservedAt = s.routingSelection.AssignedAt.Add(-time.Second) },
		func(s *BGPRoutingSource) { s.routingSelection = sources[1].routingSelection },
		func(s *BGPRoutingSource) { s.routingSelection = nil },
	} {
		copy := sources[0]
		change(&copy)
		if err := read(copy, false); err == nil {
			t.Fatal("bound routing target borrowed foreign, stale or missing authority")
		}
	}
	rollback := errors.New("restore original bound routing source")
	for _, tc := range []struct{ name, sql string }{
		{"origin-revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"sender-revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-listener'`},
		{"origin-purpose", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/wrong-purpose' WHERE tenant_id=$1 AND agent_id='role-router'`},
		{"source-rebound", `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"epoch-replaced", `UPDATE entity_source_contexts SET routing_epoch=$2 WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"unknown-format", `UPDATE entity_source_contexts SET routing_bindings=(SELECT jsonb_agg(binding || '{"source_format":"future"}'::jsonb) FROM jsonb_array_elements(routing_bindings) binding) WHERE tenant_id=$1 AND source_kind='bmp_peer'`},
		{"target-reborn", `UPDATE entities SET created_at=clock_timestamp() WHERE tenant_id=$1 AND context_id=$2 AND id=$3`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := sources[0]
			err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
				args := []any{source.TenantID}
				if tc.name == "epoch-replaced" {
					args = append(args, uuid.NewString())
				} else if tc.name == "target-reborn" {
					args = append(args, source.ContextID, source.RouterID)
				}
				if _, err := sc.Q.Exec(ctx, tc.sql, args...); err != nil {
					return err
				}
				got, err := (BGPRouting{}).sourceAuthorityForWriteInScope(ctx, sc, source)
				if err == nil || got != (BGPRoutingSourceAuthority{}) {
					t.Fatal("bound routing view retained changed credential or target authority", got, err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal("bound source mutation proof did not reach authority", err)
			}
			for _, original := range sources {
				if err := read(original, false); err != nil {
					t.Fatal("bound source mutation escaped rollback or affected another tenant", err)
				}
			}
		})
	}
}
