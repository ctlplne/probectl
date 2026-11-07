// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role storage and RLS, modeled collector credentials. No
// complete/current public RIB, transport or fallback is claimed by staging.
func TestPublicRoutingStagingKeepsTenantPrivateOwnedMetadataAndAtomicReplacement(t *testing.T) {
	f := newRoleInputsFixture(t)
	budget := BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 16 << 20, LeaseDuration: time.Hour}
	definition := publicRoutingMetadataFixture()
	definition.Public.ViewName = []byte{0, 255, 7}
	var initial []BGPPublicRoutingView
	var sources []BGPPublicRoutingSource
	begin := func(source BGPPublicRoutingSource, input BGPRoutingViewDefinition, profile BGPRoutingBudget) (BGPPublicRoutingView, error) {
		var result BGPPublicRoutingView
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
		err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				result, err = (BGPRouting{}).beginPublicViewInScope(ctx, sc, source, input, profile)
				return err
			})
		})
		return result, err
	}
	advance := func(source BGPPublicRoutingSource) BGPPublicRoutingSource {
		f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&source.ObservedAt)
		})
		source.ObservedAt = source.ObservedAt.Add(123 * time.Nanosecond)
		return source
	}
	for _, tenant := range f.tenants {
		source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, CollectorAgentID: "role-listener", SourceRef: publicRoutingSourceRef(*definition.Public), SenderSerial: f.serials[tenant+"role-listener"]}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, source.SourceRef, f.contextID)
			return err
		})
		source = advance(source)
		view, err := begin(source, definition, budget)
		if err != nil || view.ID == "" || view.Generation == "" || view.PeerKey == ([32]byte{}) || view.ValidUntil.After(source.ObservedAt.Add(budget.LeaseDuration)) {
			t.Fatal("owned public source refused private staging or exceeded its lease", view.ID, err)
		}
		definition.Public.ViewName[0] = 99
		if view.Definition.Public.ViewName[0] != 0 {
			t.Fatal("public staging returned mutable caller metadata")
		}
		definition.Public.ViewName[0] = 0
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count, published, invented int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE state='current'),count(*) FILTER (WHERE router_id IS NOT NULL OR binding_kind IS NOT NULL OR origin_serial IS NOT NULL) FROM bgp_routing_views`).Scan(&count, &published, &invented); err != nil {
				return err
			}
			if count != 1 || published != 0 || invented != 0 {
				t.Fatal("public staging leaked tenant state, published early or invented router authority", count, published, invented)
			}
			var raw []byte
			if err := sc.Q.QueryRow(ctx, `SELECT peer_identity FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2`, tenant, view.ID).Scan(&raw); err != nil {
				return err
			}
			var peer BGPPublicRoutingPeer
			if err := json.Unmarshal(raw, &peer); err != nil {
				return err
			}
			if peer.CollectorObservedUnixNanos == nil || *peer.CollectorObservedUnixNanos != source.ObservedAt.UnixNano() || peer.ObservedUnixNanos == nil || *peer.ObservedUnixNanos != *definition.Public.ObservedUnixNanos || peer.ViewName[0] != 0 || peer.PeerASN != ^uint32(0) {
				t.Fatal("public staging lost exact original/collector clocks or complete source metadata")
			}
			return nil
		})
		sources, initial = append(sources, source), append(initial, view)
	}
	state := func(view BGPPublicRoutingView) string {
		var state string
		f.in(view.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT state FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, view.TenantID, view.ID, view.Generation).Scan(&state)
		})
		return state
	}
	next := advance(sources[0])
	limited := budget
	limited.StateBytes = 1
	if _, err := begin(next, definition, limited); !errors.Is(err, ErrBGPRoutingBudget) {
		t.Fatal("public staging ignored retained admission", err)
	}
	if state(initial[0]) != "staging" || state(initial[1]) != "staging" {
		t.Fatal("refused public replacement changed former or sibling staging")
	}
	other := publicRoutingMetadataFixture()
	other.Public.PeerAddress = netip.MustParseAddr("192.0.2.9")
	otherView, err := begin(next, other, budget)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := begin(advance(next), definition, budget)
	if err != nil || replacement.PeerKey != initial[0].PeerKey || replacement.Generation == initial[0].Generation || state(initial[0]) != "invalid" || state(replacement) != "staging" || state(otherView) != "staging" || state(initial[1]) != "staging" {
		t.Fatal("public staging replacement mixed slots or tenant generations", err)
	}
	if _, err := begin(sources[0], definition, budget); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || state(replacement) != "staging" {
		t.Fatal("old public staging observation retired a newer incarnation", err)
	}
	foreign := advance(sources[0])
	foreign.SenderSerial = sources[1].SenderSerial
	if _, err := begin(foreign, definition, budget); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || state(replacement) != "staging" {
		t.Fatal("foreign public credential changed current owned staging", err)
	}
}
