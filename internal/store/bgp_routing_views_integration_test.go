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

func TestBGPRoutingBeginKeepsPrivateTenantGenerationsAndAtomicSlotReplacement(t *testing.T) {
	f := newRoleInputsFixture(t)
	budget := routingViewBudget()
	sources := make([]BGPRoutingSource, len(f.tenants))
	for lane, tenant := range f.tenants {
		var observed time.Time
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed)
		})
		sources[lane] = BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, RouterID: f.routerID, CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[tenant+"role-listener"], OriginSerial: f.serials[tenant+"role-router"], ObservedAt: observed}
	}
	begin := func(source BGPRoutingSource, definition BGPRoutingViewDefinition, profile BGPRoutingBudget) (BGPRoutingView, error) {
		var result BGPRoutingView
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
		err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				result, err = (BGPRouting{}).beginViewInScope(ctx, sc, source, definition, source.ObservedAt.Add(2*time.Hour), profile)
				return err
			})
		})
		return result, err
	}
	var initial []BGPRoutingView
	for _, source := range sources {
		input := routingViewFixture()
		view, err := begin(source, input, budget)
		if err != nil || view.ID == "" || view.Generation == "" || view.ValidUntil.After(source.ObservedAt.Add(time.Hour)) {
			t.Fatal("owned private route generation refused or exceeded credential expiry", view.ID, err)
		}
		input.Peer.Information[0].Value[0] = 77
		input.Peer.SentOpen[0] = 0
		if view.Definition.Peer.Information[0].Value[0] != 0 || view.Definition.Peer.SentOpen[0] != 255 {
			t.Fatal("routing generation aliases caller metadata")
		}
		initial = append(initial, view)
		f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var count, foreign, published int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views`).Scan(&count); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id<>$1`, source.TenantID).Scan(&foreign); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE state='current'`).Scan(&published); err != nil {
				return err
			}
			if count != 1 || foreign != 0 || published != 0 {
				t.Fatal("staging routing view leaked a tenant or became current", count, foreign, published)
			}
			var raw []byte
			if err := sc.Q.QueryRow(ctx, `SELECT peer_identity FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2`, source.TenantID, view.ID).Scan(&raw); err != nil {
				return err
			}
			var stored BGPRoutingPeer
			if err := json.Unmarshal(raw, &stored); err != nil {
				return err
			}
			if stored.ASN != 4294967295 || stored.RemotePort != 65535 || len(stored.Information) != 3 || stored.Information[0].Value[0] != 0 || stored.Information[1].Value == nil || stored.Information[2].Value != nil {
				t.Fatal("stored routing metadata lost complete values or caller ownership")
			}
			return nil
		})
	}
	// A refused new generation must not retire the former one. Mark only this
	// fixture row current to exercise the beginning transaction's rollback; this
	// is not a completion/publication proof.
	var used int64
	f.in(sources[0].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='current',completed_at=transaction_timestamp() WHERE tenant_id=$1`, sources[0].TenantID); err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx, `SELECT sum(charged_bytes)::bigint FROM bgp_routing_views WHERE tenant_id=$1`, sources[0].TenantID).Scan(&used)
	})
	limited := budget
	limited.StateBytes = used
	if view, err := begin(sources[0], routingViewFixture(), limited); !errors.Is(err, ErrBGPRoutingBudget) || view.ID != "" {
		t.Fatal("routing generation exceeded tenant retained bytes", view.ID, err)
	}
	state := func(view BGPRoutingView) string {
		var value string
		f.in(view.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT state FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, view.TenantID, view.ID, view.Generation).Scan(&value)
		})
		return value
	}
	if state(initial[0]) != "current" {
		t.Fatal("refused generation changed former publication")
	}
	other := routingViewFixture()
	other.Peer.Address = netip.MustParseAddr("192.0.2.13")
	otherView, err := begin(sources[0], other, budget)
	if err != nil {
		t.Fatal(err)
	}
	restart := routingViewFixture()
	restart.Peer.ASN = 64496
	restart.Peer.BGPIdentifier = netip.MustParseAddr("198.51.100.9")
	newView, err := begin(sources[0], restart, budget)
	if err != nil {
		t.Fatal(err)
	}
	if newView.PeerKey != initial[0].PeerKey || newView.ID == initial[0].ID || newView.Generation == initial[0].Generation || state(initial[0]) != "invalid" || state(newView) != "staging" || state(otherView) != "staging" || state(initial[1]) != "staging" {
		t.Fatal("peer restart mixed former, sibling or unrelated route generations")
	}
	loc := routingViewFixture()
	loc.Kind = "loc_rib"
	loc.Peer.Type = 3
	loc.Peer.Address = netip.Addr{}
	loc.Peer.LocalAddress = netip.Addr{}
	loc.Peer.LocalPort = 0
	loc.Peer.RemotePort = 0
	first, err := begin(sources[0], loc, budget)
	if err != nil {
		t.Fatal(err)
	}
	loc.Peer.ASN = 64497
	loc.Peer.BGPIdentifier = netip.MustParseAddr("198.51.100.7")
	second, err := begin(sources[0], loc, budget)
	if err != nil {
		t.Fatal(err)
	}
	if state(first) != "invalid" || state(second) != "staging" || state(newView) != "staging" {
		t.Fatal("Loc-RIB restart retained former selected slot or erased adjacent views")
	}
	foreign := sources[0]
	foreign.SenderSerial = sources[1].SenderSerial
	if view, err := begin(foreign, routingViewFixture(), budget); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || view.ID != "" {
		t.Fatal("foreign sender began a routing generation", err)
	}
	if state(newView) != "staging" || state(initial[1]) != "staging" {
		t.Fatal("refused sender changed an owned routing generation")
	}
}
