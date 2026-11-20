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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBGPVisibilityKeepsSharedPrefixHistoryTenantScopedAndImmutable(t *testing.T) {
	fixture := newRoleInputsFixture(t)
	storage := BGPVisibility{}
	monitorSpec := BGPVisibilityMonitor{Prefix: netip.MustParsePrefix("192.0.2.0/24"),
		MinimumVisibleBasisPoints: 9500, AlertOnPartial: true, AlertOnLoss: true}
	monitors := make([]BGPVisibilityMonitor, len(fixture.tenants))
	writer := tenancy.NewPostgresWriterFence(fixture.pool)
	write := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, writer, tenant, tenancy.ErrNoTenant, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, fixture.pool, fn)
		}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for lane, tenant := range fixture.tenants {
		write(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			monitors[lane], err = storage.SaveMonitor(ctx, sc, monitorSpec)
			if err != nil || monitors[lane].Prefix != monitorSpec.Prefix {
				t.Fatal("tenant monitor was not admitted", monitors[lane], err)
			}
			point := BGPVisibilityObservation{Source: "routeviews", Collector: "route-views.eqix", ObservedAt: at,
				BaselineClock: at, ArchiveClock: at, BaselineSHA256: strings.Repeat("ab", 32),
				ArchiveSHA256: strings.Repeat("ab", 32), PolicyVersion: "qa-1", MinimumPeerRoutes: 100,
				Availability: "available", Counts: &BGPVisibilityCounts{EligiblePeers: 5 + lane, VisiblePeers: 1,
					Origins: []bgp.PublicVisibilityOrigin{{ASN: uint32(64496 + lane), Peers: 1}}}}
			if added, err := storage.Record(ctx, sc, monitors[lane].ID, point); err != nil || !added {
				t.Fatal("initial point was not accepted", added, err)
			}
			if added, err := storage.Record(ctx, sc, monitors[lane].ID, point); err != nil || added {
				t.Fatal("exact retry changed history", added, err)
			}
			point.Counts.EligiblePeers++
			if added, err := storage.Record(ctx, sc, monitors[lane].ID, point); !errors.Is(err, ErrBGPVisibilityConflict) || added {
				t.Fatal("different point replaced an accepted source clock", added, err)
			}
			point.ObservedAt = at.Add(15 * time.Minute)
			point.Availability, point.Counts = "archive_gap", nil
			if added, err := storage.Record(ctx, sc, monitors[lane].ID, point); err != nil || !added {
				t.Fatal("explicit gap was not retained", added, err)
			}
			return nil
		})
	}
	if monitors[0].ID == monitors[1].ID {
		t.Fatal("a shared public prefix acquired a shared tenant monitor")
	}
	for lane, tenant := range fixture.tenants {
		fixture.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			points, err := storage.History(ctx, sc, monitors[lane].ID, at.Add(time.Hour), 10)
			if err != nil || len(points) != 2 || points[0].Counts != nil || points[0].Availability != "archive_gap" ||
				points[1].Counts == nil || points[1].Counts.EligiblePeers != 5+lane || len(points[1].Counts.Origins) != 1 ||
				points[1].Counts.Origins[0].ASN != uint32(64496+lane) {
				t.Fatal("history mixed tenant coverage, original origins, or gap state", points, err)
			}
			if history, err := storage.History(ctx, sc, monitors[1-lane].ID, at.Add(time.Hour), 10); !errors.Is(err, ErrBGPVisibilityMissing) || len(history) != 0 {
				t.Fatal("sibling monitor crossed authorization", history, err)
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_visibility_points`).Scan(&count); err != nil || count != 2 {
				t.Fatal("unfiltered SQL crossed tenant isolation", count, err)
			}
			return nil
		})
	}
}
