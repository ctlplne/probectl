// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBGPASPathHistoryKeepsOwnedBaselineChangesAndExactOrder(t *testing.T) {
	fixture := newRoleInputsFixture(t)
	fence := tenancy.NewPostgresWriterFence(fixture.pool)
	monitors := make([]BGPVisibilityMonitor, len(fixture.tenants))
	for lane, tenant := range fixture.tenants {
		source := routingFixtureSource(fixture, lane)
		first := routingChangeFixture()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, fence, tenant, tenancy.ErrNoTenant, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, fixture.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				monitors[lane], err = (BGPVisibility{}).SaveMonitor(ctx, sc, BGPVisibilityMonitor{
					Prefix: first.Prefix, MinimumVisibleBasisPoints: 9500,
				})
				return err
			})
		}); err != nil {
			t.Fatal(err)
		}
		ref := routingLookupBegin(t, fixture, source, routingLookupDefinition(1))
		apply := func(batch BGPRoutingBatch) {
			t.Helper()
			batch.AFI, batch.SAFI, batch.ObservedAt = 1, 1, routingFixtureTime(fixture)
			result, err := routingFixtureApply(t, fixture, source, ref, batch, routingViewBudget())
			if err != nil || result.Status != "applied" {
				t.Fatal("the owned path capture interrupted the admitted router batch", result, err)
			}
		}
		apply(BGPRoutingBatch{Sequence: 1, Changes: []BGPRoutingChange{first}})
		apply(BGPRoutingBatch{Sequence: 2, EndOfRIB: true})
		changed := first
		changed.Segments = []BGPRoutingSegment{{Kind: uint8(bgp.ASPathSequence), Values: []uint32{64496, uint32(64497 + lane), uint32(64497 + lane)}}}
		withdrawn := BGPRoutingChange{Prefix: first.Prefix, HasPathID: first.HasPathID, PathID: first.PathID, Withdraw: true}
		apply(BGPRoutingBatch{Sequence: 3, Changes: []BGPRoutingChange{first, changed, withdrawn, withdrawn}})
	}
	for lane, tenant := range fixture.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(ctx, fixture.pool, func(ctx context.Context, sc tenancy.Scope) error {
			at := monitors[lane].CreatedAt
			query := BGPASPathHistorySelection{Monitor: monitors[lane].ID, SourceKind: "router_bmp",
				From: at.Add(-time.Hour), To: at.Add(time.Hour), Limit: 12}
			points, more, err := BGPASPathHistoryInScope(ctx, sc, query, routingViewBudget())
			if err != nil || more || len(points) != 3 || points[0].Kind != "withdrawal" ||
				points[0].Operation != 2 || points[1].Kind != "path_change" || points[1].Operation != 1 ||
				points[2].Kind != "baseline" || points[2].Sequence != 2 {
				t.Fatal("the timeline lost a refresh baseline or invented changes for duplicate updates", points, more, err)
			}
			allowed := func(ctx context.Context, _ tenancy.Scope, source BGPRoutingSource, event change.Event) error {
				if source.TenantID != tenant || source.RouterID != fixture.routerID || event.Prefix != monitors[lane].Prefix.String() {
					t.Fatal("current actor authorization received the wrong original source")
				}
				return ctx.Err()
			}
			for _, event := range points {
				proof, err := VerifyBGPASPathHistorySourceInScope(ctx, sc, monitors[lane].Prefix, event, routingViewBudget(), allowed)
				if err != nil || proof.View != "loc_rib" || proof.Generation != event.SourceEpoch {
					t.Fatal("retained history did not prove the original current router authority", proof, err)
				}
			}
			for _, event := range points[:2] {
				if event.ChangeEventID == "" || event.ContextID == "" || event.RouterID != fixture.routerID {
					t.Fatal("private event lacks the original tenant routing link", event)
				}
			}
			var predecessor struct {
				Segments []BGPRoutingSegment `json:"segments"`
			}
			if err := json.Unmarshal(points[0].Previous, &predecessor); err != nil || len(predecessor.Segments) != 1 ||
				len(predecessor.Segments[0].Values) != 3 || predecessor.Segments[0].Values[2] != uint32(64497+lane) {
				t.Fatal("the withdrawal did not capture the exact intermediate prepend", err)
			}
			query.Monitor = monitors[1-lane].ID
			if sibling, _, err := BGPASPathHistoryInScope(ctx, sc, query, routingViewBudget()); !errors.Is(err, ErrBGPVisibilityMissing) || len(sibling) != 0 {
				t.Fatal("other tenant's real router history crossed the storage boundary", sibling, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBGPASPathHistoryKeepsStablePublicEvidenceInItsTenant(t *testing.T) {
	fixture := newRoleInputsFixture(t)
	writer := tenancy.NewPostgresWriterFence(fixture.pool)
	runInTenant := func(tenant string, operation func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, writer, tenant, tenancy.ErrNoTenant, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, fixture.pool, operation)
		}); err != nil {
			t.Fatal(err)
		}
	}
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	monitorIDs := make([]string, len(fixture.tenants))
	for lane, tenant := range fixture.tenants {
		runInTenant(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			monitor, err := (BGPVisibility{}).SaveMonitor(ctx, sc, BGPVisibilityMonitor{Prefix: prefix, MinimumVisibleBasisPoints: 9500})
			monitorIDs[lane] = monitor.ID
			return err
		})
	}
	clock := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	originated := clock.UnixNano()
	index, sequence := uint16(0), uint32(0)
	source := BGPASPathPublicSource{Source: "routeviews", Collector: "route-views.eqix", BaselineClock: clock, ArchiveClock: clock,
		BaselineSHA256: strings.Repeat("ab", 32), ArchiveSHA256: strings.Repeat("ab", 32),
		PeerAddress: netip.MustParseAddr("198.51.100.2"), PeerASN: 64496, ArchiveRecord: 2, ObservedUnixNanos: originated,
		RIBPeerIndex: &index, RIBSequence: &sequence, RIBOriginatedAt: &originated}
	event := BGPASPathPublicEvent{Route: bgp.RoutePrefix{Prefix: prefix, HasPathID: true, PathID: 0}, Kind: "baseline", Original: source,
		Current: &BGPASPathPublicSnapshot{Source: source, AS4Action: "absent", Segments: []bgp.ASPathSegment{
			{Kind: bgp.ASPathSequence, Values: []uint32{64496, 64497, 64497}},
		}}}
	for lane, tenant := range fixture.tenants {
		runInTenant(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if added, err := RecordBGPASPathPublicInScope(ctx, sc, monitorIDs[lane], event); err != nil || !added {
				t.Fatal("first original path was not accepted in its tenant", added, err)
			}
			if added, err := RecordBGPASPathPublicInScope(ctx, sc, monitorIDs[lane], event); err != nil || added {
				t.Fatal("exact replay changed retained history", added, err)
			}
			conflict := event
			snapshot := *event.Current
			snapshot.Segments = []bgp.ASPathSegment{{Kind: bgp.ASPathSequence, Values: []uint32{64499}}}
			conflict.Current = &snapshot
			if added, err := RecordBGPASPathPublicInScope(ctx, sc, monitorIDs[lane], conflict); !errors.Is(err, ErrBGPVisibilityConflict) || added {
				t.Fatal("conflicting evidence reused an accepted original identity", added, err)
			}
			if added, err := RecordBGPASPathPublicInScope(ctx, sc, monitorIDs[1-lane], event); !errors.Is(err, ErrBGPVisibilityMissing) || added {
				t.Fatal("a tenant wrote paths to a sibling's monitor", added, err)
			}
			update := source
			update.ArchiveSHA256, update.ArchiveRecord, update.OperationIndex = strings.Repeat("cd", 32), 1, 1
			update.RIBPeerIndex, update.RIBSequence, update.RIBOriginatedAt = nil, nil, nil
			announced := event
			announced.Route.PathID, announced.Kind, announced.Original = 1, "announcement", update
			current := *event.Current
			current.Source = update
			announced.Current = &current
			if added, err := RecordBGPASPathPublicInScope(ctx, sc, monitorIDs[lane], announced); err != nil || !added {
				t.Fatal("a second same-clock path could not retain its original order", added, err)
			}
			return nil
		})
	}
	for lane, tenant := range fixture.tenants {
		fixture.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var monitor string
			var explicitPathID bool
			var pathID int64
			var prepend string
			var count int
			err := sc.Q.QueryRow(ctx, `SELECT monitor_id::text,has_path_id,path_id,
 current_path->'segments'->0->'Values'->>2,count(*) OVER () FROM bgp_as_path_history ORDER BY path_id LIMIT 1`).Scan(&monitor, &explicitPathID, &pathID, &prepend, &count)
			if err != nil || count != 2 || monitor != monitorIDs[lane] || !explicitPathID || pathID != 0 || prepend != "64497" {
				t.Fatal("unfiltered SQL lost owner, explicit path zero or the original prepend", monitor, pathID, prepend, err)
			}
			query := BGPASPathHistorySelection{Monitor: monitorIDs[lane], SourceKind: "public_mrt",
				From: clock.Add(-time.Minute), To: clock.Add(time.Minute), Limit: 1}
			budget := BGPRoutingBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20, StateBytes: 1 << 20}
			first, more, err := BGPASPathHistoryInScope(ctx, sc, query, budget)
			if err != nil || !more || len(first) != 1 || first[0].PathID != 1 || first[0].Operation != 1 {
				t.Fatal("the same-clock page lost the original archive operation ordering", len(first), more, err)
			}
			query.After = &first[0].BGPASPathHistoryPosition
			second, more, err := BGPASPathHistoryInScope(ctx, sc, query, budget)
			if err != nil || more || len(second) != 1 || second[0].PathID != 0 || second[0].Sequence >= first[0].Sequence ||
				!second[0].ObservedAt.Equal(first[0].ObservedAt) {
				t.Fatal("the continuation lost a same-clock RIB candidate", len(second), more, err)
			}
			var updateOriginal, baselineOriginal BGPASPathPublicSource
			if json.Unmarshal(first[0].Original, &updateOriginal) != nil || json.Unmarshal(second[0].Original, &baselineOriginal) != nil ||
				updateOriginal.ArchiveRecord != 1 || baselineOriginal.ArchiveRecord != 2 {
				t.Fatal("the sortable key changed either original file record ordinal")
			}
			query.Monitor = monitorIDs[1-lane]
			if sibling, _, err := BGPASPathHistoryInScope(ctx, sc, query, budget); !errors.Is(err, ErrBGPVisibilityMissing) || len(sibling) != 0 {
				t.Fatal("the sibling monitor was reached through a valid continuation", sibling, err)
			}
			return nil
		})
	}
}
