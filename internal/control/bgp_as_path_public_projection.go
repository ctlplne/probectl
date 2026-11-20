// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type publicASPathKey struct {
	peer  bgp.PublicVisibilityPeer
	route bgp.RoutePrefix
}

// This in-memory state is shared across the locally monitored public prefixes.
// Each caller publishes the returned original events separately under the
// interested tenant's monitor and writer lease.
type publicASPathProjection struct {
	baseline string
	paths    map[publicASPathKey]*store.BGPASPathPublicSnapshot
}

func (projection *publicASPathProjection) advance(point bgp.PublicVisibilityCollectorPoint) []store.BGPASPathPublicEvent {
	if point.Paths == nil {
		projection.baseline, projection.paths = "", nil
		coverage := make([]store.BGPASPathPublicEvent, 0, len(point.Points))
		for _, watched := range point.Points {
			reason := watched.Availability
			if reason != "archive_gap" && reason != "session_change" {
				reason = "path_unavailable"
			}
			coverage = append(coverage, publicASPathCoverage(point, watched.Prefix, "coverage_gap", reason))
		}
		return coverage
	}
	if point.Paths.RIB != nil {
		return projection.captureBaseline(point)
	}
	if projection.baseline != point.Baseline.SHA256 || projection.paths == nil || point.Paths.Updates == nil {
		return nil
	}
	var events []store.BGPASPathPublicEvent
	for _, update := range point.Paths.Updates {
		if event, changed := projection.applyUpdate(point, update); changed {
			events = append(events, event)
		}
	}
	return events
}

func (projection *publicASPathProjection) captureBaseline(point bgp.PublicVisibilityCollectorPoint) []store.BGPASPathPublicEvent {
	projection.baseline = point.Baseline.SHA256
	projection.paths = make(map[publicASPathKey]*store.BGPASPathPublicSnapshot)
	events := make([]store.BGPASPathPublicEvent, 0, len(point.Paths.RIB))
	seen := map[netip.Prefix]bool{}
	for _, path := range point.Paths.RIB {
		peer := bgp.PublicVisibilityPeer{Address: path.Peer.Address, ASN: path.Peer.ASN}
		original := publicASPathOriginal(point, peer, path.ArchiveRecord, path.RecordUnixNanos, path.EntryIndex)
		original.RIBSequence, original.RIBPeerIndex, original.RIBOriginatedAt = &path.RIBSequence, &path.PeerIndex, &path.OriginatedUnixNanos
		current := publicASPathSnapshot(path.Path, original)
		projection.paths[publicASPathKey{peer, path.Route}] = current
		events = append(events, store.BGPASPathPublicEvent{Route: path.Route, Kind: "baseline", Original: original, Current: current})
		seen[path.Route.Prefix] = true
	}
	for _, watched := range point.Points {
		if !seen[watched.Prefix] {
			events = append(events, publicASPathCoverage(point, watched.Prefix, "baseline", "complete_baseline"))
		}
	}
	return events
}

func publicASPathCoverage(point bgp.PublicVisibilityCollectorPoint, prefix netip.Prefix, kind, reason string) store.BGPASPathPublicEvent {
	source := publicASPathOriginal(point, bgp.PublicVisibilityPeer{}, 0, point.Through.UnixNano(), 0)
	source.Coverage = reason
	return store.BGPASPathPublicEvent{Route: bgp.RoutePrefix{Prefix: prefix}, Kind: kind, Original: source}
}

func (projection *publicASPathProjection) applyUpdate(point bgp.PublicVisibilityCollectorPoint, update bgp.PublicArchivePathUpdate) (store.BGPASPathPublicEvent, bool) {
	key := publicASPathKey{update.Peer, update.Route}
	previous := projection.paths[key]
	original := publicASPathOriginal(point, update.Peer, update.ArchiveRecord, update.ObservedUnixNanos, update.OperationIndex)
	event := store.BGPASPathPublicEvent{Route: update.Route, Original: original, Previous: previous}
	if update.Withdraw {
		delete(projection.paths, key)
		event.Kind = "withdrawal"
		return event, previous != nil
	}
	event.Current = publicASPathSnapshot(update.Path, original)
	projection.paths[key] = event.Current
	if previous == nil {
		event.Kind = "announcement"
		return event, true
	}
	event.Kind = "path_change"
	return event, bgp.CompareASPaths(previous.Segments, event.Current.Segments).SegmentsChanged
}

func publicASPathSnapshot(path bgp.RouteASPath, original store.BGPASPathPublicSource) *store.BGPASPathPublicSnapshot {
	return &store.BGPASPathPublicSnapshot{Segments: path.Path.Segments, Source: original, AS4Action: path.Path.AS4Action}
}

func publicASPathOriginal(point bgp.PublicVisibilityCollectorPoint, peer bgp.PublicVisibilityPeer, record, at int64, operation int) store.BGPASPathPublicSource {
	return store.BGPASPathPublicSource{Source: point.Baseline.Source, Collector: point.Baseline.Collector, BaselineClock: point.Baseline.ArchiveClock,
		ArchiveClock: point.Latest.ArchiveClock, BaselineSHA256: point.Baseline.SHA256, ArchiveSHA256: point.Latest.SHA256,
		PeerAddress: peer.Address, PeerASN: peer.ASN, ArchiveRecord: record, OperationIndex: int32(operation), ObservedUnixNanos: at}
}

func (s *Server) publishPublicASPaths(ctx context.Context, tenant tenancy.ID, monitor string, events []store.BGPASPathPublicEvent) error {
	if s.pool == nil || tenant == "" {
		return tenancy.ErrNoTenant
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound != tenant {
		return tenancy.ErrNoTenant
	}
	ctx = tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenant))
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		for _, event := range events {
			if _, err := store.RecordBGPASPathPublicInScope(ctx, sc, monitor, event); err != nil {
				if errors.Is(err, store.ErrBGPVisibilityMissing) {
					return nil
				}
				return err
			}
		}
		return nil
	})
}
