// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"compress/bzip2"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/opendata"
)

// Public collectors can close the outgoing file just after its nominal
// archive boundary. Preserve those original clocks and refuse an overlap
// with the next accepted file.
const publicMRTArchiveRollover = time.Second

type PublicVisibilityCollectorPoint struct {
	Baseline opendata.PublicMRTReceipt `json:"baseline"`
	Latest   opendata.PublicMRTReceipt `json:"latest"`
	Through  time.Time                 `json:"through"`
	Points   []PublicPrefixVisibility  `json:"points"`
}

// PublicVisibilityCollector projects one collector's complete, sealed public
// archives onto an in-memory set of locally admitted prefixes. The same prefix
// can contribute to multiple tenant publications, each under its own authority.
// A caller serializes access to this projection during a baseline interval.
type PublicVisibilityCollector struct {
	baseline       opendata.PublicMRTReceipt
	latest         opendata.PublicMRTReceipt
	observed       time.Time
	next           time.Time
	through        time.Time
	expires        time.Time
	cadence        time.Duration
	intervalBudget int64
	rosters        [2]map[PublicVisibilityPeer]bool
	projections    map[netip.Prefix]*PrefixVisibilityProjection
	order          []netip.Prefix
}

func ReadPublicVisibilityCollector(ctx context.Context, cache *opendata.PublicMRTCache, ref opendata.PublicMRTArchiveRef,
	archive MRTArchiveBudget, policy PublicVisibilityBaselinePolicy, prefixes []netip.Prefix) (*PublicVisibilityCollector, error) {
	if cache == nil || ref.Kind != opendata.PublicMRTBaseline {
		return nil, ErrPublicVisibilityBaseline
	}
	request, err := opendata.PublicMRTRequest(ref)
	if err != nil {
		return nil, err
	}
	updateRef := request.Ref
	updateRef.Kind = opendata.PublicMRTUpdates
	updates, err := opendata.PublicMRTRequest(updateRef)
	if err != nil || updates.Cadence <= 0 || request.Cadence < updates.Cadence {
		return nil, ErrPublicVisibilityBaseline
	}
	receipt, file, err := cache.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	baseline, err := ReadPublicVisibilityBaseline(ctx, bzip2.NewReader(file), archive, policy, prefixes)
	if err != nil {
		return nil, err
	}
	observed := time.Unix(0, baseline.Archive.PeerIndex.ObservedUnixNanos).UTC()
	if observed.Before(receipt.ArchiveClock) || !observed.Before(receipt.ArchiveClock.Add(updates.Cadence)) {
		return nil, ErrPublicVisibilityBaseline
	}
	order := make([]netip.Prefix, 0, len(baseline.Projections))
	for prefix := range baseline.Projections {
		order = append(order, prefix)
	}
	slices.SortFunc(order, func(a, b netip.Prefix) int { return a.Compare(b) })
	return &PublicVisibilityCollector{baseline: receipt, latest: receipt, observed: observed,
		next: receipt.ArchiveClock, through: observed, expires: receipt.ArchiveClock.Add(request.Cadence), cadence: updates.Cadence,
		intervalBudget: policy.WorkingBytes / int64(request.Cadence/updates.Cadence),
		rosters:        baseline.rosters, projections: baseline.Projections, order: order}, nil
}

// Advance accepts the next original archive interval. Until its compressed
// bytes and every MRT record validate, the current point stays unchanged.
// A feed gap or session roster change removes comparability for the affected
// family. The deployment must establish a new complete baseline to recover.
func (series *PublicVisibilityCollector) Advance(ctx context.Context, cache *opendata.PublicMRTCache,
	ref opendata.PublicMRTArchiveRef, archive MRTArchiveBudget) error {
	request, err := opendata.PublicMRTRequest(ref)
	if err != nil || cache == nil || ref.Kind != opendata.PublicMRTUpdates ||
		ref.Source != series.baseline.Source || ref.Collector != series.baseline.Collector ||
		!request.Ref.At.Equal(series.next) || !series.next.Before(series.expires) {
		return ErrPublicVisibilityBaseline
	}
	receipt, file, err := cache.Open(ctx, ref)
	if err != nil {
		return err
	}
	defer file.Close()
	staged := publicVisibilityInterval{remaining: series.intervalBudget, after: series.observed, window: receipt.ArchiveClock,
		through: receipt.ArchiveClock.Add(request.Cadence), rosters: series.rosters, projections: series.projections}
	if series.latest.Kind == string(opendata.PublicMRTUpdates) {
		staged.continuityFloor = series.through
	}
	if _, _, err := StageMRTUpdates(ctx, bzip2.NewReader(file), archive, staged.stage); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	coveredThrough := staged.commit()
	series.latest, series.next, series.through = receipt, staged.through, coveredThrough
	return nil
}

func (series *PublicVisibilityCollector) MarkGap() {
	for _, projection := range series.projections {
		projection.disrupt("archive_gap")
	}
	series.next = series.next.Add(series.cadence)
	series.through = series.next
}

func (series *PublicVisibilityCollector) NextArchive() (opendata.PublicMRTArchiveRef, bool) {
	return opendata.PublicMRTArchiveRef{Source: series.baseline.Source, Collector: series.baseline.Collector,
		Kind: opendata.PublicMRTUpdates, At: series.next}, series.next.Before(series.expires)
}

func (series *PublicVisibilityCollector) Point() PublicVisibilityCollectorPoint {
	out := PublicVisibilityCollectorPoint{Baseline: series.baseline, Latest: series.latest, Through: series.through,
		Points: make([]PublicPrefixVisibility, 0, len(series.order))}
	for _, prefix := range series.order {
		out.Points = append(out.Points, series.projections[prefix].Point())
	}
	return out
}

type publicVisibilityOperation struct {
	projection *PrefixVisibilityProjection
	peer       PublicVisibilityPeer
	route      RoutePrefix
	origin     publicVisibilityOriginSet
	withdraw   bool
}

type publicVisibilityInterval struct {
	remaining              int64
	after, window, through time.Time
	continuityFloor        time.Time
	latest                 time.Time
	rosters                [2]map[PublicVisibilityPeer]bool
	projections            map[netip.Prefix]*PrefixVisibilityProjection
	operations             []publicVisibilityOperation
	disrupted              [2]bool
}

func (interval *publicVisibilityInterval) commit() time.Time {
	for _, operation := range interval.operations {
		if operation.withdraw {
			delete(operation.projection.active[operation.peer], operation.route)
		} else {
			operation.projection.retain(operation.peer, operation.route, operation.origin)
		}
	}
	coveredThrough := interval.through
	if interval.latest.After(coveredThrough) {
		coveredThrough = interval.latest
	}
	for prefix, projection := range interval.projections {
		if interval.disrupted[publicVisibilityFamily(prefix)] {
			projection.disrupt("session_change")
		}
		if projection.continuous {
			projection.through = coveredThrough
		}
	}
	return coveredThrough
}

func (interval *publicVisibilityInterval) stage(ctx context.Context, update MRTUpdate) error {
	at := time.Unix(0, update.ObservedUnixNanos).UTC()
	if at.Before(interval.window) || at.Before(interval.continuityFloor) || !at.Before(interval.through.Add(publicMRTArchiveRollover)) {
		return fmt.Errorf("MRT update clock %s outside the contiguous archive beginning %s: %w", at.Format(time.RFC3339Nano),
			interval.window.Format(time.RFC3339), ErrMRTRecord)
	}
	if at.After(interval.latest) {
		interval.latest = at
	}
	if at.Before(interval.after) {
		return nil
	}
	peer := PublicVisibilityPeer{Address: update.PeerAddress, ASN: update.PeerASN}
	for family, roster := range interval.rosters {
		eligible, known := roster[peer]
		if !known || eligible && update.NewState != 0 && update.OldState != update.NewState {
			interval.disrupted[family] = true
		}
	}
	for _, group := range update.Groups {
		if err := interval.stageRoutes(ctx, peer, group.Withdrawn, publicVisibilityOriginSet{}, true); err != nil {
			return err
		}
		if len(group.Announced) > 0 {
			if err := interval.stageRoutes(ctx, peer, group.Announced, publicVisibilityOrigins(update.Path), false); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (interval *publicVisibilityInterval) stageRoutes(ctx context.Context, peer PublicVisibilityPeer,
	routes []RoutePrefix, origin publicVisibilityOriginSet, withdraw bool) error {
	for _, route := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		family := publicVisibilityFamily(route.Prefix)
		projection := interval.projections[route.Prefix]
		if projection == nil || !projection.continuous || !interval.rosters[family][peer] || interval.disrupted[family] {
			continue
		}
		interval.remaining -= 256 + int64(len(origin.values))*8
		if interval.remaining < 0 {
			return ErrMRTBudget
		}
		interval.operations = append(interval.operations, publicVisibilityOperation{projection, peer, route, origin, withdraw})
	}
	return nil
}

func publicVisibilityFamily(prefix netip.Prefix) int {
	if prefix.Addr().Is4() {
		return 0
	}
	return 1
}
