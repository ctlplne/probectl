// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	bgpVisibilityArchiveWait   = 5 * time.Minute
	bgpVisibilityBaselineClock = 2 * time.Hour
	bgpVisibilityPolicyVersion = "routeviews-full-table-v1"
	maxSharedWatchPrefixes     = 2048
	maxVisibilityPending       = 18
)

var (
	bgpVisibilityArchiveBudget = bgp.MRTArchiveBudget{ArchiveBytes: 4 << 30, Records: 4_000_000,
		Frame: bgp.UpdateFrameBudget{MemoryBytes: 128 << 20, WorkUnits: 32 << 20}}
	bgpVisibilityBaselinePolicy = bgp.PublicVisibilityBaselinePolicy{
		MinimumIPv4Routes: 800_000, MinimumIPv6Routes: 150_000, WorkingBytes: 768 << 20}
)

// BGPVisibilitySupervisor reads only a local deployment cache. The independent
// collector fetch process has no access to this tenant sync or its watch set.
// One replica owns this job through the existing cluster lease.
type BGPVisibilitySupervisor struct {
	server     *Server
	cache      *opendata.PublicMRTCache
	collectors []string
	window     time.Duration
	observer   incident.Observer
}

type bgpVisibilityCollectorState struct {
	baseline time.Time
	prefixes []netip.Prefix
	series   *bgp.PublicVisibilityCollector
	pending  []bgp.PublicVisibilityCollectorPoint
	gap      bool
}

type bgpVisibilityTarget struct {
	tenant tenancy.ID
	id     string
}

func NewBGPVisibilitySupervisor(server *Server, directory string, collectors []string,
	window time.Duration, observer incident.Observer) (*BGPVisibilitySupervisor, error) {
	if server == nil || server.pool == nil || len(collectors) < 1 || len(collectors) > 3 || window <= 0 {
		return nil, store.ErrBGPVisibilityInput
	}
	seen := map[string]bool{}
	for _, collector := range collectors {
		if seen[collector] {
			return nil, store.ErrBGPVisibilityInput
		}
		if _, err := opendata.PublicMRTRequest(opendata.PublicMRTArchiveRef{Source: "routeviews", Collector: collector,
			Kind: opendata.PublicMRTBaseline, At: time.Unix(1_800_000_000, 0).Truncate(bgpVisibilityBaselineClock)}); err != nil {
			return nil, err
		}
		seen[collector] = true
	}
	cache, err := opendata.NewPublicMRTCache(directory, 512<<20, nil)
	if err != nil {
		return nil, err
	}
	return &BGPVisibilitySupervisor{server: server, cache: cache, collectors: slices.Clone(collectors), window: window, observer: observer}, nil
}

func (supervisor *BGPVisibilitySupervisor) Run(ctx context.Context) error {
	states := make(map[string]*bgpVisibilityCollectorState, len(supervisor.collectors))
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		err := supervisor.sync(ctx, states, time.Now().UTC())
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			supervisor.server.log.Warn("BGP visibility archive refresh failed", "error", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil
		}
	}
}

func (supervisor *BGPVisibilitySupervisor) sync(ctx context.Context, states map[string]*bgpVisibilityCollectorState, now time.Time) error {
	targets, err := supervisor.targets(ctx)
	if len(targets) == 0 {
		if err == nil {
			clear(states)
		}
		return err
	}
	prefixes := make([]netip.Prefix, 0, len(targets))
	for prefix := range targets {
		prefixes = append(prefixes, prefix)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Compare(b) })
	failed := err
	for _, collector := range supervisor.collectors {
		state := states[collector]
		if state == nil {
			state = &bgpVisibilityCollectorState{}
			states[collector] = state
		}
		if err := supervisor.syncCollector(ctx, state, collector, prefixes, targets, now); err != nil {
			failed = errors.Join(failed, fmt.Errorf("collector %s: %w", collector, err))
		}
	}
	return failed
}

func (supervisor *BGPVisibilitySupervisor) syncCollector(ctx context.Context, state *bgpVisibilityCollectorState,
	collector string, prefixes []netip.Prefix, targets map[netip.Prefix][]bgpVisibilityTarget, now time.Time) error {
	failed := supervisor.retryPublication(ctx, state, targets, now)
	retain := func(point bgp.PublicVisibilityCollectorPoint) {
		if err := supervisor.publish(ctx, point, targets, now); err != nil {
			failed = errors.Join(failed, err)
			state.savePending(point)
		}
	}
	clock := now.Add(-bgpVisibilityArchiveWait).Truncate(bgpVisibilityBaselineClock)
	if state.series == nil || !state.baseline.Equal(clock) || !slices.Equal(state.prefixes, prefixes) {
		ref := opendata.PublicMRTArchiveRef{Source: "routeviews", Collector: collector, Kind: opendata.PublicMRTBaseline, At: clock}
		series, err := bgp.ReadPublicVisibilityCollector(ctx, supervisor.cache, ref, bgpVisibilityArchiveBudget, bgpVisibilityBaselinePolicy, prefixes)
		if err != nil {
			return errors.Join(failed, err)
		}
		*state = bgpVisibilityCollectorState{baseline: clock, prefixes: slices.Clone(prefixes), series: series, pending: state.pending}
		retain(series.Point())
	}
	for {
		if state.gap {
			return failed
		}
		ref, more := state.series.NextArchive()
		if !more {
			return failed
		}
		request, err := opendata.PublicMRTRequest(ref)
		if err != nil {
			return errors.Join(failed, err)
		}
		if now.Before(ref.At.Add(request.Cadence + bgpVisibilityArchiveWait)) {
			return failed
		}
		if err := state.series.Advance(ctx, supervisor.cache, ref, bgpVisibilityArchiveBudget); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			state.series.MarkGap()
			state.gap = true
			supervisor.server.log.Warn("BGP visibility lost archive continuity", "collector", collector, "archive_at", ref.At, "error", err)
		}
		retain(state.series.Point())
	}
}

func (supervisor *BGPVisibilitySupervisor) retryPublication(ctx context.Context, state *bgpVisibilityCollectorState,
	targets map[netip.Prefix][]bgpVisibilityTarget, now time.Time) error {
	var failed error
	pending := state.pending[:0]
	for _, point := range state.pending {
		if point.Through.Before(now.Add(-2 * bgpVisibilityBaselineClock)) {
			continue
		}
		if err := supervisor.publish(ctx, point, targets, now); err != nil {
			pending = append(pending, point)
			failed = errors.Join(failed, err)
		}
	}
	clear(state.pending[len(pending):])
	state.pending = pending
	return failed
}

func (state *bgpVisibilityCollectorState) savePending(point bgp.PublicVisibilityCollectorPoint) {
	index := slices.IndexFunc(state.pending, func(saved bgp.PublicVisibilityCollectorPoint) bool {
		return saved.Through.Equal(point.Through)
	})
	if index >= 0 {
		state.pending[index] = point
		return
	}
	if len(state.pending) == maxVisibilityPending {
		copy(state.pending, state.pending[1:])
		state.pending = state.pending[:maxVisibilityPending-1]
	}
	state.pending = append(state.pending, point)
}

func (supervisor *BGPVisibilitySupervisor) targets(ctx context.Context) (map[netip.Prefix][]bgpVisibilityTarget, error) {
	tenants, err := store.NewTenants(supervisor.server.pool).List(ctx)
	if err != nil {
		return nil, err
	}
	targets := map[netip.Prefix][]bgpVisibilityTarget{}
	var failed error
	for _, tenant := range tenants {
		if tenant.Status != "active" {
			continue
		}
		bound := tenancy.ID(tenant.ID)
		err := tenancy.InTenant(tenancy.WithTenant(ctx, bound), supervisor.server.pool, func(ctx context.Context, sc tenancy.Scope) error {
			monitors, err := (store.BGPVisibility{}).ListMonitors(ctx, sc)
			if err != nil {
				return err
			}
			for _, monitor := range monitors {
				targets[monitor.Prefix] = append(targets[monitor.Prefix], bgpVisibilityTarget{tenant: bound, id: monitor.ID})
			}
			return nil
		})
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("tenant %s: %w", bound, err))
		}
		if len(targets) > maxSharedWatchPrefixes {
			return nil, store.ErrBGPVisibilityInput
		}
	}
	return targets, failed
}

func (supervisor *BGPVisibilitySupervisor) publish(ctx context.Context, point bgp.PublicVisibilityCollectorPoint,
	targets map[netip.Prefix][]bgpVisibilityTarget, now time.Time) error {
	var failed error
	for _, projection := range point.Points {
		observation := bgpVisibilityObservation(point, projection)
		eligibleForAlert := point.Through.After(now.Add(-30 * time.Minute))
		for _, target := range targets[projection.Prefix] {
			if err := supervisor.server.publishBGPVisibility(ctx, target.tenant, target.id, projection.Prefix,
				observation, eligibleForAlert, supervisor.window, supervisor.observer); err != nil {
				failed = errors.Join(failed, fmt.Errorf("tenant %s: %w", target.tenant, err))
			}
		}
	}
	return failed
}

func bgpVisibilityObservation(point bgp.PublicVisibilityCollectorPoint, projection bgp.PublicPrefixVisibility) store.BGPVisibilityObservation {
	minimumRoutes := bgpVisibilityBaselinePolicy.MinimumIPv6Routes
	if projection.Prefix.Addr().Is4() {
		minimumRoutes = bgpVisibilityBaselinePolicy.MinimumIPv4Routes
	}
	observation := store.BGPVisibilityObservation{Source: point.Baseline.Source, Collector: point.Baseline.Collector,
		ObservedAt: point.Through.UTC().Truncate(time.Microsecond), BaselineClock: point.Baseline.ArchiveClock,
		ArchiveClock: point.Latest.ArchiveClock, BaselineSHA256: point.Baseline.SHA256, ArchiveSHA256: point.Latest.SHA256,
		PolicyVersion: bgpVisibilityPolicyVersion, MinimumPeerRoutes: minimumRoutes, Availability: projection.Availability}
	if projection.Available {
		observation.Counts = &store.BGPVisibilityCounts{EligiblePeers: projection.EligiblePeers, VisiblePeers: projection.VisiblePeers,
			AmbiguousOriginPeers: projection.AmbiguousPeers, Origins: projection.Origins}
	}
	return observation
}
