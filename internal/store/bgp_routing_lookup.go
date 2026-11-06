// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	errBGPRoutingReadSnapshot = errors.New("routing lookup requires a repeatable tenant snapshot")
	errBGPRoutingRouteMissing = errors.New("complete current routing view has no matching prefix")
)

// routingLookup preserves all paths at the longest matching prefix. Loc-RIB
// means selected BGP routes, never a proof of installed forwarding state. The
// eventual exporter resolver must independently bind this exact router/context
// and label a public fallback; an adjacent view cannot stand in for Loc-RIB.
type routingLookup struct {
	Source                           BGPRoutingSource
	View                             BGPRoutingViewRef
	Prefix                           netip.Prefix
	Paths                            []BGPRoutingChange
	AsOf, ValidUntil, LastObservedAt time.Time
	LastSequence                     int64
}

type routingReadView struct {
	born, validUntil time.Time
	lastObservedAt   *time.Time
	lastSequence     int64
	clockSequence    *int64
}

// lookupViewInScope consumes the same tenant snapshot as its caller's entity
// and grant resolution. No page, partial path set or historical generation may
// escape an admission, source, lease or decoding failure.
func (store BGPRouting) lookupViewInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource,
	ref BGPRoutingViewRef, address netip.Addr, budget BGPRoutingBudget) (routingLookup, error) {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return routingLookup{}, err
	}
	if !address.IsValid() || address.Zone() != "" {
		return routingLookup{}, ErrBGPRoutingView
	}
	for _, id := range []string{ref.ID, ref.Generation} {
		if normalized, err := validRegistryUUID(id); err != nil || normalized != id {
			return routingLookup{}, ErrBGPRoutingView
		}
	}
	if err := routingBatchCharge(&budget, 2048, 256); err != nil {
		return routingLookup{}, err
	}
	for _, value := range []string{source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial} {
		if int64(len(value)) > budget.MemoryBytes/4 || int64(len(value)) > budget.WorkUnits/2 {
			return routingLookup{}, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(&budget, int64(len(value))*4, int64(len(value))*2); err != nil {
			return routingLookup{}, err
		}
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return routingLookup{}, err
	}
	afi := uint16(2)
	if address.Is4() {
		afi = 1
	}
	view, err := loadRoutingReadView(ctx, sc, source, ref, afi)
	if err != nil {
		return routingLookup{}, err
	}
	birth := source
	birth.ObservedAt = view.born
	authority, err := store.sourceAuthorityInScope(ctx, sc, birth)
	if err != nil {
		return routingLookup{}, err
	}
	if view.lastObservedAt == nil || view.clockSequence == nil || *view.clockSequence != view.lastSequence ||
		view.lastSequence <= 0 || view.lastObservedAt.Before(view.born) || view.lastObservedAt.After(authority.AsOf) {
		return routingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	deadline := minRoutingTime(view.validUntil, authority.ValidUntil)
	if !deadline.After(authority.AsOf) {
		return routingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	result, err := readRoutingLongestPrefix(ctx, sc, birth, ref, address, afi, view, budget)
	if err != nil && !errors.Is(err, errBGPRoutingRouteMissing) {
		return routingLookup{}, err
	}
	// The query may have waited for IO. A transaction-start timestamp alone
	// must not serve routes after their source/credential or heartbeat expires.
	var finished time.Time
	if clockErr := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&finished); clockErr != nil {
		return routingLookup{}, clockErr
	}
	if !deadline.After(finished) {
		return routingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return routingLookup{}, err
	}
	result.AsOf, result.ValidUntil = authority.AsOf, deadline
	return result, nil
}

func minRoutingTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func loadRoutingReadView(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, afi uint16) (routingReadView, error) {
	var view routingReadView
	err := sc.Q.QueryRow(ctx, `SELECT observed_at,valid_until,last_message_observed_at,last_sequence,message_clock_sequence
 FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4
 AND source_kind='router_bmp' AND router_id=$5 AND collector_agent_id=$6 AND source_ref=$7
 AND sender_serial=$8 AND origin_serial=$9 AND view_kind='loc_rib' AND NOT filtered
 AND state='current' AND completed_at IS NOT NULL AND afi=$10 AND safi=1`,
		source.TenantID, source.ContextID, ref.ID, ref.Generation, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, afi).
		Scan(&view.born, &view.validUntil, &view.lastObservedAt, &view.lastSequence, &view.clockSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingReadView{}, ErrBGPRoutingSourceUnavailable
	}
	return view, err
}

func readRoutingLongestPrefix(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef,
	address netip.Addr, afi uint16, view routingReadView, budget BGPRoutingBudget) (routingLookup, error) {
	for bits := address.BitLen(); bits >= 0; bits-- {
		if err := ctx.Err(); err != nil {
			return routingLookup{}, err
		}
		if err := routingBatchCharge(&budget, 0, 128); err != nil {
			return routingLookup{}, err
		}
		prefix := netip.PrefixFrom(address, bits).Masked()
		var count, encoded int64
		err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(segments::text)+octet_length(attributes::text)+octet_length(next_hops::text)+256),0)::bigint
 FROM bgp_routing_entries WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4 AND prefix=$5::cidr AND afi=$6 AND safi=1`,
			source.TenantID, source.ContextID, ref.ID, ref.Generation, prefix.String(), afi).Scan(&count, &encoded)
		if err != nil {
			return routingLookup{}, err
		}
		if count == 0 {
			continue
		}
		// Charge complete JSON/inet decoding and every output row before reading
		// bodies. The snapshot binds this account to exactly the rows read below.
		if count < 0 || encoded < 0 || encoded > budget.MemoryBytes/32 || encoded > budget.WorkUnits/8 ||
			count > budget.MemoryBytes/1024 || count > budget.WorkUnits/256 {
			return routingLookup{}, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(&budget, encoded*32, encoded*8); err != nil {
			return routingLookup{}, err
		}
		if count > budget.MemoryBytes/1024 || count > budget.WorkUnits/256 {
			return routingLookup{}, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(&budget, count*1024, count*256); err != nil {
			return routingLookup{}, err
		}
		paths, err := readRoutingPaths(ctx, sc, source, ref, prefix, afi, view, count)
		if err != nil {
			return routingLookup{}, err
		}
		return routingLookup{Source: source, View: ref, Prefix: prefix, Paths: paths, LastSequence: view.lastSequence, LastObservedAt: *view.lastObservedAt}, nil
	}
	return routingLookup{}, errBGPRoutingRouteMissing
}

func readRoutingPaths(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef,
	prefix netip.Prefix, afi uint16, view routingReadView, count int64) ([]BGPRoutingChange, error) {
	rows, err := sc.Q.Query(ctx, `SELECT has_path_id,path_id,segments,attributes,next_hops,sequence,observed_at
 FROM bgp_routing_entries WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4 AND prefix=$5::cidr AND afi=$6 AND safi=1
 ORDER BY has_path_id,path_id`, source.TenantID, source.ContextID, ref.ID, ref.Generation, prefix.String(), afi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := make([]BGPRoutingChange, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int64(len(paths)) >= count {
			return nil, ErrBGPRoutingView
		}
		change := BGPRoutingChange{Prefix: prefix}
		var id int64
		var segments, attributes []byte
		var hops []netip.Addr
		var sequence int64
		var observed time.Time
		if err := rows.Scan(&change.HasPathID, &id, &segments, &attributes, &hops, &sequence, &observed); err != nil {
			return nil, err
		}
		if id < 0 || id > 4294967295 || sequence <= 0 || sequence > view.lastSequence || observed.Before(view.born) || observed.After(*view.lastObservedAt) {
			return nil, ErrBGPRoutingView
		}
		change.PathID = uint32(id)
		change.NextHops = hops
		if err := json.Unmarshal(segments, &change.Segments); err != nil {
			return nil, ErrBGPRoutingView
		}
		if err := json.Unmarshal(attributes, &change.Attributes); err != nil {
			return nil, ErrBGPRoutingView
		}
		if err := validateRoutingChange(change, afi); err != nil {
			return nil, err
		}
		paths = append(paths, change)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if int64(len(paths)) != count {
		return nil, ErrBGPRoutingView
	}
	return paths, nil
}
