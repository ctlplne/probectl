// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPPublicRoutingPath retains the peer and view for every complete path.
// Public collectors describe internet visibility, never router selection.
type BGPPublicRoutingPath struct {
	View BGPRoutingViewRef
	Peer BGPPublicRoutingPeer
	Path BGPRoutingChange
}

type BGPPublicRoutingLookup struct {
	Source                  BGPPublicRoutingSource
	SnapshotID              string
	SourceObservedUnixNanos int64
	Prefix                  netip.Prefix
	Paths                   []BGPPublicRoutingPath
	AsOf, ValidUntil        time.Time
}

// LookupPublicSnapshotInScope reads an exact, complete source incarnation in
// the caller's repeatable tenant snapshot. It is an ingestion seam, not a user
// grant. Served readers must independently authorize the original context and
// source. No peer-provided router or tenant field can select this scope.
func (store BGPRouting) LookupPublicSnapshotInScope(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, address netip.Addr, profile BGPRoutingBudget, maxAge time.Duration) (BGPPublicRoutingLookup, error) {
	if err := validatePublicRoutingSource(ctx, sc, source); err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	if canonical, err := validRegistryUUID(id); err != nil || canonical != id || !address.IsValid() || address.Zone() != "" {
		return BGPPublicRoutingLookup{}, ErrBGPRoutingView
	}
	if err := routingBatchCharge(&profile, 4096, 512); err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	header, err := loadCurrentPublicSnapshot(ctx, sc, source, id, profile)
	if err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	source.ObservedAt = time.Unix(0, header.observedNanos)
	authority, err := store.publicSourceAuthorityInScope(ctx, sc, source, false)
	if err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	if header.observedNanos < 0 || header.lastSequence <= 0 || header.nextSequence != header.lastSequence+1 || len(header.lastDigest) != 32 || header.lastClock < header.observedNanos || time.Unix(0, header.lastClock).After(authority.AsOf) {
		return BGPPublicRoutingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	until, err := publicSnapshotDataLease(header.sourceClock, authority.AsOf, header.until, authority.ValidUntil, maxAge)
	if err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	manifestBudget := profile
	manifestBudget.MemoryBytes /= 2
	manifestBudget.WorkUnits /= 2
	peers, err := loadPublicSnapshotManifest(ctx, sc, source, id, header, manifestBudget, "current")
	if err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	profile.MemoryBytes /= 2
	profile.WorkUnits /= 2
	prefix, paths, lookupErr := readPublicSnapshotLongestPrefix(ctx, sc, source, id, address.Unmap(), header, peers, profile)
	if lookupErr != nil && !errors.Is(lookupErr, ErrBGPRoutingRouteMissing) {
		return BGPPublicRoutingLookup{}, lookupErr
	}
	var finished time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&finished); err != nil {
		return BGPPublicRoutingLookup{}, err
	}
	if !until.After(finished) {
		return BGPPublicRoutingLookup{}, ErrBGPRoutingSourceUnavailable
	}
	if lookupErr != nil {
		return BGPPublicRoutingLookup{}, lookupErr
	}
	return BGPPublicRoutingLookup{Source: source, SnapshotID: id, SourceObservedUnixNanos: *header.sourceClock, Prefix: prefix, Paths: paths, AsOf: authority.AsOf, ValidUntil: until}, nil
}

func loadCurrentPublicSnapshot(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, profile BGPRoutingBudget) (publicSnapshotWriteState, error) {
	var header publicSnapshotWriteState
	var hasSourceRecord bool
	err := sc.Q.QueryRow(ctx, `SELECT state,observed_unix_nanos,last_message_unix_nanos,next_sequence,last_sequence,expected_views,manifest_digest,last_digest,source_observed_unix_nanos,valid_until
 ,source_record IS NOT NULL,CASE WHEN octet_length(source_record)<=$7 THEN source_record ELSE NULL END
 FROM bgp_public_snapshots WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND collector_agent_id=$4 AND source_ref=$5 AND sender_serial=$6
 AND state='current' AND completed_at IS NOT NULL`, source.TenantID, source.ContextID, id, source.CollectorAgentID, source.SourceRef, source.SenderSerial, profile.MemoryBytes/128).Scan(&header.state, &header.observedNanos, &header.lastClock, &header.nextSequence, &header.lastSequence, &header.expectedViews, &header.manifestDigest, &header.lastDigest, &header.sourceClock, &header.until, &hasSourceRecord, &header.sourceRecord)
	if errors.Is(err, pgx.ErrNoRows) {
		return publicSnapshotWriteState{}, ErrBGPRoutingSourceUnavailable
	}
	if err == nil && hasSourceRecord && header.sourceRecord == nil {
		return publicSnapshotWriteState{}, ErrBGPRoutingBudget
	}
	return header, err
}

func readPublicSnapshotLongestPrefix(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, id string, address netip.Addr, header publicSnapshotWriteState, peers []publicSnapshotReadPeer, profile BGPRoutingBudget) (netip.Prefix, []BGPPublicRoutingPath, error) {
	for bits := address.BitLen(); bits >= 0; bits-- {
		if err := ctx.Err(); err != nil {
			return netip.Prefix{}, nil, err
		}
		if err := routingBatchCharge(&profile, 0, 128); err != nil {
			return netip.Prefix{}, nil, err
		}
		prefix := netip.PrefixFrom(address, bits).Masked()
		var present bool
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bgp_routing_entries e
 JOIN bgp_routing_views v ON(v.tenant_id,v.context_id,v.id,v.generation)=(e.tenant_id,e.context_id,e.view_id,e.generation)
 WHERE v.tenant_id=$1 AND v.context_id=$2 AND v.public_snapshot_id=$3 AND e.prefix=$4::cidr)`, source.TenantID, source.ContextID, id, prefix.String()).Scan(&present); err != nil {
			return netip.Prefix{}, nil, err
		}
		if present {
			paths, err := readPublicSnapshotPrefixPaths(ctx, sc, source, prefix, header, peers, profile)
			return prefix, paths, err
		}
	}
	return netip.Prefix{}, nil, ErrBGPRoutingRouteMissing
}

func readPublicSnapshotPrefixPaths(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, prefix netip.Prefix, header publicSnapshotWriteState, peers []publicSnapshotReadPeer, profile BGPRoutingBudget) ([]BGPPublicRoutingPath, error) {
	afi := uint16(2)
	if prefix.Addr().Is4() {
		afi = 1
	}
	last := time.Unix(0, header.lastClock).Round(time.Microsecond)
	view := routingReadView{born: time.Unix(0, header.observedNanos).Round(time.Microsecond), lastSequence: header.lastSequence, lastObservedAt: &last}
	result := make([]BGPPublicRoutingPath, 0)
	for _, peer := range peers {
		if peer.AFI != afi {
			continue
		}
		var count, encoded int64
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(segments::text)+octet_length(attributes::text)+octet_length(next_hops::text)+256),0)::bigint
 FROM bgp_routing_entries WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4 AND prefix=$5::cidr AND afi=$6 AND safi=1`, source.TenantID, source.ContextID, peer.ID, peer.Generation, prefix.String(), afi).Scan(&count, &encoded); err != nil {
			return nil, err
		}
		if count < 0 || encoded < 0 || encoded > profile.MemoryBytes/32 || encoded > profile.WorkUnits/8 || count > profile.MemoryBytes/1024 || count > profile.WorkUnits/256 {
			return nil, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(&profile, encoded*32, encoded*8); err != nil {
			return nil, err
		}
		if err := routingBatchCharge(&profile, count*1024, count*256); err != nil {
			return nil, err
		}
		paths, err := readRoutingPaths(ctx, sc, source.Scope, peer.BGPRoutingViewRef, prefix, afi, view, count)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			result = append(result, BGPPublicRoutingPath{View: peer.BGPRoutingViewRef, Peer: peer.Peer, Path: path})
		}
	}
	if len(result) == 0 {
		return nil, ErrBGPRoutingView
	}
	return result, nil
}
