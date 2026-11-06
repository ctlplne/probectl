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
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrBGPRoutingBatch = errors.New("routing batch is incomplete or invalid")

// These store DTOs do not interpret BGP wire bytes. The authenticated receiver
// must first validate negotiated encoding, mandatory attributes and UPDATE
// semantics. Retain segment kinds, repeated ASNs and all original attributes;
// an empty but present AS path is distinct from a missing path.
type BGPRoutingSegment struct {
	Kind   uint8
	Values []uint32
}

type BGPRoutingAttribute struct {
	Flags, Type uint8
	Value       []byte
}

type BGPRoutingAttributes struct{ Wire []BGPRoutingAttribute }

type BGPRoutingChange struct {
	Prefix     netip.Prefix
	HasPathID  bool
	PathID     uint32
	Withdraw   bool
	Segments   []BGPRoutingSegment
	Attributes BGPRoutingAttributes
	NextHops   []netip.Addr
}

// EndOfRIB is only set by an exact, exclusive, negotiated-family completion
// marker from the authenticated receiver. A caller cannot use an empty route
// list as a completion marker. Sequence is scoped to the immutable generation.
type BGPRoutingBatch struct {
	WireDigest []byte `json:"WireDigest,omitempty"` // exact complete source frame, not interpreted fields alone
	Sequence   int64
	AFI        uint16
	SAFI       uint8
	ObservedAt time.Time
	EndOfRIB   bool
	Heartbeat  bool `json:"Heartbeat,omitempty"`
	Changes    []BGPRoutingChange
}

type BGPRoutingViewRef struct{ ID, Generation string }

// Invalidated is a committed refusal, not an accepted batch. Callers must
// commit that result before reporting the refusal. Returning an error instead
// would roll back the invalidation and could expose a former complete view.
type BGPRoutingApplyResult struct {
	Status string // applied, replayed, invalidated
	Reason string
}

type routingPreparedChange struct {
	BGPRoutingChange
	segments, attributes []byte
	hops                 []string
}

type routingWriteView struct {
	state                      string
	afi                        uint16
	safi                       uint8
	nextSequence, lastSequence int64
	lastDigest                 []byte
	born, validUntil           time.Time
	lastObservedAt             *time.Time
	clockSequence              *int64
	bytes, rows                int64
}

func routingBatchCharge(profile *BGPRoutingBudget, memory, work int64) error {
	if memory < 0 || work < 0 || memory > profile.MemoryBytes || work > profile.WorkUnits || profile.StateBytes <= 0 {
		return ErrBGPRoutingBudget
	}
	profile.MemoryBytes -= memory
	profile.WorkUnits -= work
	return nil
}

func routingBatchPopulationCharge(profile *BGPRoutingBudget, count int, memory, work int64) error {
	if int64(count) > profile.MemoryBytes/memory || int64(count) > profile.WorkUnits/work {
		return ErrBGPRoutingBudget
	}
	return routingBatchCharge(profile, int64(count)*memory, int64(count)*work)
}

func prepareRoutingBatch(ctx context.Context, batch BGPRoutingBatch, afi uint16, safi uint8, profile BGPRoutingBudget) ([]routingPreparedChange, [32]byte, error) {
	var digest [32]byte
	if err := ctx.Err(); err != nil {
		return nil, digest, err
	}
	if len(batch.WireDigest) != 0 && len(batch.WireDigest) != 32 || batch.Sequence <= 0 || batch.Sequence == math.MaxInt64 || batch.AFI != afi || batch.SAFI != safi ||
		(afi != 1 && afi != 2) || safi != 1 || batch.ObservedAt.IsZero() ||
		batch.EndOfRIB && len(batch.Changes) != 0 || batch.Heartbeat && (batch.EndOfRIB || len(batch.Changes) != 0) {
		return nil, digest, ErrBGPRoutingBatch
	}
	if batch.Heartbeat && profile.LeaseDuration <= 0 {
		return nil, digest, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(&profile, 1024, 64); err != nil {
		return nil, digest, err
	}
	// Admit the whole decoded representation and its JSON/digest/plan copies
	// before allocating them. There is no prefix/path/attribute population cap.
	for _, change := range batch.Changes {
		if err := ctx.Err(); err != nil {
			return nil, digest, err
		}
		if err := routingBatchCharge(&profile, 2048, 256); err != nil {
			return nil, digest, err
		}
		for _, segment := range change.Segments {
			if err := routingBatchCharge(&profile, 256, 32); err != nil {
				return nil, digest, err
			}
			if err := routingBatchPopulationCharge(&profile, len(segment.Values), 128, 32); err != nil {
				return nil, digest, err
			}
		}
		for _, attribute := range change.Attributes.Wire {
			if err := routingBatchCharge(&profile, 256, 32); err != nil {
				return nil, digest, err
			}
			if err := routingBatchPopulationCharge(&profile, len(attribute.Value), 16, 8); err != nil {
				return nil, digest, err
			}
		}
		if err := routingBatchPopulationCharge(&profile, len(change.NextHops), 512, 128); err != nil {
			return nil, digest, err
		}
		if err := validateRoutingChange(change, afi); err != nil {
			return nil, digest, err
		}
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return nil, digest, err
	}
	prepared := make([]routingPreparedChange, 0, len(batch.Changes))
	for _, change := range batch.Changes {
		if err := ctx.Err(); err != nil {
			return nil, digest, err
		}
		segments, err := json.Marshal(change.Segments)
		if err != nil {
			return nil, digest, err
		}
		attributes, err := json.Marshal(change.Attributes)
		if err != nil {
			return nil, digest, err
		}
		hops := make([]string, len(change.NextHops))
		for index, address := range change.NextHops {
			hops[index] = address.String()
		}
		prepared = append(prepared, routingPreparedChange{BGPRoutingChange: change, segments: segments, attributes: attributes, hops: hops})
	}
	if err := ctx.Err(); err != nil {
		return nil, digest, err
	}
	copy(digest[:], crypto.Hash(body))
	return prepared, digest, nil
}

func validateRoutingChange(change BGPRoutingChange, afi uint16) error {
	if !change.Prefix.IsValid() || change.Prefix != change.Prefix.Masked() || (afi == 1) != change.Prefix.Addr().Is4() || !change.HasPathID && change.PathID != 0 {
		return ErrBGPRoutingBatch
	}
	if change.Withdraw {
		if len(change.Segments) != 0 || len(change.Attributes.Wire) != 0 || len(change.NextHops) != 0 {
			return ErrBGPRoutingBatch
		}
		return nil
	}
	if change.Segments == nil || change.Attributes.Wire == nil || len(change.NextHops) == 0 {
		return ErrBGPRoutingBatch
	}
	for _, segment := range change.Segments {
		if segment.Kind < 1 || segment.Kind > 4 || len(segment.Values) == 0 {
			return ErrBGPRoutingBatch
		}
	}
	for _, hop := range change.NextHops {
		if !hop.IsValid() || hop.Zone() != "" {
			return ErrBGPRoutingBatch
		}
	}
	return nil
}

func loadRoutingWriteView(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef) (routingWriteView, error) {
	var view routingWriteView
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return view, err
	}
	for _, id := range []string{ref.ID, ref.Generation} {
		if normalized, err := validRegistryUUID(id); err != nil || normalized != id {
			return view, ErrBGPRoutingView
		}
	}
	err = sc.Q.QueryRow(ctx, `SELECT state,afi,safi,next_sequence,last_sequence,last_digest,observed_at,valid_until,charged_bytes,row_count,last_message_observed_at,message_clock_sequence
 FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4
 AND source_kind='router_bmp' AND router_id=$5 AND collector_agent_id=$6 AND source_ref=$7
 AND sender_serial=$8 AND origin_serial=$9 AND routing_selection IS NOT DISTINCT FROM $10::jsonb FOR UPDATE`, source.TenantID, source.ContextID, ref.ID, ref.Generation,
		source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, selection).
		Scan(&view.state, &view.afi, &view.safi, &view.nextSequence, &view.lastSequence, &view.lastDigest,
			&view.born, &view.validUntil, &view.bytes, &view.rows, &view.lastObservedAt, &view.clockSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingWriteView{}, ErrBGPRoutingSourceUnavailable
	}
	return view, err
}

func invalidateRoutingView(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, reason string) (BGPRoutingApplyResult, error) {
	_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, ref.ID, ref.Generation)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return BGPRoutingApplyResult{Status: "invalidated", Reason: reason}, nil
}

// invalidateViewInScope closes a known authenticated stream generation before
// attempting any replacement metadata or route admission. It needs no payload
// budget, so an exhausted replacement cannot keep former local attribution
// alive. The caller commits this control transaction before starting a new one.
func (store BGPRouting) invalidateViewInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef) (BGPRoutingApplyResult, error) {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	view, err := loadRoutingWriteView(ctx, sc, source, ref)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if _, err := store.sourceAuthorityForWriteInScope(ctx, sc, source); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	birth := source
	birth.ObservedAt = view.born
	if _, err := store.sourceAuthorityForWriteInScope(ctx, sc, birth); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return invalidateRoutingView(ctx, sc, source, ref, "source-reset")
}

// applyBatchInScope applies a whole ordered generation batch or commits a
// refusal invalidation. Caller owns a fenced read-committed tenant transaction;
// all errors abort it. No rejected result extends the existing view lease.
func (store BGPRouting) applyBatchInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, batch BGPRoutingBatch, profile BGPRoutingBudget) (BGPRoutingApplyResult, error) {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	view, err := loadRoutingWriteView(ctx, sc, source, ref)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	// Check both this message's observation and the original generation birth.
	// A newly assigned source cannot revive a former generation with a new clock.
	authority, err := store.sourceAuthorityForWriteInScope(ctx, sc, source)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	birth := source
	birth.ObservedAt = view.born
	if _, err := store.sourceAuthorityForWriteInScope(ctx, sc, birth); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if view.state == "invalid" || !view.validUntil.After(authority.AsOf) {
		return invalidateRoutingView(ctx, sc, source, ref, "inactive-generation")
	}
	if view.lastObservedAt == nil || view.clockSequence == nil || *view.clockSequence != view.lastSequence {
		return invalidateRoutingView(ctx, sc, source, ref, "unavailable-message-clock")
	}
	prepared, digest, err := prepareRoutingBatch(ctx, batch, view.afi, view.safi, profile)
	if err != nil || !batch.ObservedAt.Equal(source.ObservedAt) || batch.ObservedAt.Before(*view.lastObservedAt) {
		if ctx.Err() != nil {
			return BGPRoutingApplyResult{}, ctx.Err()
		}
		return invalidateRoutingView(ctx, sc, source, ref, "invalid-batch")
	}
	if batch.Sequence == view.lastSequence && string(digest[:]) == string(view.lastDigest) {
		if err := store.checkRoutingWriteLease(ctx, sc, birth, view.validUntil); err != nil {
			return BGPRoutingApplyResult{}, err
		}
		return BGPRoutingApplyResult{Status: "replayed"}, nil
	}
	if batch.Sequence != view.nextSequence {
		return invalidateRoutingView(ctx, sc, source, ref, "sequence-gap-or-conflict")
	}
	lease, err := routingBatchLease(ctx, sc, batch, profile.LeaseDuration, view.validUntil, authority.ValidUntil)
	if errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		return invalidateRoutingView(ctx, sc, source, ref, "stale-heartbeat")
	}
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	plan, used, rows, err := planRoutingChanges(ctx, sc, source, ref, view, prepared, profile)
	if errors.Is(err, ErrBGPRoutingBudget) {
		return invalidateRoutingView(ctx, sc, source, ref, "state-budget")
	}
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	if err := persistRoutingChanges(ctx, sc, source, ref, batch, plan); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	// Locks serialize explicit changes, but do not stop time. Refuse and roll
	// back the whole batch if processing crossed the source or view expiry.
	if err := store.checkRoutingWriteLease(ctx, sc, birth, view.validUntil); err != nil {
		return BGPRoutingApplyResult{}, err
	}
	_, err = sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET next_sequence=$5::bigint+1,last_sequence=$5::bigint,last_digest=$6,
 charged_bytes=$7,row_count=$8,state=CASE WHEN $9 THEN 'current' ELSE state END,
 completed_at=CASE WHEN $9 THEN COALESCE(completed_at,clock_timestamp()) ELSE completed_at END,updated_at=clock_timestamp(),
 last_message_observed_at=$10,message_clock_sequence=$5::bigint,valid_until=$11
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, ref.ID, ref.Generation,
		batch.Sequence, digest[:], used, rows, batch.EndOfRIB, batch.ObservedAt, lease)
	if err != nil {
		return BGPRoutingApplyResult{}, err
	}
	return BGPRoutingApplyResult{Status: "applied"}, nil
}

func routingBatchLease(ctx context.Context, sc tenancy.Scope, batch BGPRoutingBatch, duration time.Duration, previous, authorityExpiry time.Time) (time.Time, error) {
	if !batch.Heartbeat {
		return previous, nil
	}
	lease := batch.ObservedAt.Add(duration)
	if authorityExpiry.Before(lease) {
		lease = authorityExpiry
	}
	var now time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, err
	}
	if !lease.After(now) {
		return time.Time{}, ErrBGPRoutingSourceUnavailable
	}
	return lease, nil
}

func (store BGPRouting) checkRoutingWriteLease(ctx context.Context, sc tenancy.Scope, birth BGPRoutingSource, validUntil time.Time) error {
	authority, err := store.sourceAuthorityForWriteInScope(ctx, sc, birth)
	if err != nil {
		return err
	}
	if !validUntil.After(authority.AsOf) {
		return ErrBGPRoutingSourceUnavailable
	}
	return nil
}

type routingRowKey struct {
	prefix netip.Prefix
	path   uint32
	hasID  bool
}

type routingPlannedChange struct {
	routingPreparedChange
	charge int64
}

func planRoutingChanges(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, view routingWriteView, changes []routingPreparedChange, profile BGPRoutingBudget) ([]routingPlannedChange, int64, int64, error) {
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return nil, 0, 0, err
	}
	initialUsed, rows, ownBytes := used, view.rows, view.bytes
	plan := make([]routingPlannedChange, 0, len(changes))
	indices := make(map[routingRowKey]int, len(changes))
	for _, change := range changes {
		key := routingRowKey{change.Prefix, change.PathID, change.HasPathID}
		index, present := indices[key]
		var old int64
		if present {
			old = plan[index].charge
		} else {
			err := sc.Q.QueryRow(ctx, `SELECT charged_bytes FROM bgp_routing_entries
 WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4 AND prefix=$5::cidr AND has_path_id=$6 AND path_id=$7`,
				source.TenantID, source.ContextID, ref.ID, ref.Generation, change.Prefix.String(), change.HasPathID, int64(change.PathID)).Scan(&old)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, 0, 0, err
			}
			index = len(plan)
			indices[key] = index
			plan = append(plan, routingPlannedChange{})
		}
		charge := int64(0)
		if !change.Withdraw {
			if err := sc.Q.QueryRow(ctx, `SELECT 256+octet_length($1::jsonb::text)::bigint+octet_length($2::jsonb::text)+octet_length(to_json($3::inet[])::text)+octet_length($4::text)`,
				string(change.segments), string(change.attributes), change.hops, change.Prefix.String()).Scan(&charge); err != nil {
				return nil, 0, 0, err
			}
		}
		if old > used || old > ownBytes || charge < 0 || charge > math.MaxInt64-(used-old) {
			return nil, 0, 0, ErrBGPRoutingBudget
		}
		used, ownBytes = used-old+charge, ownBytes-old+charge
		if old == 0 && charge > 0 {
			rows++
		} else if old > 0 && charge == 0 {
			rows--
		}
		plan[index] = routingPlannedChange{routingPreparedChange: change, charge: charge}
	}
	if used > profile.StateBytes || ownBytes < 0 || rows < 0 || ownBytes-view.bytes != used-initialUsed {
		return nil, 0, 0, ErrBGPRoutingBudget
	}
	return plan, ownBytes, rows, nil
}

func persistRoutingChanges(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, batch BGPRoutingBatch, plan []routingPlannedChange) error {
	for _, change := range plan {
		if change.Withdraw {
			if _, err := sc.Q.Exec(ctx, `DELETE FROM bgp_routing_entries WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4 AND prefix=$5::cidr AND has_path_id=$6 AND path_id=$7`,
				source.TenantID, source.ContextID, ref.ID, ref.Generation, change.Prefix.String(), change.HasPathID, int64(change.PathID)); err != nil {
				return err
			}
			continue
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO bgp_routing_entries
 (tenant_id,context_id,view_id,generation,afi,safi,prefix,has_path_id,path_id,segments,attributes,next_hops,sequence,observed_at,charged_bytes)
 VALUES($1,$2,$3,$4,$5,$6,$7::cidr,$8,$9,$10::jsonb,$11::jsonb,$12::inet[],$13,$14,$15)
 ON CONFLICT(tenant_id,context_id,view_id,generation,prefix,has_path_id,path_id) DO UPDATE
 SET segments=EXCLUDED.segments,attributes=EXCLUDED.attributes,next_hops=EXCLUDED.next_hops,
 sequence=EXCLUDED.sequence,observed_at=EXCLUDED.observed_at,charged_bytes=EXCLUDED.charged_bytes`,
			source.TenantID, source.ContextID, ref.ID, ref.Generation, batch.AFI, batch.SAFI, change.Prefix.String(), change.HasPathID, int64(change.PathID),
			string(change.segments), string(change.attributes), change.hops, batch.Sequence, batch.ObservedAt, change.charge)
		if err != nil {
			return err
		}
	}
	return nil
}
