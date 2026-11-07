// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPPublicRoutingView is private staging. It has neither a router identity nor
// a BMP completion marker. It must not be returned by current route readers.
type BGPPublicRoutingView struct {
	BGPPublicRoutingSource
	ID, Generation string
	Definition     BGPRoutingViewDefinition
	PeerKey        [32]byte
	ValidUntil     time.Time
}

func publicRoutingSourceRef(peer BGPPublicRoutingPeer) string {
	return peer.Feed + "/" + peer.Format + "/" + peer.Collector
}

// beginPublicViewInScope requires the caller's fenced, read-committed tenant
// transaction. Every error must abort that transaction, retaining the former
// slot. Successful replacement withdraws the former slot and inserts private
// staging only. Complete source/cohort publication is a separate operation.
func (store BGPRouting) beginPublicViewInScope(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource,
	definition BGPRoutingViewDefinition, budget BGPRoutingBudget) (BGPPublicRoutingView, error) {
	none := BGPPublicRoutingView{}
	if err := validatePublicRoutingSource(ctx, sc, source); err != nil {
		return none, err
	}
	if budget.LeaseDuration <= 0 {
		return none, ErrBGPRoutingBudget
	}
	if definition.Public == nil || publicRoutingSourceRef(*definition.Public) != source.SourceRef {
		return none, ErrBGPRoutingView
	}
	operation := budget
	for _, value := range []string{source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef, source.SenderSerial} {
		if err := routingBatchPopulationCharge(&operation, len(value), 16, 8); err != nil {
			return none, err
		}
	}
	peer := *definition.Public
	clock := source.ObservedAt.UnixNano()
	if !time.Unix(0, clock).Equal(source.ObservedAt) {
		return none, ErrBGPRoutingView
	}
	peer.CollectorObservedUnixNanos = &clock
	definition.Public = &peer
	body, key, err := publicRoutingViewMetadata(ctx, definition, operation)
	if err != nil {
		return none, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	authority, err := store.publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, err
	}
	until := source.ObservedAt.Add(budget.LeaseDuration)
	if authority.ValidUntil.Before(until) {
		until = authority.ValidUntil
	}
	if !until.After(authority.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	charge, err := admitPublicRoutingMetadata(ctx, sc, source, body, budget)
	if err != nil {
		return none, err
	}
	var latest *time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT max(observed_at) FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND collector_agent_id=$3 AND source_ref=$4
 AND source_kind='public_bgp' AND peer_key=$5 AND afi=$6 AND safi=$7`,
		source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef, key[:], definition.AFI, definition.SAFI).Scan(&latest); err != nil {
		return none, err
	}
	if latest != nil && !source.ObservedAt.Truncate(time.Microsecond).After(*latest) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	id, err := newRegistryID()
	if err != nil {
		return none, err
	}
	generation, err := newRegistryID()
	if err != nil {
		return none, err
	}
	if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND collector_agent_id=$3 AND source_ref=$4
 AND source_kind='public_bgp' AND peer_key=$5 AND afi=$6 AND safi=$7 AND state IN ('staging','current')`,
		source.TenantID, source.ContextID, source.CollectorAgentID, source.SourceRef, key[:], definition.AFI, definition.SAFI); err != nil {
		return none, err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_routing_views
 (tenant_id,context_id,id,generation,source_kind,collector_agent_id,source_ref,sender_serial,
 view_kind,peer_key,peer_identity,afi,safi,filtered,state,charged_bytes,observed_at,valid_until,
 last_message_observed_at,message_clock_sequence)
 VALUES($1,$2,$3,$4,'public_bgp',$5,$6,$7,'public_bgp',$8,$9::jsonb,$10,$11,$12,'staging',$13,$14,$15,$14,0)`,
		source.TenantID, source.ContextID, id, generation, source.CollectorAgentID, source.SourceRef, source.SenderSerial,
		key[:], string(body), definition.AFI, definition.SAFI, definition.Filtered, charge, source.ObservedAt, until); err != nil {
		return none, err
	}
	// A quota/configuration lock wait can consume the lease. Keep the exact
	// source and its birth current through the last write before publication.
	current, err := store.publicSourceAuthorityInScope(ctx, sc, source, true)
	if err != nil {
		return none, err
	}
	if !until.After(current.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	var owned BGPPublicRoutingPeer
	if err := json.Unmarshal(body, &owned); err != nil {
		return none, err
	}
	definition.Public = &owned
	return BGPPublicRoutingView{BGPPublicRoutingSource: source, ID: id, Generation: generation, Definition: definition, PeerKey: key, ValidUntil: until}, nil
}

func admitPublicRoutingMetadata(ctx context.Context, sc tenancy.Scope, source BGPPublicRoutingSource, body []byte, budget BGPRoutingBudget) (int64, error) {
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return 0, err
	}
	var charge int64
	if err := sc.Q.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)::bigint+256`, string(body)).Scan(&charge); err != nil {
		return 0, err
	}
	for _, value := range []string{source.CollectorAgentID, source.SourceRef, source.SenderSerial} {
		if charge < 0 || charge > budget.StateBytes || int64(len(value)) > budget.StateBytes-charge {
			return 0, ErrBGPRoutingBudget
		}
		charge += int64(len(value))
	}
	if used < 0 || charge < 0 || charge > budget.StateBytes || used > budget.StateBytes-charge {
		return 0, ErrBGPRoutingBudget
	}
	return charge, nil
}
