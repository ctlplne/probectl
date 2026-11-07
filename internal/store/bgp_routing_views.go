// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrBGPRoutingBudget        = errors.New("complete routing state admission exceeded")
	ErrBGPRoutingView          = errors.New("routing view metadata is invalid")
	ErrBGPRoutingWriteSnapshot = errors.New("routing writes require a read-committed tenant transaction")
)

// BGPRoutingBudget admits a complete operation and retained tenant state.
// Positive byte/work profiles bound resources, never a route population.
type BGPRoutingBudget struct {
	MemoryBytes, WorkUnits, StateBytes int64
	// LeaseDuration is operator-owned policy, never supplied by a peer. Only
	// a new ordered heartbeat may refresh the source lease by this duration.
	LeaseDuration time.Duration
}

// BGPRoutingPeer retains the complete parsed Peer Up metadata. It is untrusted
// protocol information; BGPRoutingSource supplies independent current authority.
type BGPRoutingPeer struct {
	SourceFormat               string `json:",omitempty"` // current operator-selected serializer, never supplied by BMP
	CollectorObservedUnixNanos int64  `json:",omitempty"` // exact retry clock, beyond Postgres microsecond precision
	OpenFrameDigest            []byte `json:",omitempty"` // complete original Peer Up, for exact retry identity
	Type, Flags                uint8
	Distinguisher              [8]byte
	Address                    netip.Addr
	ASN                        uint32
	BGPIdentifier              netip.Addr
	LocalAddress               netip.Addr
	LocalPort, RemotePort      uint16
	SentOpen, ReceivedOpen     []byte
	Information                []BGPRoutingPeerInformation
}

type BGPRoutingPeerInformation struct {
	Type  uint16
	Value []byte
}

type BGPRoutingViewDefinition struct {
	Kind     string
	AFI      uint16
	SAFI     uint8
	Filtered bool
	Peer     BGPRoutingPeer
	Public   *BGPPublicRoutingPeer `json:"public,omitempty"`
}

// BGPRoutingView is a staging generation, not a published route or a live grant.
// Birth observation is retained across heartbeat refreshes so rebinds cannot
// make old rows current merely by advancing their observation timestamp.
type BGPRoutingView struct {
	BGPRoutingSource
	ID, Generation string
	Definition     BGPRoutingViewDefinition
	PeerKey        [32]byte
	ValidUntil     time.Time
}

func routingViewMetadata(ctx context.Context, definition BGPRoutingViewDefinition, budget BGPRoutingBudget) ([]byte, [32]byte, error) {
	if definition.Kind == "public_bgp" {
		return publicRoutingViewMetadata(ctx, definition, budget)
	}
	var key [32]byte
	if err := ctx.Err(); err != nil {
		return nil, key, err
	}
	if definition.Public != nil {
		return nil, key, ErrBGPRoutingView
	}
	if budget.MemoryBytes <= 1024 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return nil, key, ErrBGPRoutingBudget
	}
	peer := definition.Peer
	if len(peer.OpenFrameDigest) != 0 && len(peer.OpenFrameDigest) != 32 {
		return nil, key, ErrBGPRoutingView
	}
	if (definition.AFI != 1 && definition.AFI != 2) || definition.SAFI != 1 || peer.Type > 3 ||
		!peer.BGPIdentifier.Is4() || len(peer.SentOpen) == 0 || len(peer.ReceivedOpen) == 0 {
		return nil, key, ErrBGPRoutingView
	}
	switch definition.Kind {
	case "loc_rib":
		if peer.Type != 3 || peer.Address.IsValid() || peer.LocalAddress.IsValid() || peer.LocalPort != 0 || peer.RemotePort != 0 {
			return nil, key, ErrBGPRoutingView
		}
	case "adj_rib_in_pre_policy", "adj_rib_in_post_policy", "adj_rib_out_pre_policy", "adj_rib_out_post_policy":
		if peer.Type == 3 || !peer.Address.IsValid() || peer.Address.Zone() != "" || definition.Filtered {
			return nil, key, ErrBGPRoutingView
		}
	default:
		return nil, key, ErrBGPRoutingView
	}
	memory, work := budget.MemoryBytes-1024, budget.WorkUnits
	charge := func(size, overhead int64) bool {
		if memory < overhead || size > (memory-overhead)/8 || work < 64 || size > (work-64)/4 {
			return false
		}
		memory -= overhead + size*8
		work -= 64 + size*4
		return true
	}
	if !charge(int64(len(peer.SentOpen)), 0) || !charge(int64(len(peer.ReceivedOpen)), 0) {
		return nil, key, ErrBGPRoutingBudget
	}
	for _, info := range peer.Information {
		if err := ctx.Err(); err != nil {
			return nil, key, err
		}
		if !charge(int64(len(info.Value)), 256) {
			return nil, key, ErrBGPRoutingBudget
		}
	}
	// Peer ASN/router-id/OPEN changes restart the same logical peer slot.
	// Keep address families distinct even for IPv4-mapped IPv6 addresses.
	identity := make([]byte, 26)
	identity[0] = peer.Type
	copy(identity[1:9], peer.Distinguisher[:])
	if peer.Address.IsValid() {
		identity[9] = 6
		if peer.Address.Is4() {
			identity[9] = 4
		}
		address := peer.Address.As16()
		copy(identity[10:], address[:])
	}
	body, err := json.Marshal(peer)
	if err != nil {
		return nil, key, err
	}
	if int64(len(body)) > budget.MemoryBytes/2 {
		return nil, key, ErrBGPRoutingBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, key, err
	}
	digest := crypto.Hash(identity)
	if len(digest) != len(key) {
		return nil, key, ErrBGPRoutingView
	}
	copy(key[:], digest)
	return body, key, nil
}

// beginViewInScope requires the caller's fenced write transaction. The old slot
// and new staging generation change atomically; callers must return every error
// from their transaction callback. Nothing here publishes incomplete routes.
func (store BGPRouting) beginViewInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource,
	definition BGPRoutingViewDefinition, validUntil time.Time, budget BGPRoutingBudget) (BGPRoutingView, error) {
	none := BGPRoutingView{}
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return none, err
	}
	if definition.Kind == "public_bgp" || definition.Public != nil {
		return none, ErrBGPRoutingView
	}
	if budget.MemoryBytes <= 1024 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return none, ErrBGPRoutingBudget
	}
	operation := budget
	for _, value := range []string{source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial} {
		if operation.MemoryBytes <= 0 || operation.WorkUnits <= 0 || int64(len(value)) > operation.MemoryBytes/4 || int64(len(value)) > operation.WorkUnits/2 {
			return none, ErrBGPRoutingBudget
		}
		operation.MemoryBytes -= int64(len(value)) * 4
		operation.WorkUnits -= int64(len(value)) * 2
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	authority, err := store.sourceAuthorityForWriteInScope(ctx, sc, source)
	if err != nil {
		return none, err
	}
	body, key, err := routingViewMetadata(ctx, definition, operation)
	if err != nil {
		return none, err
	}
	storedKind, err := routingStoredViewKind(source, definition)
	if err != nil {
		return none, err
	}
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return none, err
	}
	if authority.ValidUntil.Before(validUntil) {
		validUntil = authority.ValidUntil
	}
	if !validUntil.After(authority.AsOf) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	var metadataBytes int64
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return none, err
	}
	if err := sc.Q.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)::bigint+COALESCE(octet_length($2::jsonb::text),0)+256`, string(body), selection).Scan(&metadataBytes); err != nil {
		return none, err
	}
	for _, value := range []string{source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial} {
		if int64(len(value)) > budget.StateBytes-metadataBytes {
			return none, ErrBGPRoutingBudget
		}
		metadataBytes += int64(len(value))
	}
	if used < 0 || metadataBytes > budget.StateBytes || used > budget.StateBytes-metadataBytes {
		return none, ErrBGPRoutingBudget
	}
	id, err := newRegistryID()
	if err != nil {
		return none, err
	}
	generation, err := newRegistryID()
	if err != nil {
		return none, err
	}
	epoch, bindingID := routingSourceSlot(source)
	_, err = sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=transaction_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4
 AND source_kind='router_bmp' AND source_ref=$5 AND view_kind=$6 AND afi=$7 AND safi=$8
 AND (view_kind='loc_rib' OR peer_key=$9) AND state IN ('staging','current')
 AND ((routing_selection IS NULL AND $10::text IS NULL)
      OR (routing_selection->>'epoch'=$10 AND routing_selection->>'binding_id'=$11))`,
		source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef,
		storedKind, definition.AFI, definition.SAFI, key[:], epoch, bindingID)
	if err != nil {
		return none, err
	}
	err = sc.Q.QueryRow(ctx, `INSERT INTO bgp_routing_views
 (tenant_id,context_id,id,generation,source_kind,router_id,collector_agent_id,source_ref,binding_kind,
 sender_serial,origin_serial,view_kind,peer_key,peer_identity,afi,safi,filtered,state,charged_bytes,observed_at,valid_until,
 last_message_observed_at,message_clock_sequence,routing_selection)
 VALUES($1,$2,$3,$4,'router_bmp',$5,$6,$7,'bmp_peer',$8,$9,$10,$11,$12::jsonb,$13,$14,$15,'staging',$16,$17,$18,$17,0,$19::jsonb)
 RETURNING id::text,generation::text`, source.TenantID, source.ContextID, id, generation, source.RouterID,
		source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, storedKind, key[:], string(body),
		definition.AFI, definition.SAFI, definition.Filtered, metadataBytes, source.ObservedAt, validUntil, selection).Scan(&id, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, ErrBGPRoutingView
	}
	if err != nil {
		return none, err
	}
	// The persisted body owns all byte slices; do not return caller-owned OPENs
	// or information values as the supposedly immutable generation definition.
	definition.Peer = cloneBGPRoutingPeer(definition.Peer)
	return BGPRoutingView{BGPRoutingSource: source, ID: id, Generation: generation, Definition: definition, PeerKey: key, ValidUntil: validUntil}, nil
}

func lockBGPRoutingState(ctx context.Context, sc tenancy.Scope) error {
	if sc.Q == nil {
		return ErrBGPRoutingSourceUnavailable
	}
	var isolation string
	if err := sc.Q.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
		return err
	}
	// The next quota statement must see all commits by an earlier lock holder.
	// A REPEATABLE READ snapshot taken before waiting could over-admit two
	// different sources even though their advisory locks serialize perfectly.
	if isolation != "read committed" {
		return ErrBGPRoutingWriteSnapshot
	}
	_, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('bgp-routing-state:' || $1::text,0))`, sc.Tenant.String())
	return err
}

func cloneBGPRoutingPeer(peer BGPRoutingPeer) BGPRoutingPeer {
	peer.SentOpen, peer.ReceivedOpen = bytes.Clone(peer.SentOpen), bytes.Clone(peer.ReceivedOpen)
	peer.OpenFrameDigest = bytes.Clone(peer.OpenFrameDigest)
	peer.Information = slices.Clone(peer.Information)
	for index := range peer.Information {
		peer.Information[index].Value = bytes.Clone(peer.Information[index].Value)
	}
	return peer
}
