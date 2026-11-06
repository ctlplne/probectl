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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errBGPRoutingContextBinding = errors.New("routing view lacks an explicit context binding")

// BGPRoutingPeerUpInput has no tenant/context/router selector. The service
// supplies the live mTLS collector and serial; RLS operator assignments resolve
// canonical ownership. Definitions must come from complete server-side decoding.
type BGPRoutingPeerUpInput struct {
	CollectorAgentID, SenderSerial, SourceRef, OriginSerial, ObservationID string
	ObservedAt                                                             time.Time
	FrameDigest                                                            []byte
	Definitions                                                            []BGPRoutingViewDefinition
}

type BGPRoutingStagedView struct {
	BGPRoutingViewRef
	AFI  uint16
	SAFI uint8
}

type BGPRoutingStageResult struct {
	Status string // staged, replayed, invalidated; none means publication
	Views  []BGPRoutingStagedView
}

// StagePeerInScope is one complete, fenced, read-committed tenant transaction.
// A staged view is private until ordered updates and its exclusive EOR arrive.
// An invalidated refusal must COMMIT before the caller reports it to the sender.
func (store BGPRouting) StagePeerInScope(ctx context.Context, sc tenancy.Scope, input BGPRoutingPeerUpInput, profile BGPRoutingBudget) (BGPRoutingStageResult, error) {
	none := BGPRoutingStageResult{}
	source, err := routingStageSource(ctx, sc, input, profile)
	if err != nil {
		return none, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return none, err
	}
	if _, err := store.sourceAuthorityForWriteInScope(ctx, sc, source); err != nil {
		return none, err
	}
	var latest *time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT max(observed_at) FROM bgp_routing_views
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5 AND source_kind='router_bmp'`, source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef).Scan(&latest); err != nil {
		return none, err
	}
	// An old message cannot retire a newer incarnation, even with still-issued
	// credentials. Exact UUID retries below never renew its lease or birth clock.
	if latest != nil && latest.After(input.ObservedAt) {
		return BGPRoutingStageResult{Status: "invalidated"}, nil
	}
	refs, err := routingStagePlan(ctx, source, input, profile)
	if errors.Is(err, errBGPRoutingContextBinding) {
		return none, err
	}
	if err != nil {
		return invalidateRoutingStageSource(ctx, sc, source)
	}
	replay, exists, err := routingStageReplay(ctx, sc, source, input, refs, profile)
	if err != nil {
		return none, err
	}
	if exists {
		return replay, nil
	}
	if _, err := sc.Q.Exec(ctx, "SAVEPOINT routing_peer_up_stage"); err != nil {
		return none, err
	}
	if err := store.persistRoutingStage(ctx, sc, source, input, refs, profile); err != nil {
		if _, rollbackErr := sc.Q.Exec(ctx, "ROLLBACK TO SAVEPOINT routing_peer_up_stage"); rollbackErr != nil {
			return none, rollbackErr
		}
		return invalidateRoutingStageSource(ctx, sc, source)
	}
	if _, err := sc.Q.Exec(ctx, "RELEASE SAVEPOINT routing_peer_up_stage"); err != nil {
		return none, err
	}
	return BGPRoutingStageResult{Status: "staged", Views: refs}, nil
}

func (store BGPRouting) persistRoutingStage(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, input BGPRoutingPeerUpInput, refs []BGPRoutingStagedView, profile BGPRoutingBudget) error {
	// A complete Peer Up replaces the entire source incarnation. A family
	// omitted from the new OPEN must not survive from the previous generation.
	// The caller's savepoint keeps retirement atomic with every new family.
	if _, err := invalidateRoutingStageSource(ctx, sc, source); err != nil {
		return err
	}
	for i, definition := range input.Definitions {
		definition.Peer.OpenFrameDigest = append([]byte(nil), input.FrameDigest...)
		definition.Peer.CollectorObservedUnixNanos = input.ObservedAt.UnixNano()
		view, err := store.beginViewInScope(ctx, sc, source, definition, input.ObservedAt.Add(profile.LeaseDuration), profile)
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET id=$5,generation=$6 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, view.ID, view.Generation, refs[i].ID, refs[i].Generation); err != nil {
			return err
		}
	}
	return store.checkRoutingWriteLease(ctx, sc, source, input.ObservedAt.Add(profile.LeaseDuration))
}

func routingStageSource(ctx context.Context, sc tenancy.Scope, input BGPRoutingPeerUpInput, profile BGPRoutingBudget) (BGPRoutingSource, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return BGPRoutingSource{}, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return BGPRoutingSource{}, err
	}
	if profile.LeaseDuration <= 0 {
		return BGPRoutingSource{}, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(&profile, 4096, 512); err != nil {
		return BGPRoutingSource{}, err
	}
	for _, value := range []string{input.CollectorAgentID, input.SenderSerial, input.SourceRef, input.OriginSerial, input.ObservationID} {
		if value == "" {
			return BGPRoutingSource{}, entity.ErrInvalidClaim
		}
		if err := routingBatchPopulationCharge(&profile, len(value), 8, 4); err != nil {
			return BGPRoutingSource{}, err
		}
	}
	if sc.Q == nil {
		return BGPRoutingSource{}, ErrBGPRoutingSourceUnavailable
	}
	source := BGPRoutingSource{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, OriginSerial: input.OriginSerial, ObservedAt: input.ObservedAt}
	source.TenantID = tenant.String()
	err := sc.Q.QueryRow(ctx, `SELECT context_id::text,anchor_entity_id::text FROM entity_source_contexts
 WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='bmp_peer' AND source_ref=$3 AND anchor_entity_id IS NOT NULL`, source.TenantID, source.CollectorAgentID, source.SourceRef).Scan(&source.ContextID, &source.RouterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return BGPRoutingSource{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return BGPRoutingSource{}, err
	}
	return source, validateBGPRoutingSource(ctx, sc, source)
}

func routingStagePlan(ctx context.Context, source BGPRoutingSource, input BGPRoutingPeerUpInput, profile BGPRoutingBudget) ([]BGPRoutingStagedView, error) {
	if _, err := validRegistryUUID(input.ObservationID); err != nil {
		return nil, ErrBGPRoutingView
	}
	if len(input.FrameDigest) != 32 || len(input.Definitions) == 0 || len(input.Definitions) > 2 {
		return nil, ErrBGPRoutingView
	}
	var seen [3]bool
	refs := make([]BGPRoutingStagedView, 0, len(input.Definitions))
	for _, definition := range input.Definitions {
		if definition.Kind != "loc_rib" || definition.AFI < 1 || definition.AFI > 2 || definition.SAFI != 1 || seen[definition.AFI] {
			return nil, ErrBGPRoutingView
		}
		if definition.Peer.Distinguisher != ([8]byte{}) {
			return nil, errBGPRoutingContextBinding
		}
		seen[definition.AFI] = true
		definition.Peer.OpenFrameDigest = append([]byte(nil), input.FrameDigest...)
		definition.Peer.CollectorObservedUnixNanos = input.ObservedAt.UnixNano()
		if _, _, err := routingViewMetadata(ctx, definition, profile); err != nil {
			return nil, err
		}
		body, err := json.Marshal([]any{"bmp-peer-up-v1", source.Scope, source.RouterID, source.CollectorAgentID, source.SourceRef, source.SenderSerial, source.OriginSerial, input.ObservationID, definition.AFI, definition.SAFI})
		if err != nil {
			return nil, err
		}
		digest := crypto.Hash(body)
		id, err := uuid.FromBytes(digest[:16])
		if err != nil {
			return nil, err
		}
		refs = append(refs, BGPRoutingStagedView{BGPRoutingViewRef: BGPRoutingViewRef{ID: id.String(), Generation: input.ObservationID}, AFI: definition.AFI, SAFI: definition.SAFI})
	}
	return refs, nil
}

func routingStageReplay(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, input BGPRoutingPeerUpInput, refs []BGPRoutingStagedView, profile BGPRoutingBudget) (BGPRoutingStageResult, bool, error) {
	matched, found := 0, 0
	for i, ref := range refs {
		definition := input.Definitions[i]
		definition.Peer.OpenFrameDigest = append([]byte(nil), input.FrameDigest...)
		definition.Peer.CollectorObservedUnixNanos = input.ObservedAt.UnixNano()
		body, _, err := routingViewMetadata(ctx, definition, profile)
		if err != nil {
			return BGPRoutingStageResult{}, false, err
		}
		var same, current bool
		err = sc.Q.QueryRow(ctx, `SELECT peer_identity=$5::jsonb AND observed_at=$6::timestamptz,
 state IN ('staging','current') AND valid_until>clock_timestamp()
 FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, ref.ID, ref.Generation, string(body), input.ObservedAt).Scan(&same, &current)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return BGPRoutingStageResult{}, false, err
		}
		found++
		if same && current {
			matched++
		}
	}
	if found == 0 {
		return BGPRoutingStageResult{}, false, nil
	}
	if matched == len(refs) {
		return BGPRoutingStageResult{Status: "replayed", Views: refs}, true, nil
	}
	// A retired UUID or altered retry cannot revive its view or retire a newer
	// one. Failed current UUIDs are invalidated by exact generation only.
	for _, ref := range refs {
		if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, ref.ID, ref.Generation); err != nil {
			return BGPRoutingStageResult{}, false, err
		}
	}
	return BGPRoutingStageResult{Status: "invalidated"}, true, nil
}

func invalidateRoutingStageSource(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource) (BGPRoutingStageResult, error) {
	_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4 AND source_ref=$5
 AND source_kind='router_bmp' AND state IN ('staging','current')`, source.TenantID, source.ContextID, source.RouterID, source.CollectorAgentID, source.SourceRef)
	if err != nil {
		return BGPRoutingStageResult{}, err
	}
	return BGPRoutingStageResult{Status: "invalidated"}, nil
}
