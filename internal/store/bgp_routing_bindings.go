// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errRoutingBindingConflict = errors.New("current routing assignment epoch changed")

// Private configuration DTOs: no ingest frame can write these. The operator
// adapter must authorize every target context before this tenant-scoped writer.
// IDs and epoch are server-generated incarnation identifiers, never grants.
type routingSourceBinding struct {
	ID            string   `json:"id"`
	ContextID     string   `json:"context_id"`
	RouterID      string   `json:"router_id"`
	Distinguisher string   `json:"distinguisher"`
	BGPIdentifier string   `json:"bgp_identifier"`
	Families      []uint16 `json:"families"`
	SourceFormat  string   `json:"source_format,omitempty"`
}

type routingSourceManifest struct {
	AssignedAt time.Time              `json:"assigned_at"`
	Epoch      string                 `json:"epoch"`
	Bindings   []routingSourceBinding `json:"bindings"`
}

// putRoutingBindings is an expansion-only storage component. Production ingest
// continues to refuse unbound views until the complete operator/receiver/lookup
// adapters are wired. Caller owns the fenced tenant transaction and its audit.
func putRoutingBindings(ctx context.Context, sc tenancy.Scope, collector, origin, baseContext, ifMatch string, bindings []routingSourceBinding, budget BGPRoutingBudget) (routingSourceManifest, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return routingSourceManifest{}, entity.ErrScopeMismatch
	}
	key := entity.SourceKey{AgentID: collector, Kind: entity.BMPPeer, SourceRef: origin}
	normalized, err := key.Normalize()
	if err != nil || normalized != key {
		return routingSourceManifest{}, entity.ErrInvalidClaim
	}
	if id, err := validRegistryUUID(baseContext); err != nil || id != baseContext {
		return routingSourceManifest{}, entity.ErrInvalidScope
	}
	prepared, err := prepareRoutingBindings(ctx, bindings, budget)
	if err != nil {
		return routingSourceManifest{}, err
	}
	if sc.Q == nil {
		return routingSourceManifest{}, ErrBGPRoutingSourceUnavailable
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return routingSourceManifest{}, err
	}
	var current *string
	var previousBytes int64
	err = sc.Q.QueryRow(ctx, `SELECT source.routing_epoch::text,(COALESCE(octet_length(source.routing_bindings::text),0)+CASE WHEN source.routing_epoch IS NULL THEN 0 ELSE 128 END)::bigint
 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
 WHERE source.tenant_id=$1 AND source.agent_id=$2 AND source.source_kind='bmp_peer' AND source.source_ref=$3
 AND source.context_id=$4 AND source.anchor_entity_id IS NOT NULL
 AND source.assigned_at<=clock_timestamp() AND assignment.assigned_at<=clock_timestamp()
 AND (source.expires_at IS NULL OR source.expires_at>clock_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=source.tenant_id AND revoked.agent_id=source.agent_id AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
 FOR UPDATE OF source,assignment`,
		tenant.String(), collector, origin, baseContext).Scan(&current, &previousBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingSourceManifest{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return routingSourceManifest{}, err
	}
	if current == nil && ifMatch != "" || current != nil && *current != ifMatch {
		return routingSourceManifest{}, errRoutingBindingConflict
	}
	for _, binding := range prepared {
		var kind string
		err := sc.Q.QueryRow(ctx, `SELECT router.kind FROM entities router JOIN entity_contexts target ON (target.tenant_id,target.id)=(router.tenant_id,router.context_id)
 WHERE router.tenant_id=$1 AND router.context_id=$2 AND router.id=$3 AND router.kind='device' FOR SHARE OF router,target`, tenant.String(), binding.ContextID, binding.RouterID).Scan(&kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return routingSourceManifest{}, entity.ErrScopeMismatch
		}
		if err != nil {
			return routingSourceManifest{}, err
		}
	}
	epoch, err := crypto.UUIDv4()
	if err != nil {
		return routingSourceManifest{}, err
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		return routingSourceManifest{}, err
	}
	var nextBytes int64
	if err := sc.Q.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)::bigint+128`, string(body)).Scan(&nextBytes); err != nil {
		return routingSourceManifest{}, err
	}
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return routingSourceManifest{}, err
	}
	if previousBytes > used || nextBytes > budget.StateBytes || used-previousBytes > budget.StateBytes-nextBytes {
		return routingSourceManifest{}, ErrBGPRoutingBudget
	}
	var assignedAt time.Time
	err = sc.Q.QueryRow(ctx, `UPDATE entity_source_contexts SET routing_epoch=$5,routing_bindings=$6::jsonb,routing_assigned_at=clock_timestamp()
 WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='bmp_peer' AND source_ref=$3 AND context_id=$4 RETURNING routing_assigned_at`,
		tenant.String(), collector, origin, baseContext, epoch, string(body)).Scan(&assignedAt)
	if err != nil {
		return routingSourceManifest{}, err
	}
	// A new configuration must also exclude former complete rows from older
	// readers that predate explicit selector epochs. Caller commits the source
	// manifest, invalidation and audit together, or rolls the whole write back.
	if _, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET state='invalid',updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND source_kind IN ('router_bmp','router_bmp_bound')`, tenant.String(), collector, origin); err != nil {
		return routingSourceManifest{}, err
	}
	return routingSourceManifest{Epoch: epoch, Bindings: prepared, AssignedAt: assignedAt}, nil
}

func prepareRoutingBindings(ctx context.Context, bindings []routingSourceBinding, budget BGPRoutingBudget) ([]routingSourceBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := routingBatchCharge(&budget, 4096, 512); err != nil {
		return nil, err
	}
	if err := routingBatchPopulationCharge(&budget, len(bindings), 2048, 512); err != nil {
		return nil, err
	}
	prepared := make([]routingSourceBinding, 0, len(bindings))
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := normalizeRoutingBinding(&binding); err != nil {
			return nil, err
		}
		key := binding.Distinguisher + "/" + binding.BGPIdentifier
		if seen[key] {
			return nil, entity.ErrInvalidClaim
		}
		seen[key] = true
		id, err := crypto.UUIDv4()
		if err != nil {
			return nil, err
		}
		binding.ID = id
		prepared = append(prepared, binding)
	}
	sort.Slice(prepared, func(i, j int) bool {
		if prepared[i].Distinguisher != prepared[j].Distinguisher {
			return prepared[i].Distinguisher < prepared[j].Distinguisher
		}
		return prepared[i].BGPIdentifier < prepared[j].BGPIdentifier
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return prepared, nil
}

func normalizeRoutingBinding(binding *routingSourceBinding) error {
	for _, id := range []string{binding.ContextID, binding.RouterID} {
		if normalized, err := validRegistryUUID(id); err != nil || normalized != id {
			return entity.ErrInvalidScope
		}
	}
	if len(binding.Distinguisher) != 16 {
		return entity.ErrInvalidClaim
	}
	rd, err := hex.DecodeString(binding.Distinguisher)
	if err != nil || len(rd) != 8 {
		return entity.ErrInvalidClaim
	}
	binding.Distinguisher = hex.EncodeToString(rd)
	id, err := netip.ParseAddr(binding.BGPIdentifier)
	if err != nil || !id.Is4() || id.String() != binding.BGPIdentifier {
		return entity.ErrInvalidClaim
	}
	var seen [3]bool
	if len(binding.Families) == 0 {
		return entity.ErrInvalidClaim
	}
	for _, afi := range binding.Families {
		if afi < 1 || afi > 2 || seen[afi] {
			return entity.ErrInvalidClaim
		}
		seen[afi] = true
	}
	binding.Families = append([]uint16(nil), binding.Families...)
	sort.Slice(binding.Families, func(i, j int) bool { return binding.Families[i] < binding.Families[j] })
	return nil
}

func routingStateBytesInScope(ctx context.Context, sc tenancy.Scope) (int64, error) {
	var used int64
	err := sc.Q.QueryRow(ctx, `SELECT
 COALESCE((SELECT sum(charged_bytes) FROM bgp_routing_views WHERE tenant_id=$1),0)::bigint
 + COALESCE((SELECT sum(CASE WHEN routing_epoch IS NULL THEN 0 ELSE octet_length(routing_bindings::text)+128 END) FROM entity_source_contexts WHERE tenant_id=$1),0)::bigint`, sc.Tenant.String()).Scan(&used)
	return used, err
}
