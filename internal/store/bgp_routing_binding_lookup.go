// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingSourceConfiguration struct {
	TenantID, CollectorID, OriginID string
	BaseContextID, BaseRouterID     string
	Manifest                        *routingSourceManifest
}

type routingSourceSelection struct {
	BaseContextID, BaseRouterID string
	ContextID, RouterID         string
	Epoch, BindingID            string
	AssignedAt                  time.Time
	Families                    []uint16
	Binding                     routingSourceBinding
}

// Configuration reads grant no route access. The operator adapter authorizes
// every current and replacement context before an epoch-conditional write.
// Ingest must additionally prove exact current sender/origin credentials,
// assignment/binding birth and its generation after resolving this selector.
func loadRoutingSourceConfiguration(ctx context.Context, sc tenancy.Scope, collector, origin string, budget BGPRoutingBudget) (routingSourceConfiguration, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return routingSourceConfiguration{}, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return routingSourceConfiguration{}, err
	}
	key := entity.SourceKey{AgentID: collector, Kind: entity.BMPPeer, SourceRef: origin}
	if normalized, err := key.Normalize(); err != nil || normalized != key {
		return routingSourceConfiguration{}, entity.ErrInvalidClaim
	}
	if err := routingBatchCharge(&budget, 4096, 512); err != nil {
		return routingSourceConfiguration{}, err
	}
	if sc.Q == nil {
		return routingSourceConfiguration{}, ErrBGPRoutingSourceUnavailable
	}
	out := routingSourceConfiguration{TenantID: tenant.String(), CollectorID: collector, OriginID: origin}
	var epoch *string
	var assigned *time.Time
	var raw []byte
	var baseAssigned, agentAssigned, asOf time.Time
	err := sc.Q.QueryRow(ctx, `SELECT source.context_id::text,source.anchor_entity_id::text,source.routing_epoch::text,
 source.routing_assigned_at,CASE WHEN octet_length(source.routing_bindings::text)<=$4 THEN source.routing_bindings ELSE NULL END,
 source.assigned_at,assignment.assigned_at,clock_timestamp()
 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
 JOIN entities router ON (router.tenant_id,router.context_id,router.id)=(source.tenant_id,source.context_id,source.anchor_entity_id) AND router.kind='device'
 WHERE source.tenant_id=$1 AND source.agent_id=$2 AND source.source_kind='bmp_peer' AND source.source_ref=$3
 AND source.assigned_at<=clock_timestamp() AND assignment.assigned_at<=clock_timestamp()
 AND (source.expires_at IS NULL OR source.expires_at>clock_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())`,
		tenant.String(), collector, origin, budget.MemoryBytes/128).
		Scan(&out.BaseContextID, &out.BaseRouterID, &epoch, &assigned, &raw, &baseAssigned, &agentAssigned, &asOf)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingSourceConfiguration{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return routingSourceConfiguration{}, err
	}
	if epoch == nil {
		if assigned != nil || raw != nil {
			return routingSourceConfiguration{}, ErrBGPRoutingView
		}
		return out, nil
	}
	if assigned == nil || assigned.Before(baseAssigned) || assigned.Before(agentAssigned) || assigned.After(asOf) {
		return routingSourceConfiguration{}, ErrBGPRoutingSourceUnavailable
	}
	bindings, err := decodeRoutingBindings(ctx, raw, budget)
	if err != nil {
		return routingSourceConfiguration{}, err
	}
	if id, err := validRegistryUUID(*epoch); err != nil || id != *epoch {
		return routingSourceConfiguration{}, ErrBGPRoutingView
	}
	out.Manifest = &routingSourceManifest{Epoch: *epoch, AssignedAt: *assigned, Bindings: bindings}
	return out, nil
}

func decodeRoutingBindings(ctx context.Context, raw []byte, budget BGPRoutingBudget) ([]routingSourceBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 || routingBatchPopulationCharge(&budget, len(raw), 128, 16) != nil {
		return nil, ErrBGPRoutingBudget
	}
	var bindings []routingSourceBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bindings); err != nil || bindings == nil {
		return nil, ErrBGPRoutingView
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrBGPRoutingView
	}
	seen, ids := map[string]bool{}, map[string]bool{}
	for i := range bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before := bindings[i]
		if id, err := validRegistryUUID(before.ID); err != nil || id != before.ID || ids[id] {
			return nil, ErrBGPRoutingView
		}
		if err := normalizeRoutingBinding(&bindings[i]); err != nil || !reflect.DeepEqual(before, bindings[i]) {
			return nil, ErrBGPRoutingView
		}
		key := before.Distinguisher + "/" + before.BGPIdentifier
		if seen[key] {
			return nil, ErrBGPRoutingView
		}
		seen[key], ids[before.ID] = true, true
	}
	return bindings, nil
}

func selectRoutingSource(ctx context.Context, sc tenancy.Scope, config routingSourceConfiguration, peer BGPRoutingPeer, families []uint16) (routingSourceSelection, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return routingSourceSelection{}, entity.ErrScopeMismatch
	}
	if config.TenantID != tenant.String() {
		return routingSourceSelection{}, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return routingSourceSelection{}, err
	}
	if peer.Type != 3 || !peer.BGPIdentifier.Is4() || len(families) == 0 || len(families) > 2 {
		return routingSourceSelection{}, ErrBGPRoutingView
	}
	var seen [3]bool
	for _, afi := range families {
		if afi < 1 || afi > 2 || seen[afi] {
			return routingSourceSelection{}, ErrBGPRoutingView
		}
		seen[afi] = true
	}
	out := routingSourceSelection{BaseContextID: config.BaseContextID, BaseRouterID: config.BaseRouterID, Families: append([]uint16(nil), families...)}
	if config.Manifest == nil {
		if peer.Distinguisher != ([8]byte{}) {
			return routingSourceSelection{}, errBGPRoutingContextBinding
		}
		out.ContextID, out.RouterID = config.BaseContextID, config.BaseRouterID
		return out, nil
	}
	selector := hex.EncodeToString(peer.Distinguisher[:])
	for _, binding := range config.Manifest.Bindings {
		if binding.Distinguisher != selector || binding.BGPIdentifier != peer.BGPIdentifier.String() {
			continue
		}
		for _, afi := range families {
			present := false
			for _, permitted := range binding.Families {
				present = present || afi == permitted
			}
			if !present {
				return routingSourceSelection{}, errBGPRoutingContextBinding
			}
		}
		if sc.Q == nil {
			return routingSourceSelection{}, ErrBGPRoutingSourceUnavailable
		}
		var owned bool
		storedBinding, err := json.Marshal(binding)
		if err != nil {
			return routingSourceSelection{}, err
		}
		permittedFamilies, err := json.Marshal(families)
		if err != nil {
			return routingSourceSelection{}, err
		}
		err = sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entity_source_contexts source
 JOIN entity_agent_contexts assignment ON (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(source.tenant_id,source.agent_id,source.context_id)
 CROSS JOIN LATERAL jsonb_array_elements(source.routing_bindings) binding
 JOIN entities router ON router.tenant_id=source.tenant_id AND router.context_id=$2 AND router.id=$3 AND router.kind='device'
 JOIN entity_contexts target ON (target.tenant_id,target.id)=(router.tenant_id,router.context_id)
 WHERE source.tenant_id=$1 AND source.agent_id=$5 AND source.source_kind='bmp_peer' AND source.source_ref=$6
 AND source.context_id=$7 AND source.anchor_entity_id=$8 AND source.routing_epoch=$9 AND source.routing_assigned_at=$4
 AND source.assigned_at<=$4 AND assignment.assigned_at<=$4
 AND (source.expires_at IS NULL OR source.expires_at>clock_timestamp())
 AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
 AND binding->>'id'=$10 AND binding->>'context_id'=$2::text AND binding->>'router_id'=$3::text
 AND binding->>'distinguisher'=$11 AND binding->>'bgp_identifier'=$12 AND binding->'families' @> $13::jsonb AND binding=$14::jsonb
 AND router.created_at<=$4 AND target.created_at<=$4)`, tenant.String(), binding.ContextID, binding.RouterID, config.Manifest.AssignedAt,
			config.CollectorID, config.OriginID, config.BaseContextID, config.BaseRouterID, config.Manifest.Epoch, binding.ID, selector, peer.BGPIdentifier.String(), string(permittedFamilies), string(storedBinding)).Scan(&owned)
		if err != nil {
			return routingSourceSelection{}, err
		}
		if !owned {
			return routingSourceSelection{}, ErrBGPRoutingSourceUnavailable
		}
		out.ContextID, out.RouterID, out.Epoch, out.BindingID, out.AssignedAt = binding.ContextID, binding.RouterID, config.Manifest.Epoch, binding.ID, config.Manifest.AssignedAt
		out.Binding = binding
		out.Binding.Families = append([]uint16(nil), binding.Families...)
		return out, nil
	}
	return routingSourceSelection{}, errBGPRoutingContextBinding
}
