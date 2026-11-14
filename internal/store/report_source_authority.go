// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ReportSourceKey is a canonical source selector, never disclosure authority.
// Reader permission checks remain the caller's responsibility in this snapshot.
type ReportSourceKey struct {
	ContextID string `json:"context_id"`
	AgentID   string `json:"agent_id"`
	Kind      string `json:"kind"`
	Ref       string `json:"ref"`
}

// ReportSourceBinding retains assignment lineage to recheck, never a grant.
type ReportSourceBinding struct {
	Key                   ReportSourceKey `json:"key"`
	Anchor                *string         `json:"anchor"`
	SourceAssignedAt      time.Time       `json:"source_assigned_at"`
	AgentAssignedAt       time.Time       `json:"agent_assigned_at"`
	RoutingEpoch          *string         `json:"routing_epoch,omitempty"`
	RoutingAssignedAt     *time.Time      `json:"routing_assigned_at,omitempty"`
	RoutingBindingsDigest string          `json:"routing_bindings_digest"`
}

// ReportEvidenceRef selects an exact evidence row inside the current tenant.
type ReportEvidenceRef struct{ ContextID, ID string }

// ReportEvidenceSourceKeysInScope resolves exact already-captured evidence IDs
// to source identities. No payload or expired certificate becomes a read grant.
func (*EntityRegistry) ReportEvidenceSourceKeysInScope(ctx context.Context, sc tenancy.Scope, refs []ReportEvidenceRef, memory int64) ([]ReportSourceKey, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireReportSourceReadScope(ctx, sc); err != nil {
		return nil, err
	}
	if memory < 4096 || int64(len(refs)) > memory/2048 {
		return nil, ErrClientReportBudget
	}
	contexts, ids := []string{}, []string{}
	seen := map[ReportEvidenceRef]bool{}
	for _, ref := range refs {
		for _, id := range []string{ref.ContextID, ref.ID} {
			if _, err := validRegistryUUID(id); err != nil {
				return nil, err
			}
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		contexts, ids = append(contexts, ref.ContextID), append(ids, ref.ID)
	}
	rows, err := sc.Q.Query(ctx, `WITH selected AS (SELECT * FROM unnest($2::uuid[],$3::uuid[]) AS r(context_id,id))
 SELECT e.context_id::text,e.agent_id,e.source_kind,e.configured_ref FROM selected r
 JOIN entity_evidence e ON (e.tenant_id,e.context_id,e.id)=($1,r.context_id,r.id)`, sc.Tenant.String(), contexts, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportSourceKey{}
	for rows.Next() {
		var key ReportSourceKey
		if err := rows.Scan(&key.ContextID, &key.AgentID, &key.Kind, &key.Ref); err != nil {
			return nil, err
		}
		if int64(len(out)+1)*2048 > memory {
			return nil, ErrClientReportBudget
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(seen) {
		return nil, entity.ErrConflictingEvidence
	}
	return out, ctx.Err()
}

// ReportSourceBindingsInScope rechecks current compound assignments and live
// identities at storage. Original observation/certificate expiry is not a new
// expiry on a historical report. Revocation and assignment withdrawal still
// fail closed; renewed credentials confer no new tenant or source ownership.
func (*EntityRegistry) ReportSourceBindingsInScope(ctx context.Context, sc tenancy.Scope, keys []ReportSourceKey, memory int64) ([]ReportSourceBinding, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireReportSourceReadScope(ctx, sc); err != nil {
		return nil, err
	}
	if memory < 8192 || int64(len(keys)) > memory/2048 {
		return nil, ErrClientReportBudget
	}
	contexts, agents, kinds, refs := []string{}, []string{}, []string{}, []string{}
	seen := map[ReportSourceKey]bool{}
	for _, key := range keys {
		if _, err := validRegistryUUID(key.ContextID); err != nil {
			return nil, err
		}
		source, err := (entity.SourceKey{AgentID: key.AgentID, Kind: entity.SourceKind(key.Kind), SourceRef: key.Ref}).Normalize()
		if err != nil || source.AgentID != key.AgentID || string(source.Kind) != key.Kind || source.SourceRef != key.Ref {
			return nil, entity.ErrInvalidSource
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		contexts, agents, kinds, refs = append(contexts, key.ContextID), append(agents, key.AgentID), append(kinds, key.Kind), append(refs, key.Ref)
	}
	rows, err := sc.Q.Query(ctx, `WITH selected AS (
 SELECT * FROM unnest($2::uuid[],$3::text[],$4::text[],$5::text[]) AS r(context_id,agent_id,kind,ref))
 SELECT m.context_id::text,m.agent_id,m.source_kind,m.source_ref,m.anchor_entity_id::text,m.assigned_at,a.assigned_at,m.routing_epoch::text,m.routing_assigned_at,CASE WHEN octet_length(COALESCE(m.routing_bindings::text,''))<=$6 THEN COALESCE(m.routing_bindings::text,'') END
 FROM selected r JOIN entity_source_contexts m ON
 (m.tenant_id,m.context_id,m.agent_id,m.source_kind,m.source_ref)=($1,r.context_id,r.agent_id,r.kind,r.ref)
 JOIN entity_agent_contexts a ON (a.tenant_id,a.context_id,a.agent_id)=(m.tenant_id,m.context_id,m.agent_id)
 WHERE m.tenant_id=$1 AND a.tenant_id=$1
 AND m.assigned_at<=transaction_timestamp() AND a.assigned_at<=transaction_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())
 AND (a.expires_at IS NULL OR a.expires_at>transaction_timestamp())
 AND EXISTS(SELECT 1 FROM agent_identities i WHERE i.tenant_id=$1 AND i.agent_id=m.agent_id
 AND i.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/entity/'||m.agent_id
 AND i.issued_at<=transaction_timestamp() AND i.not_after>transaction_timestamp() AND i.revoked_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=$1 AND revoked.agent_id=m.agent_id
 AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')
 AND (m.source_kind<>'bmp_peer' OR (
 EXISTS(SELECT 1 FROM agent_identities origin WHERE origin.tenant_id=$1 AND origin.agent_id=m.source_ref
 AND origin.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/bmp/'||m.source_ref
 AND origin.issued_at<=transaction_timestamp() AND origin.not_after>transaction_timestamp() AND origin.revoked_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=$1 AND revoked.agent_id=m.source_ref
 AND revoked.spiffe_id='spiffe://probectl/tenant/'||$1::text||'/bmp/'||m.source_ref
 AND revoked.revoked_at IS NOT NULL)))
 ORDER BY m.context_id,m.agent_id,m.source_kind,m.source_ref`, pgx.QueryExecModeDescribeExec, bound.String(), contexts, agents, kinds, refs, memory/16)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportSourceBinding{}
	for rows.Next() {
		var item ReportSourceBinding
		var routing *string
		if err := rows.Scan(&item.Key.ContextID, &item.Key.AgentID, &item.Key.Kind, &item.Key.Ref, &item.Anchor, &item.SourceAssignedAt, &item.AgentAssignedAt, &item.RoutingEpoch, &item.RoutingAssignedAt, &routing); err != nil {
			return nil, err
		}
		if int64(len(out)+1)*2048 > memory {
			return nil, ErrClientReportBudget
		}
		if routing == nil {
			return nil, ErrClientReportBudget
		}
		item.RoutingBindingsDigest = hex.EncodeToString(crypto.Hash([]byte(*routing)))
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(seen) {
		return nil, entity.ErrInvalidSource
	}
	return out, ctx.Err()
}

// ReportBaseSourceKeyInScope retains the independently resolved routing base
// assignment. Its epoch/bindings are rechecked by ReportSourceBindingsInScope;
// a serialized private routing selector is never accepted from a report reader.
func (BGPRouting) ReportBaseSourceKeyInScope(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, budget BGPRoutingBudget) (ReportSourceKey, error) {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return ReportSourceKey{}, err
	}
	config, err := loadRoutingSourceConfiguration(ctx, sc, source.CollectorAgentID, source.SourceRef, budget)
	if err != nil {
		return ReportSourceKey{}, err
	}
	return ReportSourceKey{ContextID: config.BaseContextID, AgentID: source.CollectorAgentID, Kind: "bmp_peer", Ref: source.SourceRef}, nil
}

func requireReportSourceReadScope(ctx context.Context, sc tenancy.Scope) error {
	if err := requireRoutingReadSnapshot(ctx, sc); err == nil {
		return nil
	}
	return requireRoutingCaptureReadSnapshot(context.WithValue(ctx, routingReportPublicationKey{}, sc.Tenant.String()), sc)
}
