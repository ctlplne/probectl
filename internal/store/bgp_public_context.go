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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPPublicContextLookup is complete public visibility for the operator's
// active assigned source cohort. Sources retains every contributor, including
// a proved prefix absence or less-specific observation. Paths contains all
// paths at the cohort's most-specific prefix, never a router-selection claim.
type BGPPublicContextLookup struct {
	Scope            entity.Scope
	Sources          []BGPPublicRoutingLookup
	Prefix           netip.Prefix
	Paths            []BGPPublicRoutingPath
	AsOf, ValidUntil time.Time
}

type publicContextSource struct {
	collector, reference, snapshot, serial string
}

const publicContextSourcesSQL = ` FROM entity_source_contexts source
 LEFT JOIN bgp_public_snapshots header ON header.tenant_id=source.tenant_id
 AND header.context_id=source.context_id AND header.collector_agent_id=source.agent_id
 AND header.source_ref=source.source_ref AND header.state='current' AND header.completed_at IS NOT NULL
 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.source_kind='public_bgp'
 AND (source.expires_at IS NULL OR source.expires_at>transaction_timestamp())`

// LookupPublicContextInScope selects only current operator-assigned sources in
// this tenant/context and validates their whole manifests and authority in one
// repeatable snapshot. Any missing, ambiguous, corrupt, unadmitted or expired
// member refuses the whole result. This ingestion seam grants no user access.
func (store BGPRouting) LookupPublicContextInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, address netip.Addr, profile BGPRoutingBudget, maxAge time.Duration) (BGPPublicContextLookup, error) {
	if err := routingConfigurationScope(ctx, sc); err != nil {
		return BGPPublicContextLookup{}, err
	}
	if scope.TenantID != sc.Tenant.String() {
		return BGPPublicContextLookup{}, entity.ErrScopeMismatch
	}
	if normalized, err := scope.Normalize(); err != nil || normalized != scope || !address.IsValid() || address.Zone() != "" || maxAge <= 0 {
		return BGPPublicContextLookup{}, ErrBGPRoutingView
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return BGPPublicContextLookup{}, err
	}
	refs, remaining, err := readPublicContextSources(ctx, sc, scope, profile)
	if err != nil {
		return BGPPublicContextLookup{}, err
	}
	// Divide one admitted operation among the complete cohort. A member may
	// not obtain a fresh full allowance while prior results remain retained.
	part := remaining
	part.MemoryBytes /= int64(len(refs))
	part.WorkUnits /= int64(len(refs))
	out := BGPPublicContextLookup{Scope: scope, Sources: make([]BGPPublicRoutingLookup, 0, len(refs))}
	for _, ref := range refs {
		source := BGPPublicRoutingSource{Scope: scope, CollectorAgentID: ref.collector, SenderSerial: ref.serial, SourceRef: ref.reference, ObservedAt: time.Now()}
		got, err := store.LookupPublicSnapshotInScope(ctx, sc, source, ref.snapshot, address, part, maxAge)
		if err != nil && !errors.Is(err, ErrBGPRoutingRouteMissing) {
			return BGPPublicContextLookup{}, err
		}
		if got.Source.Scope != scope || got.SnapshotID != ref.snapshot || got.AsOf.IsZero() || !got.ValidUntil.After(got.AsOf) {
			return BGPPublicContextLookup{}, ErrBGPRoutingSourceUnavailable
		}
		out.Sources = append(out.Sources, got)
		if got.AsOf.After(out.AsOf) {
			out.AsOf = got.AsOf
		}
		if out.ValidUntil.IsZero() || got.ValidUntil.Before(out.ValidUntil) {
			out.ValidUntil = got.ValidUntil
		}
		if got.Prefix.IsValid() && (!out.Prefix.IsValid() || got.Prefix.Bits() > out.Prefix.Bits()) {
			out.Prefix, out.Paths = got.Prefix, nil
		}
		if got.Prefix.IsValid() && got.Prefix == out.Prefix {
			out.Paths = append(out.Paths, got.Paths...)
		}
	}
	var finished time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&finished); err != nil {
		return BGPPublicContextLookup{}, err
	}
	if !out.ValidUntil.After(finished) {
		return BGPPublicContextLookup{}, ErrBGPRoutingSourceUnavailable
	}
	if !out.Prefix.IsValid() {
		return out, ErrBGPRoutingRouteMissing
	}
	return out, nil
}

func readPublicContextSources(ctx context.Context, sc tenancy.Scope, scope entity.Scope, budget BGPRoutingBudget) ([]publicContextSource, BGPRoutingBudget, error) {
	var count, encoded int64
	err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(source.agent_id)+octet_length(source.source_ref)+COALESCE(octet_length(header.sender_serial),0)+128),0)::bigint`+publicContextSourcesSQL, scope.TenantID, scope.ContextID).Scan(&count, &encoded)
	if err != nil {
		return nil, budget, err
	}
	if count == 0 {
		return nil, budget, ErrBGPRoutingSourceUnavailable
	}
	if count < 0 || encoded < 0 || count > budget.MemoryBytes/1024 || count > budget.WorkUnits/2048 || encoded > budget.MemoryBytes/64 || encoded > budget.WorkUnits/16 {
		return nil, budget, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(&budget, count*512+encoded*32, count*1024+encoded*8); err != nil {
		return nil, budget, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT source.agent_id,source.source_ref,COALESCE(header.id::text,''),COALESCE(header.sender_serial,'')`+publicContextSourcesSQL+` ORDER BY source.agent_id,source.source_ref,header.id`, scope.TenantID, scope.ContextID)
	if err != nil {
		return nil, budget, err
	}
	defer rows.Close()
	refs := make([]publicContextSource, 0, int(count))
	seen := make(map[[2]string]bool, int(count))
	for rows.Next() {
		var ref publicContextSource
		if err := rows.Scan(&ref.collector, &ref.reference, &ref.snapshot, &ref.serial); err != nil {
			return nil, budget, err
		}
		key := [2]string{ref.collector, ref.reference}
		if seen[key] || ref.snapshot == "" || ref.serial == "" || int64(len(refs)) >= count {
			return nil, budget, ErrBGPRoutingSourceUnavailable
		}
		seen[key] = true
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, budget, err
	}
	if int64(len(refs)) != count {
		return nil, budget, ErrBGPRoutingSourceUnavailable
	}
	return refs, budget, nil
}
