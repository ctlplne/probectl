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
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrPrefixImpactSources = errors.New("complete current flow exporter bindings are required for the routing context")

type PrefixImpactFlowBinding struct {
	AgentID  string
	Exporter netip.Addr
	Since    time.Time
}

// PrefixImpactFlowBindingsInScope reads the entire operator-assigned exporter
// population of the authorized routing context. The bindings must have been
// effective throughout the source window and must still be current.
func PrefixImpactFlowBindingsInScope(ctx context.Context, sc tenancy.Scope, contextID string, from time.Time) ([]PrefixImpactFlowBinding, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || from.IsZero() {
		return nil, entity.ErrScopeMismatch
	}
	if _, err := validRegistryUUID(contextID); err != nil {
		return nil, err
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	// Each pair occupies one filter group and two predicates. Refuse a source
	// population that cannot be represented by a complete bounded query.
	const limit = min(flow.MaxQueryGroupEntries, (flow.MaxQueryPredicates-1)/2)
	rows, err := sc.Q.Query(ctx, `SELECT source.agent_id,source.source_ref,
	 GREATEST(source.assigned_at,assignment.assigned_at)
	 FROM entity_source_contexts source
	 JOIN entity_agent_contexts assignment ON
	 (source.tenant_id,source.agent_id,source.context_id)=(assignment.tenant_id,assignment.agent_id,assignment.context_id)
	 WHERE source.tenant_id=$1 AND source.context_id=$2 AND source.source_kind='flow_exporter'
	 AND source.assigned_at<=clock_timestamp() AND (source.expires_at IS NULL OR source.expires_at>clock_timestamp())
	 AND assignment.assigned_at<=clock_timestamp() AND (assignment.expires_at IS NULL OR assignment.expires_at>clock_timestamp())
	 ORDER BY source.agent_id,source.source_ref LIMIT $3`, bound.String(), contextID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrefixImpactFlowBinding
	seen := make(map[PrefixImpactFlowBinding]struct{})
	for rows.Next() {
		if len(out) == limit {
			return nil, ErrPrefixImpactSources
		}
		var item PrefixImpactFlowBinding
		var raw string
		if err := rows.Scan(&item.AgentID, &raw, &item.Since); err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" || item.AgentID == "" || item.Since.IsZero() || item.Since.After(from) {
			return nil, ErrPrefixImpactSources
		}
		item.Exporter = address.Unmap()
		key := PrefixImpactFlowBinding{AgentID: item.AgentID, Exporter: item.Exporter}
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrPrefixImpactSources
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrPrefixImpactSources
	}
	return out, ctx.Err()
}
