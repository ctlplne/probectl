// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ActiveCanonicalOverrideMatches reads the entire requested signal population
// once. It holds the same tenant incident-mutation lock as operator detach and
// reversal, so a publication cannot lose a new exclusion between this read and
// its writes. It grants no source authority and returns no population prefix.
func (Incidents) ActiveCanonicalOverrideMatches(ctx context.Context, sc tenancy.Scope, signals []incident.Signal, maxBytes int64) ([]bool, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if maxBytes < 4096 || int64(len(signals)) > maxBytes/1024 {
		return nil, ErrAlertDependencyBudget
	}
	var planes, kinds, targets, prefixes, contexts, entities []string
	remaining := maxBytes
	for _, signal := range signals {
		if signal.TenantID != tenant.String() || !signal.IdentityLookupAttempted {
			return nil, entity.ErrScopeMismatch
		}
		for _, id := range []string{signal.IdentityContextID, signal.IdentityEntityID} {
			if _, err := validRegistryUUID(id); err != nil {
				return nil, err
			}
		}
		remaining -= int64(1024 + 4*(len(signal.Plane)+len(signal.Kind)+len(signal.Target)+len(signal.Prefix)))
		if remaining < 0 {
			return nil, ErrAlertDependencyBudget
		}
		planes, kinds = append(planes, signal.Plane), append(kinds, signal.Kind)
		targets, prefixes = append(targets, signal.Target), append(prefixes, signal.Prefix)
		contexts, entities = append(contexts, signal.IdentityContextID), append(entities, signal.IdentityEntityID)
	}
	out := make([]bool, len(signals))
	if len(signals) == 0 {
		return out, nil
	}
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, tenant.String()); err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `WITH requested AS (
 SELECT * FROM unnest($2::text[],$3::text[],$4::text[],$5::text[],$6::uuid[],$7::uuid[])
 WITH ORDINALITY AS r(plane,kind,target,prefix,context_id,entity_id,position))
 SELECT r.position, EXISTS(SELECT 1 FROM incident_correlation_overrides o
 WHERE o.tenant_id=$1 AND o.active AND o.identity_lookup_attempted
 AND o.entity_id IS NOT NULL AND o.entity_context_id=r.context_id AND o.entity_id=r.entity_id
 AND o.plane=r.plane AND o.kind=r.kind AND o.target=r.target AND o.prefix=r.prefix)
 FROM requested r ORDER BY r.position`, tenant.String(), planes, kinds, targets, prefixes, contexts, entities)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var position int
		var matched bool
		if err := rows.Scan(&position, &matched); err != nil {
			return nil, err
		}
		if position != count+1 || position > len(out) {
			return nil, entity.ErrScopeMismatch
		}
		out[position-1], count = matched, position
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if count != len(out) {
		return nil, entity.ErrScopeMismatch
	}
	return out, ctx.Err()
}
