// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrSubscriberAssignmentUnavailable = errors.New("current subscriber prefix assignment is unavailable")

type SubscriberAssignmentBounds struct {
	Revision    int64
	StableSince time.Time
	UsesRules   bool
}

// Scope must already carry the exact source contexts authorized for the
// captured flow view. The tenant predicate and RLS also cover every join.
func SubscriberAssignmentInScope(ctx context.Context, sc tenancy.Scope, contexts []string, tagID, key, value string) (SubscriberAssignmentBounds, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || len(contexts) == 0 {
		return SubscriberAssignmentBounds{}, ErrSubscriberAssignmentUnavailable
	}
	var result SubscriberAssignmentBounds
	err := sc.Q.QueryRow(ctx, `
 SELECT r.revision, GREATEST(r.changed_at,
     (SELECT max(e.updated_at) FROM entities e WHERE e.tenant_id=$1 AND e.context_id=ANY($2::uuid[]) AND e.kind='prefix'),
     (SELECT max(x.assigned_at) FROM entity_source_contexts x WHERE x.tenant_id=$1 AND x.context_id=ANY($2::uuid[]) AND x.source_kind='flow_exporter')),
     EXISTS (SELECT 1 FROM tenant_tag_rules q WHERE q.tenant_id=$1 AND q.context_id=ANY($2::uuid[]) AND q.tag_id=$3 AND q.target_kind='prefix')
 FROM tenant_tag_revisions r JOIN tenant_tag_definitions d ON d.tenant_id=r.tenant_id AND d.id=$3 AND d.key=$4
 WHERE r.tenant_id=$1 AND EXISTS (
     SELECT 1 FROM tenant_tag_assignments a JOIN entities e
     ON e.tenant_id=a.tenant_id AND e.context_id=a.context_id AND e.id=a.entity_id AND e.kind='prefix'
     WHERE a.tenant_id=$1 AND a.context_id=ANY($2::uuid[]) AND a.tag_id=$3 AND a.target_kind='prefix'
     AND a.value=$5 AND e.network_prefix IS NOT NULL)`, sc.Tenant.String(), contexts, tagID, key, value).Scan(&result.Revision, &result.StableSince, &result.UsesRules)
	if errors.Is(err, pgx.ErrNoRows) {
		return SubscriberAssignmentBounds{}, ErrSubscriberAssignmentUnavailable
	}
	return result, err
}
