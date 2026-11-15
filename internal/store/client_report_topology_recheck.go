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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func validateReportPhysicalRefs(refs []ReportPhysicalLinkRef, memory int64) error {
	if memory < 8192 || int64(len(refs)) > memory/8192 {
		return ErrClientReportBudget
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		for _, id := range []string{ref.ContextID, ref.LinkID, ref.FromEntityID, ref.ToEntityID, ref.EvidenceID, ref.RemoteEvidenceID} {
			if _, err := validRegistryUUID(id); err != nil {
				return err
			}
		}
		digest, err := hex.DecodeString(ref.OriginalsDigest)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != ref.OriginalsDigest || ref.CapturedAt.IsZero() || seen[ref.LinkID] {
			return entity.ErrInvalidClaim
		}
		seen[ref.LinkID] = true
	}
	return nil
}

// Historical adjacency retains the exact independent capture-time support.
// Original certificate expiry and later measurement TTL retirement do not
// rewrite history. Current source/agent assignment, active renewed identity,
// revocation, exact immutable contents and tenant ownership still fail closed.
func (*EntityRegistry) RecheckReportPhysicalLinksInScope(ctx context.Context, sc tenancy.Scope, refs []ReportPhysicalLinkRef, memory int64) error {
	if err := reportPhysicalReadScope(ctx, sc, memory); err != nil {
		return err
	}
	if err := validateReportPhysicalRefs(refs, memory); err != nil {
		return err
	}
	if len(refs) == 0 {
		return ctx.Err()
	}
	predicate, err := reportNeighborHistoricalSQL()
	if err != nil {
		return err
	}
	remote := reportEvidenceAlias.ReplaceAllString(predicate, "remote.")
	query := `WITH requested AS (SELECT * FROM jsonb_to_recordset($2::jsonb) AS r(
 context_id uuid,link_id uuid,from_entity_id uuid,to_entity_id uuid,evidence_id uuid,remote_evidence_id uuid,
 captured_at timestamptz,originals_digest text)) ` + reportPhysicalSelect + `
 FROM requested JOIN entity_links l ON (l.tenant_id,l.context_id,l.id)=($1,requested.context_id,requested.link_id) ` + reportPhysicalLocalJoin + `
 JOIN entity_evidence remote ON (remote.tenant_id,remote.context_id,remote.id)=(e.tenant_id,e.context_id,requested.remote_evidence_id)
 JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(remote.tenant_id,remote.context_id,remote.entity_id)
 WHERE l.from_entity_id=requested.from_entity_id AND l.to_entity_id=requested.to_entity_id AND e.id=requested.evidence_id
 AND ` + reportPhysicalLocalGuard + predicate + ` AND ` + reportPhysicalRemoteGuard + remote + `
 ORDER BY l.context_id,l.id LIMIT $3`
	raw, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	rows, err := sc.Q.Query(ctx, query, pgx.QueryExecModeDescribeExec, sc.Tenant.String(), raw, len(refs)+1, memory/16)
	items, err := scanReportPhysicalLinks(ctx, rows, err, memory)
	if err != nil {
		return err
	}
	if len(items) != len(refs) {
		return entity.ErrConflictingEvidence
	}
	originals := make(map[string]ReportPhysicalLinkRef, len(refs))
	for _, ref := range refs {
		originals[ref.LinkID] = ref
	}
	for _, item := range items {
		ref := originals[item.LinkID]
		if ref.OriginalsDigest != item.OriginalsDigest || !ref.CapturedAt.Equal(item.CapturedAt) {
			return entity.ErrConflictingEvidence
		}
	}
	return ctx.Err()
}
