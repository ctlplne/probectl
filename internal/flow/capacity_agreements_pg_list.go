// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"strconv"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ListCapacityAgreements returns complete current definitions from one tenant
// snapshot. The UUID seek cursor confers no authority and is reapplied only
// inside that tenant's FORCE-RLS lane. Pagination has no total-catalog cap.
func (s *PostgresCapacityAgreements) ListCapacityAgreements(ctx context.Context, actor string, input CapacityAgreementList) (CapacityAgreementPage, error) {
	return s.list(ctx, actor, "", input)
}

// ListCapacityAgreementRevisions walks recording order, including terms whose
// inventory reference has retired. Effective-date lookup remains independent.
func (s *PostgresCapacityAgreements) ListCapacityAgreementRevisions(ctx context.Context, actor, id string, input CapacityAgreementList) (CapacityAgreementPage, error) {
	if !capacityAgreementUUID(id) {
		return CapacityAgreementPage{}, ErrCapacityAgreementInvalid
	}
	return s.list(ctx, actor, id, input)
}

func (s *PostgresCapacityAgreements) list(ctx context.Context, actor, id string, input CapacityAgreementList) (CapacityAgreementPage, error) {
	if _, ok := tenancy.FromContext(ctx); !ok {
		return CapacityAgreementPage{}, tenancy.ErrNoTenant
	}
	if s == nil || s.memoryBytes < 1<<20 || s.workUnits < 4096 {
		return CapacityAgreementPage{}, ErrCapacityAgreementBudget
	}
	if input.Limit == 0 {
		input.Limit = 100
	}
	limit := int64(input.Limit)
	if limit < 1 || limit > (s.memoryBytes-(1<<20))/1024 || limit > (s.workUnits-4096)/4096 {
		return CapacityAgreementPage{}, ErrCapacityAgreementBudget
	}
	var beforeVersion int64
	if input.After != "" {
		if id == "" {
			if !capacityAgreementUUID(input.After) {
				return CapacityAgreementPage{}, ErrCapacityAgreementInvalid
			}
		} else {
			var err error
			beforeVersion, err = capacityAgreementVersion(input.After)
			if err != nil {
				return CapacityAgreementPage{}, ErrCapacityAgreementInvalid
			}
		}
	}
	page := CapacityAgreementPage{Items: []CapacityAgreement{}}
	err := s.inScope(ctx, actor, true, false, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&page.AsOf); err != nil {
			return err
		}
		query := `SELECT a.id::text,a.version,octet_length(r.definition::text)
FROM flow_capacity_agreements a LEFT JOIN flow_capacity_agreement_revisions r
 ON r.tenant_id=a.tenant_id AND r.agreement_id=a.id AND r.version=a.version
WHERE a.tenant_id=$1 AND ($2='' OR a.id>NULLIF($2,'')::uuid) ORDER BY a.id LIMIT $3`
		args := []any{sc.Tenant.String(), input.After, limit + 1}
		if id != "" {
			// Require the header even for an empty revision page, making a
			// missing/foreign agreement indistinguishable from a single get.
			var exists bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_capacity_agreements WHERE tenant_id=$1 AND id=$2)`, sc.Tenant.String(), id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrCapacityAgreementNotFound
			}
			query = `SELECT agreement_id::text,version,octet_length(definition::text)
FROM flow_capacity_agreement_revisions WHERE tenant_id=$1 AND agreement_id=$2
 AND ($3::bigint=0 OR version<$3) ORDER BY version DESC LIMIT $4`
			args = []any{sc.Tenant.String(), id, beforeVersion, limit + 1}
		}
		rows, err := sc.Q.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		type selected struct {
			id      string
			version int64
		}
		var selectedRows []selected
		memory, work := s.memoryBytes-(1<<20), s.workUnits-4096
		for rows.Next() {
			var row selected
			var size *int64
			if err := rows.Scan(&row.id, &row.version, &size); err != nil {
				rows.Close()
				return err
			}
			if len(selectedRows) == input.Limit {
				page.HasMore = true
				break
			}
			if size == nil {
				rows.Close()
				return ErrCapacityAgreementInvalid
			}
			if *size < 0 || *size > memory/64 || *size > work/64 {
				rows.Close()
				return ErrCapacityAgreementBudget
			}
			memory, work = memory-*size*64-1024, work-*size*64-4096
			if memory < 0 || work < 0 {
				rows.Close()
				return ErrCapacityAgreementBudget
			}
			selectedRows = append(selectedRows, row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, row := range selectedRows {
			item, err := s.read(ctx, sc, row.id, row.version, "")
			if err != nil {
				return err
			}
			page.Items = append(page.Items, item)
			page.Next = row.id
			if id != "" {
				page.Next = strconv.FormatInt(row.version, 10)
			}
		}
		if !page.HasMore {
			page.Next = ""
		}
		return ctx.Err()
	})
	if err != nil {
		return CapacityAgreementPage{}, capacityAgreementStorageError(err)
	}
	return page, nil
}
