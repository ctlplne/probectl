// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrTagReference = errors.New("tag context, definition or subject is not owned by this tenant")

// TagRules writes one context's reviewed rules inside a tenant transaction.
// The caller must append audit through the same scope before committing.
type TagRules struct{}

// List returns one stable ID-ordered page. The bound applies before rows can
// leave FORCE-RLS storage; a foreign context therefore cannot leak rules.
func (TagRules) List(ctx context.Context, sc tenancy.Scope, contextID, cursor string,
	limit int) ([]tags.Rule, string, error) {
	if limit < 1 || limit > 100 {
		return nil, "", tags.ErrInvalid
	}
	if cursor != "" {
		if _, err := uuid.Parse(cursor); err != nil {
			return nil, "", tags.ErrInvalid
		}
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,tag_id::text,target_kind,match_kind,
		COALESCE(address_side,''),COALESCE(cidr::text,''),COALESCE(name_pattern,''),
		COALESCE(snmp_field,''),COALESCE(snmp_value,''),value,priority
		FROM tenant_tag_rules WHERE tenant_id=$1 AND context_id=$2
		AND ($3::uuid IS NULL OR id > $3::uuid) ORDER BY id LIMIT $4`,
		sc.Tenant.String(), contextID, tagOptional(cursor), limit+1)
	if err != nil {
		return nil, "", tagRuleError(err)
	}
	defer rows.Close()
	items := make([]tags.Rule, 0, limit)
	var page tagPageBudget
	for rows.Next() {
		item := tags.Rule{Scope: tags.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}}
		if err := rows.Scan(&item.ID, &item.TagID, &item.TargetKind,
			&item.Match, &item.AddressSide, &item.CIDR, &item.NamePattern,
			&item.SNMPField, &item.SNMPValue, &item.Value, &item.Priority); err != nil {
			return nil, "", err
		}
		if len(items) == limit {
			return items, items[len(items)-1].ID, nil
		}
		admitted, err := page.admit(item)
		if err != nil {
			return nil, "", err
		}
		if !admitted {
			return items, items[len(items)-1].ID, nil
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return items, "", nil
}

func (TagRules) Create(ctx context.Context, sc tenancy.Scope, input tags.Rule) (tags.Rule, error) {
	id, err := crypto.UUIDv4()
	if err != nil {
		return tags.Rule{}, err
	}
	input.ID = id
	if input.TenantID != sc.Tenant.String() {
		return tags.Rule{}, tags.ErrScopeMismatch
	}
	if err := tags.ValidateRule(input); err != nil {
		return tags.Rule{}, err
	}
	if err := lockTagRuleQuota(ctx, sc); err != nil {
		return tags.Rule{}, err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO tenant_tag_rules
		(tenant_id,context_id,id,tag_id,target_kind,match_kind,address_side,cidr,
		 name_pattern,snmp_field,snmp_value,value,priority)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		input.TenantID, input.ContextID, input.ID, input.TagID,
		input.TargetKind, input.Match, tagOptional(input.AddressSide),
		tagOptional(input.CIDR), tagOptional(input.NamePattern),
		tagOptional(input.SNMPField), tagOptional(input.SNMPValue),
		input.Value, input.Priority)
	if err != nil {
		return tags.Rule{}, tagRuleError(err)
	}
	return input, nil
}

func (TagRules) Update(ctx context.Context, sc tenancy.Scope, input tags.Rule) (tags.Rule, error) {
	if input.TenantID != sc.Tenant.String() {
		return tags.Rule{}, tags.ErrScopeMismatch
	}
	if err := tags.ValidateRule(input); err != nil {
		return tags.Rule{}, err
	}
	result, err := sc.Q.Exec(ctx, `UPDATE tenant_tag_rules SET
		tag_id=$4,target_kind=$5,match_kind=$6,address_side=$7,cidr=$8,
		name_pattern=$9,snmp_field=$10,snmp_value=$11,value=$12,priority=$13
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
		input.TenantID, input.ContextID, input.ID, input.TagID,
		input.TargetKind, input.Match, tagOptional(input.AddressSide),
		tagOptional(input.CIDR), tagOptional(input.NamePattern),
		tagOptional(input.SNMPField), tagOptional(input.SNMPValue),
		input.Value, input.Priority)
	if err != nil {
		return tags.Rule{}, tagRuleError(err)
	}
	if result.RowsAffected() == 0 {
		return tags.Rule{}, pgx.ErrNoRows
	}
	return input, nil
}

func (TagRules) Delete(ctx context.Context, sc tenancy.Scope, contextID, id string) error {
	result, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_rules
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, sc.Tenant.String(), contextID, id)
	if err != nil {
		return tagRuleError(err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func lockTagRuleQuota(ctx context.Context, sc tenancy.Scope) error {
	tenantID := sc.Tenant.String()
	if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_revisions(tenant_id,revision)
		VALUES ($1,1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return err
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
		WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&revision); err != nil {
		return err
	}
	var count int
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_rules
		WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
		return err
	}
	if count >= tags.MaxRules {
		return tags.ErrInvalid
	}
	return nil
}

func tagOptional(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func tagRuleError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return ErrTagReference
		case "23505":
			return tags.ErrConflict
		case "23514", "22P02":
			return tags.ErrInvalid
		}
	}
	return err
}
