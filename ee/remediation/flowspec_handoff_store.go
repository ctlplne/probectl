// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowSpecHandoffStore interface {
	LoadFlowSpecHandoff(context.Context, string, string) (rem.FlowSpecHandoff, error)
	RequestFlowSpecWithdrawal(context.Context, string, string, string, time.Time, rem.RTBHImpactPublication, AuditSink) (rem.FlowSpecHandoff, error)
}

func (s *PGStore) LoadFlowSpecHandoff(ctx context.Context, tenant, id string) (rem.FlowSpecHandoff, error) {
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.FlowSpecHandoff{}, err
	}
	var out rem.FlowSpecHandoff
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		out, err = loadFlowSpecHandoffInScope(ctx, sc, id, false)
		return err
	})
	return out, err
}

func loadFlowSpecHandoffInScope(ctx context.Context, sc tenancy.Scope, id string, lock bool) (rem.FlowSpecHandoff, error) {
	var raw []byte
	var withdrawal *time.Time
	var fingerprint string
	statement := `
		SELECT CASE WHEN octet_length(flowspec_handoff::text)<=$3 THEN flowspec_handoff END,
		       flowspec_withdraw_requested_at, flowspec_review #>> '{review,review_fingerprint}'
		FROM remediation_proposals
		WHERE tenant_id=$1 AND id=$2 AND kind='flowspec_review' AND state='approved' AND flowspec_handoff IS NOT NULL`
	if lock {
		statement += " FOR UPDATE"
	}
	err := sc.Q.QueryRow(ctx, statement, sc.Tenant.String(), id, maxFlowSpecHandoffBytes).Scan(&raw, &withdrawal, &fingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return rem.FlowSpecHandoff{}, rem.Error{Code: "not_found", Message: "approved FlowSpec handoff not found"}
	}
	if err != nil {
		return rem.FlowSpecHandoff{}, err
	}
	out, err := decodeFlowSpecHandoff(id, raw)
	if err != nil || fingerprint != out.ReviewFingerprint || (withdrawal != nil && withdrawal.Before(out.IssuedAt)) {
		return rem.FlowSpecHandoff{}, rem.ErrUnknownBlastRadius
	}
	out.WithdrawRequested = withdrawal
	return out, nil
}

func (s *PGStore) RequestFlowSpecWithdrawal(ctx context.Context, tenant, actor, id string, at time.Time,
	publication rem.RTBHImpactPublication, sink AuditSink,
) (rem.FlowSpecHandoff, error) {
	txAudit, ok := sink.(scopedAuditSink)
	if !ok || publication.Publish == nil {
		return rem.FlowSpecHandoff{}, errAuditUnavailable
	}
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.FlowSpecHandoff{}, err
	}
	var out rem.FlowSpecHandoff
	err = s.withProposalPublication(scoped, publication, "remediation.approve", func(ctx context.Context, sc tenancy.Scope) error {
		out, err = loadFlowSpecHandoffInScope(ctx, sc, id, true)
		if err != nil || out.State(at) != rem.FlowSpecAuthorized {
			return err
		}
		tag, err := sc.Q.Exec(ctx, `
			UPDATE remediation_proposals SET flowspec_withdraw_requested_at=$3
			WHERE tenant_id=$1 AND id=$2 AND kind='flowspec_review' AND state='approved'
			  AND flowspec_handoff IS NOT NULL AND flowspec_withdraw_requested_at IS NULL`,
			sc.Tenant.String(), id, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return rem.ErrNotProposed
		}
		out.WithdrawRequested = &at
		return txAudit.appendScoped(ctx, sc, actor, "remediation.flowspec_withdraw", id, map[string]any{
			"review_fingerprint": out.ReviewFingerprint, "withdraw_requested_at": at,
		})
	})
	if err != nil {
		return rem.FlowSpecHandoff{}, err
	}
	return out, nil
}

func attachFlowSpecHandoff(current rem.RTBHImpactPublication, id string, raw []byte) rem.RTBHImpactPublication {
	if len(raw) == 0 {
		return current
	}
	publish := current.Publish
	current.Publish = func(ctx context.Context, sc tenancy.Scope, permission string, commit func(context.Context, tenancy.Scope) error) error {
		return publish(ctx, sc, permission, func(ctx context.Context, sc tenancy.Scope) error {
			if err := commit(ctx, sc); err != nil {
				return err
			}
			tag, err := sc.Q.Exec(ctx, `
				UPDATE remediation_proposals SET flowspec_handoff=$3::jsonb
				WHERE tenant_id=$1 AND id=$2 AND kind='flowspec_review' AND state='approved' AND flowspec_handoff IS NULL`,
				sc.Tenant.String(), id, raw)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return rem.ErrNotProposed
			}
			return nil
		})
	}
	return current
}
