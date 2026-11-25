// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *PGStore) insertRoutingTransferReview(ctx context.Context, tenant string, proposal rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || proposal.Kind != rem.KindRoutingTransferReview || len(review) == 0 || len(review) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.insertAuditedWithReview(ctx, tenant, proposal, review, current, sink, event)
}

type loadedRoutingTransferReview struct {
	proposal  rem.Proposal
	review    []byte
	approval  []byte
	withdrawn *time.Time
}

func (s *PGStore) loadRoutingTransferReview(ctx context.Context, tenant, id string) (loadedRoutingTransferReview, error) {
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return loadedRoutingTransferReview{}, err
	}
	var out loadedRoutingTransferReview
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = loadRoutingTransferReviewInScope(ctx, sc, id, false)
		return err
	})
	return out, err
}

func loadRoutingTransferReviewInScope(ctx context.Context, sc tenancy.Scope, id string, lock bool) (loadedRoutingTransferReview, error) {
	var out loadedRoutingTransferReview
	const owned = ` FROM remediation_proposals WHERE tenant_id=$1 AND id=$2 AND kind='routing_transfer_review'`
	statement := `SELECT ` + cols + owned
	if lock {
		statement += " FOR UPDATE NOWAIT"
	}
	tenant := sc.Tenant.String()
	var err error
	out.proposal, err = scanProposal(sc.Q.QueryRow(ctx, statement, tenant, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return loadedRoutingTransferReview{}, rem.Error{Code: "not_found", Message: "routing transfer review not found"}
	}
	if err != nil {
		return loadedRoutingTransferReview{}, err
	}
	if err := sc.Q.QueryRow(ctx, `SELECT
            CASE WHEN octet_length(routing_transfer_review::text)<=$3 THEN routing_transfer_review END,
            CASE WHEN octet_length(routing_transfer_approval::text)<=2048 THEN routing_transfer_approval END,
            routing_transfer_withdraw_requested_at`+owned,
		tenant, id, maxRTBHReviewBytes).Scan(&out.review, &out.approval, &out.withdrawn); err != nil {
		return loadedRoutingTransferReview{}, err
	}
	if len(out.review) == 0 || (out.proposal.State == rem.StateApproved && len(out.approval) == 0) {
		return loadedRoutingTransferReview{}, rem.ErrUnknownBlastRadius
	}
	return out, nil
}

func (s *PGStore) approveRoutingTransferReview(ctx context.Context, tenant, id, actor, note string, expiresAt time.Time,
	expected []byte, current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || expiresAt.IsZero() || len(expected) == 0 || len(expected) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	txAudit, ok := sink.(scopedAuditSink)
	if !ok {
		return rem.Proposal{}, errAuditUnavailable
	}
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = s.withProposalPublication(scoped, current, "remediation.approve", func(ctx context.Context, sc tenancy.Scope) error {
		user, err := remediationActor(ctx, tenant, true)
		if err != nil {
			return err
		}
		out, err = approveOwnedRoutingTransferReview(ctx, sc.Q, tenant, id, user, actor, note, expiresAt, expected)
		if err != nil {
			return err
		}
		return txAudit.appendScoped(ctx, sc, actor, "remediation.approve", out.ID, auditData(event.Data, out))
	})
	if err != nil {
		return rem.Proposal{}, err
	}
	return out, nil
}

func approveOwnedRoutingTransferReview(ctx context.Context, q tenancy.Querier, tenant, id, user, actor, note string,
	expiresAt time.Time, expected []byte) (rem.Proposal, error) {
	out, err := scanProposal(q.QueryRow(ctx, `
		WITH owned AS MATERIALIZED (
			SELECT p.id AS owned_id
			  FROM remediation_proposals p
			  JOIN users u ON u.tenant_id=p.tenant_id AND u.id=$3::uuid AND u.status='active'
			 WHERE p.tenant_id=$1 AND p.id=$2 AND p.kind='routing_transfer_review' AND p.state='proposed'
			   AND p.proposed_user_id IS NOT NULL AND p.proposed_user_id<>u.id
			   AND p.routing_transfer_review=$7::jsonb AND p.routing_transfer_approval IS NULL
			   FOR UPDATE OF p NOWAIT FOR SHARE OF u NOWAIT
		), decision AS MATERIALIZED (SELECT owned_id, clock_timestamp() AS wall_time FROM owned)
		UPDATE remediation_proposals
		   SET state='approved', decided_by=$4, decision_note=$5, decided_at=decision.wall_time,
		       routing_transfer_approval=jsonb_build_object(
		           'version',1, 'review_fingerprint',routing_transfer_review #>> '{review,fingerprint}',
		           'approved_by_user_id',($3::uuid)::text, 'approved_at',decision.wall_time,
		           'expires_at',LEAST($6::timestamptz,(routing_transfer_review #>> '{review,expires_at}')::timestamptz))
		  FROM decision
		 WHERE tenant_id=$1 AND id=decision.owned_id AND decision.wall_time<$6::timestamptz
		   AND decision.wall_time<(routing_transfer_review #>> '{review,expires_at}')::timestamptz
		RETURNING `+cols,
		tenant, id, user, actor, note, expiresAt, expected))
	// Publication already holds the audit lock to freeze the agreement terms.
	// A competing rejection may hold this proposal while it waits for audit.
	// Refuse immediately rather than waiting on that lock in reverse order.
	var postgresErr *pgconn.PgError
	if errors.As(err, &postgresErr) && postgresErr.Code == "55P03" {
		return rem.Proposal{}, changedRTBHReview()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return rem.Proposal{}, rem.ErrNotProposed
	}
	return out, err
}
