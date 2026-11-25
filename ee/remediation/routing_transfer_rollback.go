// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"errors"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferRollbackStore interface {
	readRoutingTransferRollback(context.Context, string, string, rem.RoutingTransferRollbackAuthorizer) (rem.RoutingTransferRollback, error)
	requestRoutingTransferWithdrawal(context.Context, string, string, string, string, rem.RoutingTransferRollbackAuthorizer, AuditSink) (rem.RoutingTransferRollback, error)
}

func (s *Service) GetRoutingTransferRollback(ctx context.Context, tenant, id string,
	authorize rem.RoutingTransferRollbackAuthorizer) (rem.RoutingTransferRollback, error) {
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	store, ok := s.store.(routingTransferRollbackStore)
	if !ok || authorize == nil {
		return rem.RoutingTransferRollback{}, unavailableRTBHReview()
	}
	out, err := store.readRoutingTransferRollback(ctx, tenant, id, authorize)
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	out.State = out.StateAt(s.now().UTC())
	return out, ctx.Err()
}

func (s *Service) RequestRoutingTransferWithdrawal(ctx context.Context, tenant, actor, id, fingerprint string,
	authorize rem.RoutingTransferRollbackAuthorizer) (rem.RoutingTransferRollback, error) {
	if _, err := remediationActor(ctx, tenant, true); err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	store, ok := s.store.(routingTransferRollbackStore)
	if !ok || authorize == nil {
		return rem.RoutingTransferRollback{}, unavailableRTBHReview()
	}
	if !validRTBHDigest(fingerprint) {
		return rem.RoutingTransferRollback{}, rem.Error{Code: "validation", Message: "choose the exact approved routing transfer"}
	}
	out, err := store.requestRoutingTransferWithdrawal(ctx, tenant, actor, id, fingerprint, authorize, s.audit)
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	out.State = out.StateAt(s.now().UTC())
	return out, ctx.Err()
}

func storedRoutingTransferRollback(ctx context.Context, sc tenancy.Scope, loaded loadedRoutingTransferReview,
	authorize rem.RoutingTransferRollbackAuthorizer) (rem.RoutingTransferRollback, error) {
	var out rem.RoutingTransferRollback
	if loaded.proposal.State != rem.StateApproved {
		return out, rem.Error{Code: "not_found", Message: "approved routing transfer not found"}
	}
	tenant := sc.Tenant.String()
	stored, err := decodeStoredRoutingTransferReview(tenant, loaded.review)
	if err != nil {
		return out, err
	}
	preview := stored.Review.Preview
	if loaded.proposal.Target != preview.ExactPrefix || !hasRoutingTransferRollback(tenant, preview) {
		return out, changedRTBHReview()
	}
	decision, err := decodeRoutingTransferDecision(loaded, stored.Review.Fingerprint, stored.Review.ExpiresAt)
	if err != nil {
		return out, err
	}
	if loaded.withdrawn != nil && loaded.withdrawn.Before(decision.ApprovedAt) {
		return out, changedRTBHReview()
	}
	source := entity.SourceKey{AgentID: preview.ArchiveAgentID, Kind: entity.DeviceTarget, SourceRef: preview.ArchiveSourceRef}
	if err := authorize(ctx, sc, preview.ContextID, preview.RouterID, source); err != nil {
		return out, err
	}
	return rem.RoutingTransferRollback{
		ProposalID: loaded.proposal.ID, Fingerprint: stored.Review.Fingerprint,
		ContextID: preview.ContextID, RouterID: preview.RouterID, ExactPrefix: preview.ExactPrefix,
		CandidatePeer: preview.CandidatePeer, RestorePolicy: preview.CurrentInboundPolicy, RemovePolicy: preview.ProposedInboundPolicy,
		ApprovedAt: decision.ApprovedAt, ApprovalExpiresAt: decision.ValidUntil, WithdrawRequested: loaded.withdrawn,
		Withdraw: preview.Withdraw,
	}, nil
}

func hasRoutingTransferRollback(tenant string, preview rem.RoutingTransferDryRun) bool {
	scope := entity.Scope{TenantID: tenant, ContextID: preview.ContextID}
	normalized, scopeErr := scope.Normalize()
	router, routerErr := uuid.Parse(preview.RouterID)
	prefix, prefixErr := netip.ParsePrefix(preview.ExactPrefix)
	return scopeErr == nil && normalized == scope && routerErr == nil && router != uuid.Nil &&
		router.String() == preview.RouterID && prefixErr == nil && prefix == prefix.Masked() &&
		prefix.String() == preview.ExactPrefix && preview.CandidatePeer != "" &&
		preview.ArchiveAgentID != "" && preview.ArchiveSourceRef != "" &&
		preview.CurrentInboundPolicy != "" && preview.ProposedInboundPolicy != "" && len(preview.Withdraw) != 0
}

func (s *PGStore) readRoutingTransferRollback(ctx context.Context, tenant, id string,
	authorize rem.RoutingTransferRollbackAuthorizer) (rem.RoutingTransferRollback, error) {
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	var result rem.RoutingTransferRollback
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		loaded, err := loadRoutingTransferReviewInScope(ctx, sc, id, false)
		if err != nil {
			return err
		}
		result, err = storedRoutingTransferRollback(ctx, sc, loaded, authorize)
		return err
	})
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	return result, nil
}

func (s *PGStore) requestRoutingTransferWithdrawal(ctx context.Context, tenant, actor, id, fingerprint string,
	authorize rem.RoutingTransferRollbackAuthorizer, sink AuditSink) (rem.RoutingTransferRollback, error) {
	txAudit, ok := sink.(scopedAuditSink)
	if !ok {
		return rem.RoutingTransferRollback{}, errAuditUnavailable
	}
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	var result rem.RoutingTransferRollback
	err = tenancy.InTenant(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		loaded, err := loadRoutingTransferReviewInScope(ctx, sc, id, true)
		if err != nil {
			return err
		}
		result, err = storedRoutingTransferRollback(ctx, sc, loaded, authorize)
		if err != nil {
			return err
		}
		if fingerprint != result.Fingerprint {
			return changedRTBHReview()
		}
		if result.WithdrawRequested != nil {
			return nil
		}
		if err := sc.Q.QueryRow(ctx, `UPDATE remediation_proposals
			SET routing_transfer_withdraw_requested_at=GREATEST(clock_timestamp(),decided_at)
			WHERE tenant_id=$1 AND id=$2 AND kind='routing_transfer_review' AND state='approved'
			  AND routing_transfer_approval->>'review_fingerprint'=$3 AND routing_transfer_withdraw_requested_at IS NULL
			RETURNING routing_transfer_withdraw_requested_at`, sc.Tenant.String(), id, fingerprint).Scan(&result.WithdrawRequested); err != nil {
			return err
		}
		return txAudit.appendScoped(ctx, sc, actor, "remediation.routing_transfer_withdraw", id, map[string]any{
			"review_fingerprint": fingerprint, "context_id": result.ContextID, "router_id": result.RouterID,
			"exact_prefix": result.ExactPrefix, "withdraw_requested_at": result.WithdrawRequested,
		})
	})
	var postgresErr *pgconn.PgError
	if errors.As(err, &postgresErr) && postgresErr.Code == "55P03" {
		return rem.RoutingTransferRollback{}, changedRTBHReview()
	}
	if err != nil {
		return rem.RoutingTransferRollback{}, err
	}
	return result, nil
}
