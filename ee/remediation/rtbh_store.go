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

const maxRTBHReviewBytes = 1 << 20

// RTBH uses the same owned row and audit transaction as other proposals.
// Its source callback holds the original detector and current tenant fences
// around the existing insert/decision and corresponding audit append.
type rtbhStore interface {
	InsertRTBHAudited(context.Context, string, rem.Proposal, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
	LoadRTBHReview(context.Context, string, string) (rem.Proposal, []byte, error)
	ApproveRTBHAudited(context.Context, string, string, string, string, time.Time, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
}

func (s *PGStore) InsertRTBHAudited(ctx context.Context, tenantID string, p rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || p.Kind != rem.KindRTBHReview || len(review) == 0 || len(review) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.insertAuditedWithReview(ctx, tenantID, p, review, current, sink, event)
}

func (s *PGStore) InsertFlowSpecAudited(ctx context.Context, tenantID string, p rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || p.Kind != rem.KindFlowSpecReview || len(review) == 0 || len(review) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.insertAuditedWithReview(ctx, tenantID, p, review, current, sink, event)
}

func (s *PGStore) LoadRTBHReview(ctx context.Context, tenantID, id string) (rem.Proposal, []byte, error) {
	return s.loadRoutingReview(ctx, tenantID, id, rem.KindRTBHReview)
}

func (s *PGStore) LoadFlowSpecReview(ctx context.Context, tenantID, id string) (rem.Proposal, []byte, error) {
	return s.loadRoutingReview(ctx, tenantID, id, rem.KindFlowSpecReview)
}

func (s *PGStore) loadRoutingReview(ctx context.Context, tenantID, id string, kind rem.Kind) (rem.Proposal, []byte, error) {
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, nil, err
	}
	var p rem.Proposal
	var review []byte
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		p, err = scanProposal(sc.Q.QueryRow(ctx, `SELECT `+cols+` FROM remediation_proposals WHERE tenant_id=$1 AND id=$2 AND kind=$3`, tenantID, id, kind))
		if err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx, `
		 SELECT CASE WHEN octet_length(review::text)<=$4 THEN review END
		 FROM (SELECT CASE kind WHEN 'rtbh_review' THEN rtbh_review WHEN 'flowspec_review' THEN flowspec_review END AS review
		       FROM remediation_proposals WHERE tenant_id=$1 AND id=$2 AND kind=$3) owned_review`,
			tenantID, id, kind, maxRTBHReviewBytes).Scan(&review)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return rem.Proposal{}, nil, rem.Error{Code: "not_found", Message: "routing review not found"}
	}
	if err != nil {
		return rem.Proposal{}, nil, err
	}
	if len(review) == 0 {
		return rem.Proposal{}, nil, rem.ErrUnknownBlastRadius
	}
	return p, review, nil
}

func (s *PGStore) ApproveRTBHAudited(ctx context.Context, tenantID, id, actor, note string, at time.Time, expected []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || len(expected) == 0 || len(expected) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.decideAuditedWithReview(ctx, tenantID, id, rem.StateApproved, actor, note, at, rem.KindRTBHReview, expected, current, sink, event)
}

func (s *PGStore) ApproveFlowSpecAudited(ctx context.Context, tenantID, id, actor, note string, at time.Time, expected []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || len(expected) == 0 || len(expected) > maxRTBHReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.decideAuditedWithReview(ctx, tenantID, id, rem.StateApproved, actor, note, at, rem.KindFlowSpecReview, expected, current, sink, event)
}

func (s *PGStore) withProposalPublication(ctx context.Context, publication rem.RTBHImpactPublication, permission string,
	mutate func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if publication.Publish == nil {
			return mutate(ctx, sc)
		}
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		// Publish takes the original rule row before the canonical audit lock,
		// just as alert receipt reads and updates do.
		return publication.Publish(ctx, sc, permission, mutate)
	})
}
