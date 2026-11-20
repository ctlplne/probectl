// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/json"
	"time"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

func (s *Service) ProposeDiversion(ctx context.Context, tenant, actor string, input rem.DiversionProposalInput, check func(context.Context) error, authority rem.RTBHImpactPublication) (rem.Proposal, error) {
	store, ok := s.store.(diversionStore)
	if !ok {
		return rem.Proposal{}, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return rem.Proposal{}, err
	}
	if !validRTBHDigest(input.PreviewFingerprint) || input.Selection.Action == rem.DiversionStart && input.ObservedTo == nil ||
		input.Selection.Action == rem.DiversionStop && (input.ObservedTo != nil || input.MaxKnownBenignPackets != "") {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "select the exact displayed diversion preview"}
	}
	var observedTo time.Time
	if input.ObservedTo != nil {
		observedTo = *input.ObservedTo
		if observedTo.IsZero() {
			return rem.Proposal{}, changedRTBHReview()
		}
	}
	preview, current, err := s.prepareDiversion(ctx, tenant, input.Selection, observedTo, check)
	if err != nil {
		return rem.Proposal{}, err
	}
	if preview.Fingerprint != input.PreviewFingerprint {
		return rem.Proposal{}, changedRTBHReview()
	}
	now := s.now().UTC()
	stored := storedDiversionReview{Version: 1, Selection: input.Selection, Scope: current.Scope,
		Review: rem.DiversionReview{Candidate: preview, MaxKnownBenignPackets: input.MaxKnownBenignPackets, ExpiresAt: now.Add(rtbhReviewLifetime)}}
	title := "Stop diversion preview"
	if preview.Action == rem.DiversionStart {
		title = "Start diversion preview"
		stored.Review.BlastRadius, err = s.diversionBlastRadius(preview, input.MaxKnownBenignPackets)
		if err != nil {
			return rem.Proposal{}, err
		}
		stored.Review.ExpiresAt = observedTo.UTC().Add(rtbhReviewLifetime)
	} else {
		current.Publish = authority.Publish
	}
	if current.Publish == nil {
		return rem.Proposal{}, unavailableRTBHReview()
	}
	stored.Review.Fingerprint, err = diversionReviewDigest(stored)
	if err != nil {
		return rem.Proposal{}, err
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return rem.Proposal{}, err
	}
	proposal := rem.Proposal{Kind: rem.KindDiversionPreview, Title: title,
		Rationale: "Review the scope of a local scrubbing diversion simulation.", State: rem.StateProposed, ProposedBy: actor,
		ProposedUserID: user, CreatedAt: now, DryRun: rem.DryRun{BlastRadius: stored.Review.BlastRadius, Note: "Local preview"}}
	return store.InsertDiversionAudited(ctx, tenant, proposal, raw, s.withRTBHExpiry(current, stored.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.propose", Data: map[string]any{"kind": rem.KindDiversionPreview,
			"diversion_action": preview.Action, "proposer_user_id": user}})
}

func (s *Service) diversionBlastRadius(preview rem.DiversionPreview, limit string) (int, error) {
	if preview.Impact == nil {
		return 0, rem.ErrUnknownBlastRadius
	}
	bound, err := routingReviewBlastRadius(preview.Prefix, preview.Impact.Prefix, s.maxBlastRadius)
	if err != nil {
		return 0, err
	}
	return bound, routingReviewCollateralWithinLimit(preview.Impact.KnownBenign.Packets, limit)
}

func (s *Service) GetDiversionReview(ctx context.Context, tenant, id string, check func(context.Context) error) (rem.DiversionReview, error) {
	store, ok := s.store.(diversionStore)
	if !ok || check == nil {
		return rem.DiversionReview{}, unavailableRTBHReview()
	}
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return rem.DiversionReview{}, err
	}
	if err := check(ctx); err != nil {
		return rem.DiversionReview{}, err
	}
	loaded, err := store.loadDiversionReview(ctx, tenant, id)
	if err != nil {
		return rem.DiversionReview{}, err
	}
	stored, err := decodeDiversionReview(loaded.Raw)
	if err != nil {
		return rem.DiversionReview{}, err
	}
	if stored.Review.Candidate.Action == rem.DiversionStart {
		if loaded.Proposal.State == rem.StateProposed {
			if stored.Review.Candidate.Impact == nil || !s.now().UTC().Before(stored.Review.ExpiresAt) {
				return rem.DiversionReview{}, changedRTBHReview()
			}
			preview, publication, err := s.prepareDiversion(ctx, tenant, stored.Selection, stored.Review.Candidate.Impact.To, check)
			if err != nil {
				return rem.DiversionReview{}, err
			}
			if preview.Fingerprint != stored.Review.Candidate.Fingerprint || publication.Scope != stored.Scope {
				return rem.DiversionReview{}, changedRTBHReview()
			}
		} else {
			stored.Review.Candidate.Impact = nil
		}
	}
	stored.Review.Receipt = loaded.Receipt
	stored.Review.StartStoppedAt = loaded.StartStoppedAt
	return stored.Review, check(ctx)
}

func (s *Service) ApproveDiversion(ctx context.Context, tenant, actor, id string, input rem.DiversionApprovalInput, check func(context.Context) error, authority rem.RTBHImpactPublication) (rem.DiversionReceipt, error) {
	if !s.approvalsEnabled {
		return rem.DiversionReceipt{}, rem.ErrApprovalsDisabled
	}
	store, ok := s.store.(diversionStore)
	if !ok || authority.Publish == nil || check == nil {
		return rem.DiversionReceipt{}, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	if err := check(ctx); err != nil {
		return rem.DiversionReceipt{}, err
	}
	loaded, err := store.loadDiversionReview(ctx, tenant, id)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	proposal := loaded.Proposal
	if proposal.ProposedUserID == "" || proposal.ProposedUserID == user {
		reason, refusal := "self_approval", rem.ErrSelfApproval
		if proposal.ProposedUserID == "" {
			reason, refusal = "proposer_identity_unavailable", rem.ErrProposerIdentityUnavailable
		}
		if err := s.record(ctx, tenant, actor, "remediation.approve_blocked", id, map[string]any{"reason": reason, "approver_user_id": user}); err != nil {
			return rem.DiversionReceipt{}, err
		}
		return rem.DiversionReceipt{}, refusal
	}
	stored, err := decodeDiversionReview(loaded.Raw)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	if input.Fingerprint != stored.Review.Fingerprint {
		return rem.DiversionReceipt{}, changedRTBHReview()
	}
	if proposal.State == rem.StateApproved && loaded.Receipt != nil {
		return *loaded.Receipt, check(ctx)
	}
	if proposal.State != rem.StateProposed {
		return rem.DiversionReceipt{}, rem.ErrNotProposed
	}
	if !s.now().UTC().Before(stored.Review.ExpiresAt) {
		return rem.DiversionReceipt{}, changedRTBHReview()
	}
	var observedTo time.Time
	if stored.Review.Candidate.Impact != nil {
		observedTo = stored.Review.Candidate.Impact.To
	}
	preview, current, err := s.prepareDiversion(ctx, tenant, stored.Selection, observedTo, check)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	if preview.Fingerprint != stored.Review.Candidate.Fingerprint || current.Scope != stored.Scope {
		return rem.DiversionReceipt{}, changedRTBHReview()
	}
	if preview.Action == rem.DiversionStart {
		bound, err := s.diversionBlastRadius(preview, stored.Review.MaxKnownBenignPackets)
		if err != nil {
			return rem.DiversionReceipt{}, err
		}
		if bound != stored.Review.BlastRadius {
			return rem.DiversionReceipt{}, changedRTBHReview()
		}
	} else {
		current.Publish = authority.Publish
	}
	return store.ApproveDiversionAudited(ctx, tenant, id, actor, input.Note, s.now().UTC(), loaded.Raw, preview, s.withRTBHExpiry(current, stored.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.approve", Target: id, Data: map[string]any{"state": rem.StateApproved,
			"kind": rem.KindDiversionPreview, "diversion_action": preview.Action, "connector": preview.Connector,
			"note": input.Note, "approver_user_id": user}})
}
