// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

type storedFlowSpecReview struct {
	Version     int                       `json:"version"`
	Request     rem.FlowSpecProposalInput `json:"request"`
	Review      rem.FlowSpecReview        `json:"review"`
	SourceScope string                    `json:"source_scope"`
}

type flowSpecReviewStore interface {
	InsertFlowSpecAudited(context.Context, string, rem.Proposal, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
	LoadFlowSpecReview(context.Context, string, string) (rem.Proposal, []byte, error)
	ApproveFlowSpecAudited(context.Context, string, string, string, string, time.Time, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
}

func (s *Service) ProposeFlowSpec(ctx context.Context, tenant, actor string, input rem.FlowSpecProposalInput,
	credential func(context.Context) error,
) (rem.Proposal, error) {
	var empty rem.Proposal
	store, ok := s.store.(flowSpecReviewStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, false)
	if err != nil {
		return empty, err
	}
	if !validRTBHDigest(input.PreviewFingerprint) || input.ObservedTo.IsZero() {
		return empty, rem.Error{Code: "validation", Message: "select the exact displayed FlowSpec proposal"}
	}
	now := s.now().UTC()
	if input.ObservedTo.After(now) || !now.Before(input.ObservedTo.Add(rtbhReviewLifetime)) {
		return empty, changedRTBHReview()
	}
	preview, prepared, err := s.prepareFlowSpec(ctx, tenant, input.Preview, input.ObservedTo, credential)
	if err != nil {
		return empty, err
	}
	if preview.Fingerprint != input.PreviewFingerprint {
		return empty, changedRTBHReview()
	}
	bound, err := s.flowSpecReviewLimits(preview, input.MaxKnownBenignPackets)
	if err != nil {
		return empty, err
	}
	input.ObservedTo = preview.Matching.To
	stored := storedFlowSpecReview{Version: 1, Request: input, SourceScope: prepared.Scope, Review: rem.FlowSpecReview{
		Proposal: preview, MaxKnownBenignPackets: input.MaxKnownBenignPackets,
		BlastRadius: bound, ExpiresAt: input.ObservedTo.Add(rtbhReviewLifetime),
	}}
	stored.Review.Fingerprint, err = flowSpecReviewFingerprint(stored.Review)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return empty, err
	}
	proposal := rem.Proposal{
		Kind: rem.KindFlowSpecReview, Title: "FlowSpec proposal review", Rationale: "Review the current scoped match and declared collateral limit.",
		DryRun: rem.DryRun{BlastRadius: bound, Note: "Configured destination scope"},
		State:  rem.StateProposed, ProposedBy: actor, ProposedUserID: user, CreatedAt: now,
	}
	return store.InsertFlowSpecAudited(ctx, tenant, proposal, raw, s.withRTBHExpiry(prepared, stored.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.propose", Data: map[string]any{"kind": rem.KindFlowSpecReview, "proposer_user_id": user}})
}

func (s *Service) GetFlowSpecReview(ctx context.Context, tenant, id string, credential func(context.Context) error) (rem.FlowSpecReview, error) {
	var empty rem.FlowSpecReview
	store, ok := s.store.(flowSpecReviewStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return empty, err
	}
	_, raw, err := store.LoadFlowSpecReview(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	stored, err := decodeStoredFlowSpecReview(raw)
	if err != nil {
		return empty, err
	}
	if _, err := s.refreshFlowSpecReview(ctx, tenant, stored, credential); err != nil {
		return empty, err
	}
	return stored.Review, ctx.Err()
}

func (s *Service) ApproveFlowSpec(ctx context.Context, tenant, actor, id, fingerprint, note string,
	credential func(context.Context) error,
) (rem.Proposal, error) {
	var empty rem.Proposal
	if !s.approvalsEnabled {
		return empty, rem.ErrApprovalsDisabled
	}
	store, ok := s.store.(flowSpecReviewStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return empty, err
	}
	proposal, raw, err := store.LoadFlowSpecReview(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	if proposal.State != rem.StateProposed {
		return empty, rem.ErrNotProposed
	}
	if proposal.ProposedUserID == "" || proposal.ProposedUserID == user {
		reason, refusal := "self_approval", rem.ErrSelfApproval
		if proposal.ProposedUserID == "" {
			reason, refusal = "proposer_identity_unavailable", rem.ErrProposerIdentityUnavailable
		}
		if err := s.record(ctx, tenant, actor, "remediation.approve_blocked", id, map[string]any{"reason": reason, "approver_user_id": user}); err != nil {
			return empty, err
		}
		return empty, refusal
	}
	stored, err := decodeStoredFlowSpecReview(raw)
	if err != nil {
		return empty, err
	}
	if fingerprint != stored.Review.Fingerprint {
		return empty, changedRTBHReview()
	}
	prepared, err := s.refreshFlowSpecReview(ctx, tenant, stored, credential)
	if err != nil {
		return empty, err
	}
	return store.ApproveFlowSpecAudited(ctx, tenant, id, actor, note, s.now().UTC(), raw,
		s.withRTBHExpiry(prepared, stored.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.approve", Target: id,
			Data: map[string]any{"state": rem.StateApproved, "note": note, "approver_user_id": user}})
}

func (s *Service) refreshFlowSpecReview(ctx context.Context, tenant string, stored storedFlowSpecReview,
	credential func(context.Context) error,
) (rem.RTBHImpactPublication, error) {
	if !s.now().UTC().Before(stored.Review.ExpiresAt) {
		return rem.RTBHImpactPublication{}, changedRTBHReview()
	}
	preview, prepared, err := s.prepareFlowSpec(ctx, tenant, stored.Request.Preview, stored.Request.ObservedTo, credential)
	if err != nil {
		return rem.RTBHImpactPublication{}, err
	}
	if prepared.Scope != stored.SourceScope || preview.Fingerprint != stored.Request.PreviewFingerprint {
		return rem.RTBHImpactPublication{}, changedRTBHReview()
	}
	bound, err := s.flowSpecReviewLimits(preview, stored.Review.MaxKnownBenignPackets)
	if err != nil {
		return rem.RTBHImpactPublication{}, err
	}
	current := stored.Review
	current.Proposal, current.BlastRadius = preview, bound
	if currentDigest, err := flowSpecReviewFingerprint(current); err != nil || currentDigest != stored.Review.Fingerprint {
		return rem.RTBHImpactPublication{}, changedRTBHReview()
	}
	return prepared, ctx.Err()
}

func (s *Service) flowSpecReviewLimits(preview rem.FlowSpecPreview, maxBenignPackets string) (int, error) {
	if preview.Matching.ObservedRecords == 0 {
		return 0, rem.ErrUnknownBlastRadius
	}
	bound, err := routingReviewBlastRadius(preview.Candidate.Destination, preview.Matching.Prefix, s.maxBlastRadius)
	if err != nil {
		return 0, err
	}
	return bound, routingReviewCollateralWithinLimit(preview.Matching.KnownBenign.Packets, maxBenignPackets)
}

func decodeStoredFlowSpecReview(raw []byte) (storedFlowSpecReview, error) {
	var review, empty storedFlowSpecReview
	if len(raw) == 0 || len(raw) > maxRTBHReviewBytes {
		return empty, rem.ErrUnknownBlastRadius
	}
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.DisallowUnknownFields()
	if err := reader.Decode(&review); err != nil || reader.Decode(new(any)) != io.EOF || review.Version != 1 ||
		!validRTBHDigest(review.SourceScope) || !validRTBHDigest(review.Request.PreviewFingerprint) ||
		!review.Review.ExpiresAt.Equal(review.Request.ObservedTo.Add(rtbhReviewLifetime)) ||
		!review.Review.Proposal.Matching.To.Equal(review.Request.ObservedTo) ||
		review.Review.Proposal.Fingerprint != review.Request.PreviewFingerprint ||
		review.Review.MaxKnownBenignPackets != review.Request.MaxKnownBenignPackets {
		return empty, rem.ErrUnknownBlastRadius
	}
	if digest, err := flowSpecReviewFingerprint(review.Review); err != nil || !validRTBHDigest(review.Review.Fingerprint) || digest != review.Review.Fingerprint {
		return empty, rem.ErrUnknownBlastRadius
	}
	return review, nil
}

func flowSpecReviewFingerprint(review rem.FlowSpecReview) (string, error) {
	review.Fingerprint = ""
	review.ExpiresAt = review.ExpiresAt.UTC()
	encoded, err := json.Marshal(review)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(encoded)), nil
}
