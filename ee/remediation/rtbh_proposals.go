// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const rtbhReviewLifetime = 10 * time.Minute

func (s *Service) prepareRTBH(ctx context.Context, tenant string, input rem.RTBHPreviewInput, observedTo time.Time, credential func(context.Context) error) (rem.RTBHPreview, rem.RTBHImpactPublication, error) {
	var empty rem.RTBHPreview
	source, ok := s.prefixImpact.(rem.RTBHReviewSource)
	if !ok || credential == nil {
		return empty, rem.RTBHImpactPublication{}, unavailableRTBHReview()
	}
	if !input.RoutingPolicyAgreed || !canonicalRTBHCommunity(input.Community) {
		return empty, rem.RTBHImpactPublication{}, rem.Error{Code: "validation", Message: "confirm the routing policy and enter its canonical community"}
	}
	prepared, err := source.PreparePrefixImpact(ctx, tenant, input.PrefixImpactInput, observedTo, credential)
	if err != nil {
		return empty, prepared, err
	}
	if !validRTBHDigest(prepared.Scope) || prepared.Publish == nil || prepared.Impact.To.IsZero() ||
		(!observedTo.IsZero() && !prepared.Impact.To.Equal(observedTo)) || !s.now().UTC().Before(prepared.Impact.To.Add(rtbhReviewLifetime)) {
		return empty, prepared, changedRTBHReview()
	}
	preview, err := composeRTBHPreview(ctx, input, prepared.Impact)
	if err != nil {
		return empty, prepared, err
	}
	preview.Impact.From, preview.Impact.To = preview.Impact.From.UTC(), preview.Impact.To.UTC()
	raw, err := json.Marshal(struct {
		Version int                  `json:"version"`
		Tenant  string               `json:"tenant_id"`
		Input   rem.RTBHPreviewInput `json:"input"`
		Preview rem.RTBHPreview      `json:"preview"`
		Scope   string               `json:"source_scope"`
	}{1, tenant, input, preview, prepared.Scope})
	if err != nil {
		return empty, prepared, err
	}
	preview.Fingerprint = hex.EncodeToString(crypto.Hash(raw))
	return preview, prepared, ctx.Err()
}

func (s *Service) ProposeRTBH(ctx context.Context, tenant, actor string, input rem.RTBHProposalInput, credential func(context.Context) error) (rem.Proposal, error) {
	var empty rem.Proposal
	store, ok := s.store.(rtbhStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, false)
	if err != nil {
		return empty, err
	}
	if !validRTBHDigest(input.PreviewFingerprint) || input.ObservedTo.IsZero() {
		return empty, rem.Error{Code: "validation", Message: "select the exact displayed routing review"}
	}
	now := s.now().UTC()
	if input.ObservedTo.After(now) || !now.Before(input.ObservedTo.Add(rtbhReviewLifetime)) {
		return empty, changedRTBHReview()
	}
	preview, prepared, err := s.prepareRTBH(ctx, tenant, input.Preview, input.ObservedTo, credential)
	if err != nil {
		return empty, err
	}
	if preview.Fingerprint != input.PreviewFingerprint {
		return empty, changedRTBHReview()
	}
	bound, err := rtbhBlastRadius(preview, s.maxBlastRadius)
	if err != nil {
		return empty, err
	}
	if err := rtbhCollateralWithinLimit(preview, input.MaxKnownBenignPackets); err != nil {
		return empty, err
	}
	input.ObservedTo = preview.Impact.To
	review := storedRTBHReview{Version: 1, Request: input, SourceScope: prepared.Scope,
		Review: rem.RTBHReview{Candidate: preview, MaxKnownBenignPackets: input.MaxKnownBenignPackets, BlastRadius: bound, ExpiresAt: input.ObservedTo.Add(rtbhReviewLifetime)}}
	review.Review.Fingerprint, err = rtbhReviewFingerprint(review.Review)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(review)
	if err != nil {
		return empty, err
	}
	proposal := rem.Proposal{Kind: rem.KindRTBHReview, Title: "Routing mitigation review", Rationale: "Review the exact scoped traffic and declared collateral limit.",
		DryRun: rem.DryRun{BlastRadius: bound, Note: "Configured address scope"}, State: rem.StateProposed, ProposedBy: actor, ProposedUserID: user, CreatedAt: now}
	return store.InsertRTBHAudited(ctx, tenant, proposal, raw, s.withRTBHExpiry(prepared, review.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.propose", Data: map[string]any{"kind": rem.KindRTBHReview, "proposer_user_id": user}})
}

func (s *Service) GetRTBHReview(ctx context.Context, tenant, id string, credential func(context.Context) error) (rem.RTBHReview, error) {
	var empty rem.RTBHReview
	store, ok := s.store.(rtbhStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return empty, err
	}
	_, raw, err := store.LoadRTBHReview(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	stored, err := decodeStoredRTBHReview(raw, maxRTBHReviewBytes)
	if err != nil {
		return empty, err
	}
	preview, prepared, err := s.prepareRTBH(ctx, tenant, stored.Request.Preview, stored.Request.ObservedTo, credential)
	if err != nil {
		return empty, err
	}
	if err := validateCurrentRTBHReview(stored, preview, prepared.Scope, s.now().UTC(), s.maxBlastRadius); err != nil {
		return empty, err
	}
	return stored.Review, ctx.Err()
}

func (s *Service) ApproveRTBH(ctx context.Context, tenant, actor, id, fingerprint, note string, credential func(context.Context) error) (rem.Proposal, error) {
	var empty rem.Proposal
	if !s.approvalsEnabled {
		return empty, rem.ErrApprovalsDisabled
	}
	store, ok := s.store.(rtbhStore)
	if !ok {
		return empty, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return empty, err
	}
	proposal, raw, err := store.LoadRTBHReview(ctx, tenant, id)
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
	stored, err := decodeStoredRTBHReview(raw, maxRTBHReviewBytes)
	if err != nil {
		return empty, err
	}
	if fingerprint != stored.Review.Fingerprint || !s.now().UTC().Before(stored.Review.ExpiresAt) {
		return empty, changedRTBHReview()
	}
	preview, prepared, err := s.prepareRTBH(ctx, tenant, stored.Request.Preview, stored.Request.ObservedTo, credential)
	if err != nil {
		return empty, err
	}
	now := s.now().UTC()
	if err := validateCurrentRTBHReview(stored, preview, prepared.Scope, now, s.maxBlastRadius); err != nil {
		return empty, err
	}
	return store.ApproveRTBHAudited(ctx, tenant, id, actor, note, now, raw, s.withRTBHExpiry(prepared, stored.Review.ExpiresAt), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.approve", Target: id,
			Data: map[string]any{"state": rem.StateApproved, "note": note, "approver_user_id": user}})
}

func rtbhReviewFingerprint(review rem.RTBHReview) (string, error) {
	review.Fingerprint = ""
	review.Candidate.Impact.From = review.Candidate.Impact.From.UTC()
	review.Candidate.Impact.To = review.Candidate.Impact.To.UTC()
	review.ExpiresAt = review.ExpiresAt.UTC()
	encoded, err := json.Marshal(review)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(encoded)), nil
}

func (s *Service) withRTBHExpiry(prepared rem.RTBHImpactPublication, expiry time.Time) rem.RTBHImpactPublication {
	publish := prepared.Publish
	prepared.Publish = func(ctx context.Context, sc tenancy.Scope, permission string, mutate func(context.Context, tenancy.Scope) error) error {
		return publish(ctx, sc, permission, func(ctx context.Context, sc tenancy.Scope) error {
			if !s.now().UTC().Before(expiry) {
				return changedRTBHReview()
			}
			return mutate(ctx, sc)
		})
	}
	return prepared
}

func validRTBHDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func unavailableRTBHReview() error {
	return rem.Error{Code: "not_found", Message: "traffic review is unavailable"}
}

func changedRTBHReview() error {
	return rem.Error{Code: "review_changed", Message: "refresh the proposal with current scoped observations"}
}
