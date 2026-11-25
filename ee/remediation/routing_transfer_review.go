// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
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
)

type routingTransferReviewStore interface {
	insertRoutingTransferReview(context.Context, string, rem.Proposal, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
	loadRoutingTransferReview(context.Context, string, string) (loadedRoutingTransferReview, error)
	approveRoutingTransferReview(context.Context, string, string, string, string, time.Time, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
}

type storedRoutingTransferReview struct {
	Version   int                       `json:"version"`
	Selection json.RawMessage           `json:"selection"`
	Scope     string                    `json:"scope"`
	Review    rem.RoutingTransferReview `json:"review"`
}

func (s *Service) ProposeRoutingTransfer(ctx context.Context, tenant, actor string, selection json.RawMessage,
	previewFingerprint, maxMoved string, prepare rem.RoutingTransferReviewPrepare) (rem.Proposal, error) {
	store, ok := s.store.(routingTransferReviewStore)
	if !ok || prepare == nil {
		return rem.Proposal{}, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return rem.Proposal{}, err
	}
	if !validRTBHDigest(previewFingerprint) || len(selection) == 0 || len(selection) > maxRTBHReviewBytes || !json.Valid(selection) {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "select the exact displayed routing transfer preview"}
	}
	preview, current, err := prepare(ctx, selection)
	if err != nil {
		return rem.Proposal{}, err
	}
	now := s.now().UTC()
	expires := routingTransferDeadline(now.Add(rtbhReviewLifetime), preview.SourceValidUntil)
	if preview.PreviewFingerprint != previewFingerprint || !expires.After(now) || current.Publish == nil ||
		!validRTBHDigest(current.Scope) || !hasRoutingTransferRollback(tenant, preview) {
		return rem.Proposal{}, changedRTBHReview()
	}
	blastRadius, err := s.routingTransferApprovalBound(preview, maxMoved)
	if err != nil {
		return rem.Proposal{}, err
	}
	stored := storedRoutingTransferReview{
		Version: 1, Selection: selection, Scope: current.Scope,
		Review: rem.RoutingTransferReview{Preview: preview, MaxMovedBPS: maxMoved, BlastRadius: blastRadius, ExpiresAt: expires.UTC()},
	}
	stored.Review.Fingerprint, err = routingTransferReviewFingerprint(tenant, stored)
	if err != nil {
		return rem.Proposal{}, err
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return rem.Proposal{}, err
	}
	proposal := rem.Proposal{
		Kind: rem.KindRoutingTransferReview, State: rem.StateProposed, ProposedBy: actor, ProposedUserID: user, CreatedAt: now,
		Title: "Review exact prefix routing transfer", Rationale: "Review a scoped upstream preference and its rollback.",
		Target: preview.ExactPrefix, DryRun: rem.DryRun{BlastRadius: blastRadius, ImpactedPrefixes: []string{preview.ExactPrefix}},
	}
	return store.insertRoutingTransferReview(ctx, tenant, proposal, raw, s.withRTBHExpiry(current, expires), s.audit,
		AuditEvent{Actor: actor, Action: "remediation.propose", Data: map[string]any{
			"kind": proposal.Kind, "proposer_user_id": user, "review_fingerprint": stored.Review.Fingerprint,
		}})
}

func (s *Service) GetRoutingTransfer(ctx context.Context, tenant, id string,
	prepare rem.RoutingTransferReviewPrepare) (rem.RoutingTransferReview, error) {
	var empty rem.RoutingTransferReview
	store, ok := s.store.(routingTransferReviewStore)
	if !ok || prepare == nil {
		return empty, unavailableRTBHReview()
	}
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return empty, err
	}
	loaded, err := store.loadRoutingTransferReview(ctx, tenant, id)
	if err != nil {
		return empty, err
	}
	if loaded.proposal.State != rem.StateProposed && loaded.proposal.State != rem.StateApproved {
		return empty, rem.ErrNotProposed
	}
	if loaded.withdrawn != nil {
		return empty, changedRTBHReview()
	}
	stored, err := decodeStoredRoutingTransferReview(tenant, loaded.review)
	if err != nil {
		return empty, err
	}
	if !s.now().Before(stored.Review.ExpiresAt) {
		return empty, changedRTBHReview()
	}
	preview, current, err := prepare(ctx, stored.Selection)
	if err != nil {
		return empty, err
	}
	validUntil := routingTransferDeadline(stored.Review.ExpiresAt, preview.SourceValidUntil)
	if preview.PreviewFingerprint != stored.Review.Preview.PreviewFingerprint || current.Scope != stored.Scope ||
		!s.now().Before(validUntil) {
		return empty, changedRTBHReview()
	}
	stored.Review.ValidUntil = validUntil
	if loaded.proposal.State == rem.StateApproved {
		decision, err := decodeRoutingTransferDecision(loaded, stored.Review.Fingerprint, validUntil)
		if err != nil {
			return empty, err
		}
		if !s.now().Before(decision.ValidUntil) {
			return empty, changedRTBHReview()
		}
		stored.Review.Decision = decision
		stored.Review.ValidUntil = decision.ValidUntil
	}
	return stored.Review, ctx.Err()
}

func (s *Service) ApproveRoutingTransfer(ctx context.Context, tenant, actor, id, fingerprint, note string,
	prepare rem.RoutingTransferReviewPrepare) (rem.Proposal, error) {
	if !s.approvalsEnabled {
		return rem.Proposal{}, rem.ErrApprovalsDisabled
	}
	store, ok := s.store.(routingTransferReviewStore)
	if !ok || prepare == nil {
		return rem.Proposal{}, unavailableRTBHReview()
	}
	user, err := remediationActor(ctx, tenant, true)
	if err != nil {
		return rem.Proposal{}, err
	}
	loaded, err := store.loadRoutingTransferReview(ctx, tenant, id)
	if err != nil {
		return rem.Proposal{}, err
	}
	proposal := loaded.proposal
	if err := s.checkRoutingTransferReviewer(ctx, tenant, actor, user, proposal); err != nil {
		return rem.Proposal{}, err
	}
	stored, err := decodeStoredRoutingTransferReview(tenant, loaded.review)
	if err != nil {
		return rem.Proposal{}, err
	}
	if fingerprint != stored.Review.Fingerprint || !s.now().Before(stored.Review.ExpiresAt) {
		return rem.Proposal{}, changedRTBHReview()
	}
	preview, current, err := prepare(ctx, stored.Selection)
	if err != nil {
		return rem.Proposal{}, err
	}
	expiry := routingTransferDeadline(stored.Review.ExpiresAt, preview.SourceValidUntil)
	if preview.PreviewFingerprint != stored.Review.Preview.PreviewFingerprint || current.Scope != stored.Scope ||
		current.Publish == nil || !s.now().Before(expiry) {
		return rem.Proposal{}, changedRTBHReview()
	}
	bound, err := s.routingTransferApprovalBound(preview, stored.Review.MaxMovedBPS)
	if err != nil {
		return rem.Proposal{}, err
	}
	if bound != stored.Review.BlastRadius || bound != proposal.DryRun.BlastRadius || preview.ExactPrefix != proposal.Target {
		return rem.Proposal{}, changedRTBHReview()
	}
	if preview.WeightVerification {
		return rem.Proposal{}, rem.Error{Code: "validation", Message: "the current policy requires observed best-path verification before approval"}
	}
	return store.approveRoutingTransferReview(ctx, tenant, id, actor, note, expiry, loaded.review, s.withRTBHExpiry(current, expiry), s.audit,
		AuditEvent{Data: map[string]any{"kind": proposal.Kind, "state": rem.StateApproved, "approver_user_id": user, "review_fingerprint": fingerprint, "note": note}})
}

func (s *Service) checkRoutingTransferReviewer(ctx context.Context, tenant, actor, user string, proposal rem.Proposal) error {
	if proposal.State != rem.StateProposed {
		return rem.ErrNotProposed
	}
	if proposal.ProposedUserID != "" && proposal.ProposedUserID != user {
		return nil
	}
	reason, refusal := "self_approval", rem.ErrSelfApproval
	if proposal.ProposedUserID == "" {
		reason, refusal = "proposer_identity_unavailable", rem.ErrProposerIdentityUnavailable
	}
	if err := s.record(ctx, tenant, actor, "remediation.approve_blocked", proposal.ID,
		map[string]any{"reason": reason, "approver_user_id": user}); err != nil {
		return err
	}
	return refusal
}

func (s *Service) routingTransferApprovalBound(preview rem.RoutingTransferDryRun, maxMoved string) (int, error) {
	const maxExactRateBytes = 256
	limit, ok := positiveRoutingTransferBPS(maxMoved, maxExactRateBytes)
	if !ok {
		return 0, rem.Error{Code: "validation", Message: "set the exact peak traffic limit for moving this prefix"}
	}
	measured, ok := positiveRoutingTransferBPS(preview.MovedPeakBPS, maxExactRateBytes)
	if !ok {
		return 0, rem.ErrUnknownBlastRadius
	}
	if measured.Cmp(limit) > 0 {
		return 0, rem.ErrBlastRadiusExceeded
	}
	return routingReviewBlastRadius(preview.ExactPrefix, preview.ExactPrefix, s.maxBlastRadius)
}

func decodeStoredRoutingTransferReview(tenant string, raw []byte) (storedRoutingTransferReview, error) {
	var stored storedRoutingTransferReview
	if json.Unmarshal(raw, &stored) != nil || stored.Version != 1 || stored.Review.Decision != nil ||
		!stored.Review.ValidUntil.IsZero() || !validRTBHDigest(stored.Review.Fingerprint) {
		return storedRoutingTransferReview{}, changedRTBHReview()
	}
	actual, err := routingTransferReviewFingerprint(tenant, stored)
	if err != nil || actual != stored.Review.Fingerprint {
		return storedRoutingTransferReview{}, changedRTBHReview()
	}
	return stored, nil
}

func routingTransferReviewFingerprint(tenant string, stored storedRoutingTransferReview) (string, error) {
	stored.Review.Fingerprint = ""
	// The exact selection binds the preview digest, while Postgres may
	// reorder the keys of its JSON representation between write and read.
	identity, err := json.Marshal(struct {
		Tenant  string                    `json:"tenant_id"`
		Version int                       `json:"version"`
		Scope   string                    `json:"scope"`
		Review  rem.RoutingTransferReview `json:"review"`
	}{tenant, stored.Version, stored.Scope, stored.Review})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(identity)), nil
}

func decodeRoutingTransferDecision(loaded loadedRoutingTransferReview, fingerprint string, currentExpiry time.Time) (*rem.RoutingTransferDecision, error) {
	var approval struct {
		Version     int       `json:"version"`
		Fingerprint string    `json:"review_fingerprint"`
		Approver    string    `json:"approved_by_user_id"`
		ApprovedAt  time.Time `json:"approved_at"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	p := loaded.proposal
	if err := json.Unmarshal(loaded.approval, &approval); err != nil {
		return nil, changedRTBHReview()
	}
	if approval.Version != 1 || fingerprint != approval.Fingerprint ||
		approval.Approver == "" || p.ProposedUserID == "" || p.ProposedUserID == approval.Approver ||
		p.DecidedAt == nil || !p.DecidedAt.Equal(approval.ApprovedAt) || p.DecidedBy == "" ||
		!approval.ExpiresAt.After(approval.ApprovedAt) {
		return nil, changedRTBHReview()
	}
	return &rem.RoutingTransferDecision{
		ApprovedBy: p.DecidedBy, ApprovedAt: approval.ApprovedAt,
		ValidUntil: routingTransferDeadline(currentExpiry, approval.ExpiresAt),
	}, nil
}

func routingTransferDeadline(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}
