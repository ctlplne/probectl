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

const maxFlowSpecHandoffBytes = 16 << 10

type storedFlowSpecHandoff struct {
	Version int                 `json:"version"`
	Handoff rem.FlowSpecHandoff `json:"handoff"`
}

func digestFlowSpecQualification(result rem.FlowSpecQualification) (string, error) {
	result.QualificationFingerprint = ""
	exact, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(exact)), nil
}

func prepareFlowSpecHandoff(id string, review rem.FlowSpecReview, input *rem.FlowSpecHandoffInput, at time.Time) ([]byte, error) {
	if input == nil {
		return nil, nil
	}
	const maxSeconds = int(rtbhReviewLifetime / time.Second)
	if input.DurationSeconds < 1 || input.DurationSeconds > maxSeconds || !validRTBHDigest(input.QualificationFingerprint) {
		return nil, rem.Error{Code: "validation", Message: "choose the exact router qualification and its authorized duration"}
	}
	end := at.Add(time.Duration(input.DurationSeconds) * time.Second)
	if !at.Before(review.ExpiresAt) || end.After(review.ExpiresAt) {
		return nil, rem.Error{Code: "review_changed", Message: "choose an expiry inside the current review window"}
	}
	qualification, err := qualifyFlowSpec(review, input.Qualification)
	if err != nil {
		return nil, err
	}
	if !qualification.SyntaxCompatible || qualification.Template == nil ||
		qualification.Capacity.FitsDeclared == nil || !*qualification.Capacity.FitsDeclared {
		return nil, rem.Error{Code: "validation", Message: "the current router profile and declared capacity must admit the exact rule"}
	}
	fingerprint, err := digestFlowSpecQualification(qualification)
	if err != nil {
		return nil, err
	}
	if fingerprint != input.QualificationFingerprint {
		return nil, changedRTBHReview()
	}
	qualification.QualificationFingerprint = fingerprint
	return json.Marshal(storedFlowSpecHandoff{Version: 1, Handoff: rem.FlowSpecHandoff{
		ProposalID: id, ReviewFingerprint: review.Fingerprint, Qualification: qualification,
		IssuedAt: at.UTC(), ExpiresAt: end.UTC(),
	}})
}

func decodeFlowSpecHandoff(id string, raw []byte) (rem.FlowSpecHandoff, error) {
	var handoff storedFlowSpecHandoff
	if len(raw) == 0 || len(raw) > maxFlowSpecHandoffBytes {
		return rem.FlowSpecHandoff{}, rem.ErrUnknownBlastRadius
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&handoff); err != nil || decoder.Decode(new(any)) != io.EOF || handoff.Version != 1 {
		return rem.FlowSpecHandoff{}, rem.ErrUnknownBlastRadius
	}
	out := handoff.Handoff
	if out.ProposalID != id || !validRTBHDigest(out.ReviewFingerprint) || out.Qualification.ReviewFingerprint != out.ReviewFingerprint ||
		out.IssuedAt.IsZero() || !out.IssuedAt.Before(out.ExpiresAt) || out.ExpiresAt.Sub(out.IssuedAt) > rtbhReviewLifetime ||
		!out.Qualification.SyntaxCompatible || out.Qualification.Template == nil ||
		out.Qualification.Capacity.FitsDeclared == nil || !*out.Qualification.Capacity.FitsDeclared ||
		out.WithdrawRequested != nil {
		return rem.FlowSpecHandoff{}, rem.ErrUnknownBlastRadius
	}
	digest, err := digestFlowSpecQualification(out.Qualification)
	if err != nil || digest != out.Qualification.QualificationFingerprint {
		return rem.FlowSpecHandoff{}, rem.ErrUnknownBlastRadius
	}
	return out, nil
}

func (s *Service) GetFlowSpecHandoff(ctx context.Context, tenant, id string, check func(context.Context) error) (rem.FlowSpecHandoffStatus, error) {
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	store, ok := s.store.(flowSpecHandoffStore)
	if !ok || check == nil {
		return rem.FlowSpecHandoffStatus{}, unavailableRTBHReview()
	}
	if err := check(ctx); err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	out, err := store.LoadFlowSpecHandoff(ctx, tenant, id)
	if err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	if err := check(ctx); err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	return rem.FlowSpecHandoffStatus{FlowSpecHandoff: out, State: out.State(s.now().UTC())}, ctx.Err()
}

func (s *Service) WithdrawFlowSpecHandoff(ctx context.Context, tenant, actor, id string, publication rem.RTBHImpactPublication) (rem.FlowSpecHandoffStatus, error) {
	if _, err := remediationActor(ctx, tenant, true); err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	store, ok := s.store.(flowSpecHandoffStore)
	if !ok || publication.Publish == nil {
		return rem.FlowSpecHandoffStatus{}, unavailableRTBHReview()
	}
	out, err := store.RequestFlowSpecWithdrawal(ctx, tenant, actor, id, s.now().UTC(), publication, s.audit)
	if err != nil {
		return rem.FlowSpecHandoffStatus{}, err
	}
	return rem.FlowSpecHandoffStatus{FlowSpecHandoff: out, State: out.State(s.now().UTC())}, ctx.Err()
}
