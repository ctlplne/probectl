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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	rem "github.com/ctlplne/probectl/internal/remediation"
)

const maxDiversionReviewBytes = 32 << 10

type storedDiversionReview struct {
	Version   int                       `json:"version"`
	Selection rem.DiversionPreviewInput `json:"selection"`
	Scope     string                    `json:"source_scope"`
	Review    rem.DiversionReview       `json:"review"`
}

type diversionStore interface {
	ActiveDiversionStart(context.Context, string, string) (rem.DiversionReceipt, error)
	InsertDiversionAudited(context.Context, string, rem.Proposal, []byte, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.Proposal, error)
	loadDiversionReview(context.Context, string, string) (loadedDiversionReview, error)
	ApproveDiversionAudited(context.Context, string, string, string, string, time.Time, []byte, rem.DiversionPreview, rem.RTBHImpactPublication, AuditSink, AuditEvent) (rem.DiversionReceipt, error)
}

func (s *Service) PreviewDiversion(ctx context.Context, tenant string, selection rem.DiversionPreviewInput, check func(context.Context) error) (rem.DiversionPreview, error) {
	preview, _, err := s.prepareDiversion(ctx, tenant, selection, time.Time{}, check)
	return preview, err
}

func (s *Service) prepareDiversion(ctx context.Context, tenant string, selection rem.DiversionPreviewInput, observedTo time.Time, check func(context.Context) error) (rem.DiversionPreview, rem.RTBHImpactPublication, error) {
	preview := rem.DiversionPreview{Connector: rem.LocalDiversionPreview, Action: selection.Action}
	var prepared rem.RTBHImpactPublication
	if _, err := remediationActor(ctx, tenant, false); err != nil {
		return rem.DiversionPreview{}, prepared, err
	}
	if check == nil {
		return rem.DiversionPreview{}, prepared, unavailableRTBHReview()
	}
	if err := check(ctx); err != nil {
		return rem.DiversionPreview{}, prepared, err
	}
	switch selection.Action {
	case rem.DiversionStart:
		if selection.Observation == nil || selection.StartPreviewID != "" {
			return rem.DiversionPreview{}, prepared, rem.Error{Code: "validation", Message: "select a current protected traffic observation"}
		}
		var err error
		prepared, err = s.prepareDiversionImpact(ctx, tenant, *selection.Observation, observedTo, check)
		if err != nil {
			return rem.DiversionPreview{}, prepared, err
		}
		preview.Prefix, preview.Impact = prepared.Impact.Prefix, &prepared.Impact
	case rem.DiversionStop:
		store, ok := s.store.(diversionStore)
		if !ok {
			return rem.DiversionPreview{}, prepared, unavailableRTBHReview()
		}
		id, err := uuid.Parse(selection.StartPreviewID)
		if selection.Observation != nil || !observedTo.IsZero() || err != nil || id == uuid.Nil || id.String() != selection.StartPreviewID {
			return rem.DiversionPreview{}, prepared, rem.Error{Code: "validation", Message: "select the exact approved local start preview"}
		}
		receipt, err := store.ActiveDiversionStart(ctx, tenant, selection.StartPreviewID)
		if err != nil {
			return rem.DiversionPreview{}, prepared, err
		}
		preview.Prefix, preview.StartPreviewID = receipt.Prefix, receipt.StartPreviewID
		if prepared.Scope, err = diversionReviewDigest(receipt); err != nil {
			return rem.DiversionPreview{}, prepared, err
		}
	default:
		return rem.DiversionPreview{}, prepared, rem.Error{Code: "validation", Message: "choose start or stop diversion preview"}
	}
	fingerprint, err := diversionReviewDigest(struct {
		Version   int                       `json:"version"`
		Tenant    string                    `json:"tenant_id"`
		Selection rem.DiversionPreviewInput `json:"selection"`
		Preview   rem.DiversionPreview      `json:"preview"`
		Scope     string                    `json:"source_scope"`
	}{1, tenant, selection, preview, prepared.Scope})
	if err != nil {
		return rem.DiversionPreview{}, prepared, err
	}
	preview.Fingerprint = fingerprint
	return preview, prepared, check(ctx)
}

func (s *Service) prepareDiversionImpact(ctx context.Context, tenant string, selection rem.PrefixImpactInput, observedTo time.Time, check func(context.Context) error) (rem.RTBHImpactPublication, error) {
	source, ok := s.prefixImpact.(rem.RTBHReviewSource)
	if !ok {
		return rem.RTBHImpactPublication{}, unavailableRTBHReview()
	}
	prepared, err := source.PreparePrefixImpact(ctx, tenant, selection, observedTo, check)
	if err != nil {
		return prepared, err
	}
	prepared.Impact.From, prepared.Impact.To = prepared.Impact.From.UTC(), prepared.Impact.To.UTC()
	now := s.now().UTC()
	if !validRTBHDigest(prepared.Scope) || prepared.Publish == nil || prepared.Impact.To.IsZero() || prepared.Impact.To.After(now) ||
		!now.Before(prepared.Impact.To.Add(rtbhReviewLifetime)) || (!observedTo.IsZero() && !observedTo.Equal(prepared.Impact.To)) {
		return prepared, changedRTBHReview()
	}
	return prepared, nil
}

func diversionReviewDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(payload)), nil
}

func decodeDiversionReview(raw []byte) (storedDiversionReview, error) {
	var out storedDiversionReview
	if len(raw) == 0 || len(raw) > maxDiversionReviewBytes {
		return out, rem.ErrUnknownBlastRadius
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil || decoder.Decode(new(any)) != io.EOF || out.Version != 1 ||
		!validRTBHDigest(out.Scope) || out.Review.Receipt != nil || out.Review.StartStoppedAt != nil || out.Review.ExpiresAt.IsZero() ||
		out.Review.Candidate.Connector != rem.LocalDiversionPreview || out.Selection.Action != out.Review.Candidate.Action {
		return storedDiversionReview{}, rem.ErrUnknownBlastRadius
	}
	fingerprint := out.Review.Fingerprint
	out.Review.Fingerprint = ""
	expected, err := diversionReviewDigest(out)
	if err != nil || expected != fingerprint {
		return storedDiversionReview{}, rem.ErrUnknownBlastRadius
	}
	out.Review.Fingerprint = fingerprint
	return out, nil
}
