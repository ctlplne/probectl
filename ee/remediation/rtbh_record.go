// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	rem "github.com/ctlplne/probectl/internal/remediation"
)

type storedRTBHReview struct {
	Version     int                   `json:"version"`
	Request     rem.RTBHProposalInput `json:"request"`
	Review      rem.RTBHReview        `json:"review"`
	SourceScope string                `json:"source_scope"`
}

func decodeStoredRTBHReview(raw []byte, memory int64) (storedRTBHReview, error) {
	var review, empty storedRTBHReview
	if len(raw) == 0 || int64(len(raw)) > memory {
		return empty, rem.ErrUnknownBlastRadius
	}
	reader := json.NewDecoder(bytes.NewReader(raw))
	reader.DisallowUnknownFields()
	if err := reader.Decode(&review); err != nil || reader.Decode(new(any)) != io.EOF || review.Version != 1 ||
		!validRTBHDigest(review.SourceScope) || !validRTBHDigest(review.Request.PreviewFingerprint) || review.Review.ExpiresAt.IsZero() ||
		!review.Review.Candidate.Impact.To.Equal(review.Request.ObservedTo) || !review.Request.ObservedTo.Before(review.Review.ExpiresAt) ||
		review.Review.Candidate.Announcement.Community != review.Request.Preview.Community ||
		!storedRTBHTemplateMatches(review.Request.Preview, review.Review.Candidate.UpstreamTemplate) ||
		review.Review.Candidate.Fingerprint != review.Request.PreviewFingerprint ||
		review.Review.MaxKnownBenignPackets != review.Request.MaxKnownBenignPackets {
		return empty, rem.ErrUnknownBlastRadius
	}
	if digest, err := rtbhReviewFingerprint(review.Review); err != nil || !validRTBHDigest(review.Review.Fingerprint) || digest != review.Review.Fingerprint {
		return empty, rem.ErrUnknownBlastRadius
	}
	return review, nil
}

func validateCurrentRTBHReview(stored storedRTBHReview, current rem.RTBHPreview, source string, now time.Time, maxBlastRadius int) error {
	if !now.Before(stored.Review.ExpiresAt) || current.Fingerprint != stored.Request.PreviewFingerprint || source != stored.SourceScope ||
		current.Announcement != stored.Review.Candidate.Announcement ||
		!current.Impact.From.Equal(stored.Review.Candidate.Impact.From) || !current.Impact.To.Equal(stored.Review.Candidate.Impact.To) {
		return rem.Error{Code: "review_changed", Message: "refresh the proposal with current scoped observations"}
	}
	bound, err := rtbhBlastRadius(current, maxBlastRadius)
	if err != nil {
		return err
	}
	current.Impact.From, current.Impact.To = stored.Review.Candidate.Impact.From, stored.Review.Candidate.Impact.To
	if bound != stored.Review.BlastRadius || current.Impact != stored.Review.Candidate.Impact {
		return rem.Error{Code: "review_changed", Message: "refresh the proposal with current scoped observations"}
	}
	return rtbhCollateralWithinLimit(current, stored.Review.MaxKnownBenignPackets)
}

func storedRTBHTemplateMatches(input rem.RTBHPreviewInput, template *rem.RTBHUpstreamTemplate) bool {
	if template == nil {
		return input.UpstreamTemplateID == ""
	}
	return template.ID != "" && template.ID == input.UpstreamTemplateID && template.Community == input.Community
}
