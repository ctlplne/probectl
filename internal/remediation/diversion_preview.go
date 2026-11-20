// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"time"
)

const KindDiversionPreview Kind = "diversion_preview"
const LocalDiversionPreview = "local_preview"

type DiversionAction string

const (
	DiversionStart DiversionAction = "start"
	DiversionStop  DiversionAction = "stop"
)

// DiversionPreviewInput selects either a current protected observation or a
// single previously approved local preview. The source fixes the tenant and prefix.
type DiversionPreviewInput struct {
	Action         DiversionAction    `json:"action"`
	Observation    *PrefixImpactInput `json:"observation,omitempty"`
	StartPreviewID string             `json:"start_preview_id,omitempty"`
}

type DiversionPreview struct {
	Connector      string          `json:"connector"`
	Action         DiversionAction `json:"action"`
	Prefix         string          `json:"prefix"`
	Impact         *PrefixImpact   `json:"impact,omitempty"`
	StartPreviewID string          `json:"start_preview_id,omitempty"`
	Fingerprint    string          `json:"preview_fingerprint"`
}

type DiversionProposalInput struct {
	Selection             DiversionPreviewInput `json:"selection"`
	ObservedTo            *time.Time            `json:"observed_to,omitempty"`
	PreviewFingerprint    string                `json:"preview_fingerprint"`
	MaxKnownBenignPackets string                `json:"max_known_benign_packets,omitempty"`
}

type DiversionReview struct {
	Candidate             DiversionPreview  `json:"candidate"`
	MaxKnownBenignPackets string            `json:"max_known_benign_packets,omitempty"`
	BlastRadius           int               `json:"blast_radius"`
	ExpiresAt             time.Time         `json:"expires_at"`
	Fingerprint           string            `json:"review_fingerprint"`
	Receipt               *DiversionReceipt `json:"receipt,omitempty"`
	StartStoppedAt        *time.Time        `json:"start_stopped_at,omitempty"`
}

type DiversionApprovalInput struct {
	Fingerprint string `json:"review_fingerprint"`
	Note        string `json:"note"`
}

// DiversionReceipt describes the result of a local preview. StartPreviewID
// is also the stable handle a later stop is allowed to refer to.
type DiversionReceipt struct {
	Connector      string          `json:"connector"`
	Action         DiversionAction `json:"action"`
	Prefix         string          `json:"prefix"`
	StartPreviewID string          `json:"start_preview_id"`
	RecordedAt     time.Time       `json:"recorded_at"`
}

type DiversionReviews interface {
	PreviewDiversion(context.Context, string, DiversionPreviewInput, func(context.Context) error) (DiversionPreview, error)
	ProposeDiversion(context.Context, string, string, DiversionProposalInput, func(context.Context) error, RTBHImpactPublication) (Proposal, error)
	GetDiversionReview(context.Context, string, string, func(context.Context) error) (DiversionReview, error)
	ApproveDiversion(context.Context, string, string, string, DiversionApprovalInput, func(context.Context) error, RTBHImpactPublication) (DiversionReceipt, error)
}
