// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// RTBHProposalInput binds the displayed preview to an operator-selected limit
// for the known benign traffic. Approval sees the same evidence and limit.
type RTBHProposalInput struct {
	Preview               RTBHPreviewInput `json:"preview"`
	ObservedTo            time.Time        `json:"observed_to"`
	PreviewFingerprint    string           `json:"preview_fingerprint"`
	MaxKnownBenignPackets string           `json:"max_known_benign_packets"`
}

type RTBHReview struct {
	Candidate             RTBHPreview `json:"candidate"`
	MaxKnownBenignPackets string      `json:"max_known_benign_packets"`
	BlastRadius           int         `json:"blast_radius"`
	ExpiresAt             time.Time   `json:"expires_at"`
	Fingerprint           string      `json:"review_fingerprint"`
}

// RTBHImpactPublication carries structured evidence and bounded lineage. The
// callback keeps the source fences held for the audited proposal mutation.
type RTBHImpactPublication struct {
	Impact     PrefixImpact
	WholeScope *PrefixImpact
	Scope      string
	Publish    func(context.Context, tenancy.Scope, string, func(context.Context, tenancy.Scope) error) error
}

type RTBHReviewSource interface {
	PreparePrefixImpact(context.Context, string, PrefixImpactInput, time.Time, func(context.Context) error) (RTBHImpactPublication, error)
}

type FlowSpecReviewSource interface {
	PrepareFlowSpecImpact(context.Context, string, PrefixImpactInput, FlowSpecTransport, time.Time, func(context.Context) error) (RTBHImpactPublication, error)
}

type FlowSpecPreviewInput struct {
	PrefixImpactInput
	Transport           FlowSpecTransport `json:"transport"`
	RoutingPolicyAgreed bool              `json:"routing_policy_agreed"`
}

type FlowSpecCandidate struct {
	Family      string            `json:"family"`
	Destination string            `json:"destination"`
	Transport   FlowSpecTransport `json:"transport"`
	Action      string            `json:"action"`
}

type FlowSpecPreview struct {
	Candidate   FlowSpecCandidate `json:"candidate"`
	Matching    PrefixImpact      `json:"matching"`
	WholeScope  PrefixImpact      `json:"whole_scope"`
	Fingerprint string            `json:"preview_fingerprint,omitempty"`
}

type FlowSpecPreviewer interface {
	PreviewFlowSpec(context.Context, string, FlowSpecPreviewInput, func(context.Context) error) (FlowSpecPreview, error)
}

type FlowSpecProposalInput struct {
	Preview               FlowSpecPreviewInput `json:"preview"`
	ObservedTo            time.Time            `json:"observed_to"`
	PreviewFingerprint    string               `json:"preview_fingerprint"`
	MaxKnownBenignPackets string               `json:"max_known_benign_packets"`
}

type FlowSpecReview struct {
	Proposal              FlowSpecPreview `json:"proposal"`
	MaxKnownBenignPackets string          `json:"max_known_benign_packets"`
	BlastRadius           int             `json:"blast_radius"`
	ExpiresAt             time.Time       `json:"expires_at"`
	Fingerprint           string          `json:"review_fingerprint"`
}

type FlowSpecReviews interface {
	ProposeFlowSpec(context.Context, string, string, FlowSpecProposalInput, func(context.Context) error) (Proposal, error)
	GetFlowSpecReview(context.Context, string, string, func(context.Context) error) (FlowSpecReview, error)
	QualifyFlowSpec(context.Context, string, string, FlowSpecQualificationInput, func(context.Context) error) (FlowSpecQualification, error)
	ApproveFlowSpec(context.Context, string, string, string, string, string, func(context.Context) error) (Proposal, error)
}

type RTBHReviews interface {
	ProposeRTBH(context.Context, string, string, RTBHProposalInput, func(context.Context) error) (Proposal, error)
	GetRTBHReview(context.Context, string, string, func(context.Context) error) (RTBHReview, error)
	ApproveRTBH(context.Context, string, string, string, string, string, func(context.Context) error) (Proposal, error)
}
