// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"encoding/json"
	"time"
)

const KindRoutingTransferReview Kind = "routing_transfer_review"

// RoutingTransferReviewPrepare resolves the stored selection through the
// current actor's financial, routing, and device authority. Its publication
// callback must recheck that authority and fence changes to the evidence in
// the same tenant transaction as the decision and audit append.
type RoutingTransferReviewPrepare func(context.Context, json.RawMessage) (RoutingTransferDryRun, RTBHImpactPublication, error)

type RoutingTransferReview struct {
	Preview     RoutingTransferDryRun    `json:"preview"`
	MaxMovedBPS string                   `json:"max_moved_bps"`
	BlastRadius int                      `json:"blast_radius"`
	ExpiresAt   time.Time                `json:"expires_at"`
	ValidUntil  time.Time                `json:"valid_until,omitzero"` // Calculated for this read, outside the stored review.
	Fingerprint string                   `json:"fingerprint"`
	Decision    *RoutingTransferDecision `json:"decision,omitempty"`
}

// RoutingTransferDecision records the current human decision for the exact
// review. The existing preview response contains the policy and rollback.
type RoutingTransferDecision struct {
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
	ValidUntil time.Time `json:"valid_until"`
}

type RoutingTransferReviewService interface {
	ProposeRoutingTransfer(context.Context, string, string, json.RawMessage, string, string, RoutingTransferReviewPrepare) (Proposal, error)
	GetRoutingTransfer(context.Context, string, string, RoutingTransferReviewPrepare) (RoutingTransferReview, error)
	ApproveRoutingTransfer(context.Context, string, string, string, string, string, RoutingTransferReviewPrepare) (Proposal, error)
}
