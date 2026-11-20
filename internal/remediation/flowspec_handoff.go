// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import "time"

type FlowSpecApprovalInput struct {
	Fingerprint string                `json:"review_fingerprint"`
	Note        string                `json:"note"`
	Handoff     *FlowSpecHandoffInput `json:"handoff,omitempty"`
}

type FlowSpecHandoffInput struct {
	Qualification            FlowSpecQualificationInput `json:"qualification"`
	QualificationFingerprint string                     `json:"qualification_fingerprint"`
	DurationSeconds          int                        `json:"duration_seconds"`
}

type FlowSpecHandoffState string

const (
	FlowSpecAuthorized          FlowSpecHandoffState = "authorized"
	FlowSpecWithdrawalRequested FlowSpecHandoffState = "withdrawal_requested"
	FlowSpecExpired             FlowSpecHandoffState = "expired"
)

type FlowSpecHandoff struct {
	ProposalID        string                `json:"proposal_id"`
	ReviewFingerprint string                `json:"review_fingerprint"`
	Qualification     FlowSpecQualification `json:"qualification"`
	IssuedAt          time.Time             `json:"issued_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
	WithdrawRequested *time.Time            `json:"withdraw_requested_at,omitempty"`
}

// State reports authorization and withdrawal intent. A separate receiver
// observation is required before the workflow can report removal.
func (h FlowSpecHandoff) State(now time.Time) FlowSpecHandoffState {
	switch {
	case h.WithdrawRequested != nil:
		return FlowSpecWithdrawalRequested
	case !now.Before(h.ExpiresAt):
		return FlowSpecExpired
	default:
		return FlowSpecAuthorized
	}
}

type FlowSpecHandoffStatus struct {
	FlowSpecHandoff
	State FlowSpecHandoffState `json:"state"`
}
