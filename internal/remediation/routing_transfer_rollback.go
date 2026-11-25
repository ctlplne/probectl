// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type RoutingTransferRollbackState string

const (
	RoutingTransferApprovalActive      RoutingTransferRollbackState = "approval_active"
	RoutingTransferApprovalExpired     RoutingTransferRollbackState = "approval_expired"
	RoutingTransferWithdrawalRequested RoutingTransferRollbackState = "withdrawal_requested"
)

// RoutingTransferRollback contains the approved rollback. State describes
// the approval and operator intent. Router state needs independent evidence.
type RoutingTransferRollback struct {
	ProposalID        string                       `json:"proposal_id"`
	Fingerprint       string                       `json:"review_fingerprint"`
	ContextID         string                       `json:"context_id"`
	RouterID          string                       `json:"router_id"`
	ExactPrefix       string                       `json:"exact_prefix"`
	CandidatePeer     string                       `json:"candidate_peer"`
	RestorePolicy     string                       `json:"restore_policy"`
	RemovePolicy      string                       `json:"remove_policy"`
	ApprovedAt        time.Time                    `json:"approved_at"`
	ApprovalExpiresAt time.Time                    `json:"approval_expires_at"`
	WithdrawRequested *time.Time                   `json:"withdraw_requested_at,omitempty"`
	State             RoutingTransferRollbackState `json:"state"`
	Withdraw          []string                     `json:"withdraw"`
}

func (r RoutingTransferRollback) StateAt(now time.Time) RoutingTransferRollbackState {
	switch {
	case r.WithdrawRequested != nil:
		return RoutingTransferWithdrawalRequested
	case !now.Before(r.ApprovalExpiresAt):
		return RoutingTransferApprovalExpired
	default:
		return RoutingTransferApprovalActive
	}
}

// RoutingTransferRollbackAuthorizer runs on the same tenant storage
// scope that loaded the immutable approval or records withdrawal intent.
type RoutingTransferRollbackAuthorizer func(ctx context.Context, scope tenancy.Scope, contextID, routerID string, source entity.SourceKey) error

type RoutingTransferRollbackService interface {
	GetRoutingTransferRollback(context.Context, string, string, RoutingTransferRollbackAuthorizer) (RoutingTransferRollback, error)
	RequestRoutingTransferWithdrawal(context.Context, string, string, string, string, RoutingTransferRollbackAuthorizer) (RoutingTransferRollback, error)
}
