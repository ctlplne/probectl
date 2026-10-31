// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"

	"github.com/ctlplne/probectl/internal/auth"
)

// FlowQuestionPolicyPlanner rechecks current model consent before dispatch and
// before publishing a stateless proposal after pending model IO.
// This grants no source, native query or execution authority. Remote planners
// must use the same gate as the calling server, never a second policy source.
type FlowQuestionPolicyPlanner interface {
	FlowQuestionPlanner
	RevalidateFlowQuestion(context.Context, *EgressGate) error
}

var (
	_ FlowQuestionPolicyPlanner = (*BuiltinFlowQuestionPlanner)(nil)
	_ FlowQuestionPolicyPlanner = (*ModelFlowQuestionPlanner)(nil)
)

func (p *BuiltinFlowQuestionPlanner) RevalidateFlowQuestion(ctx context.Context, _ *EgressGate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.budget.Validate() != nil {
		return ErrFlowQuestionModelUnavailable
	}
	return nil // Offline planning performs no model egress.
}

func (p *ModelFlowQuestionPlanner) RevalidateFlowQuestion(ctx context.Context, shared *EgressGate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.completer == nil || p.completer.inner == nil {
		return ErrFlowQuestionModelUnavailable
	}
	remote, classified := p.completer.inner.(RemoteEgresser)
	if !classified {
		return ErrFlowQuestionModelUnavailable
	}
	if !remote.RemoteEgress() {
		return nil // Classified loopback/local inference keeps its exemption.
	}
	if shared == nil || p.completer.gate != shared {
		return ErrEgressAuditUnavailable
	}
	principal := auth.PrincipalFrom(ctx)
	if principal == nil || principal.TenantID == "" {
		return ErrNoTenant
	}
	// The gate records denials durably; successful policy reads are not new
	// remote calls. Actual dispatch still performs its own gate/audit/redaction.
	if err := shared.AuthorizeAttempt(ctx, EgressEvent{TenantID: principal.TenantID, Endpoint: remote.Endpoint(), Model: p.completer.inner.Name(), Surface: "flow_question"}); err != nil {
		return flowQuestionPlannerError(err)
	}
	return nil
}
