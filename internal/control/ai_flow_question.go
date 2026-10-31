// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
)

type flowQuestionResult struct {
	Proposal ai.FlowQuestionProposal `json:"proposal"`
}

// planFlowQuestion proposes configuration only. No conversation, telemetry read
// or saved query is created. Execution is a separate, fully authorized request.
// Transports own fairness admission, as they do for structured flow queries.
func (s *Server) planFlowQuestion(ctx context.Context, principal *auth.Principal, question string) (_ flowQuestionResult, operationErr error) {
	finish := s.beginFlowOperation(ctx, "plan")
	defer func() { finish(operationErr) }()
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return flowQuestionResult{}, err
	}
	if s.flowQuestionPlannerErr != nil || s.flowQuestionPlanner == nil {
		return flowQuestionResult{}, apierror.Unavailable("flow question planning is unavailable")
	}
	ctx = auth.WithPrincipal(ctx, principal)
	revalidate := func() error {
		if planner, ok := s.flowQuestionPlanner.(ai.FlowQuestionPolicyPlanner); ok {
			return planner.RevalidateFlowQuestion(ctx, s.egressGate)
		}
		return ctx.Err()
	}
	if err := revalidate(); err != nil {
		return flowQuestionResult{}, flowQuestionError(err)
	}
	zone, locale := principal.TimeZone, principal.Locale
	if strings.TrimSpace(zone) == "" {
		zone = principal.TenantTimeZone
	}
	if strings.TrimSpace(locale) == "" {
		locale = principal.TenantLocale
	}
	now := time.Now().UTC()
	proposal, err := s.flowQuestionPlanner.Plan(ctx, ai.FlowQuestionInput{Question: question, Now: now, TimeZone: zone, Locale: locale})
	if err != nil {
		return flowQuestionResult{}, flowQuestionError(err)
	}
	proposal, err = ai.NormalizeFlowQuestionProposal(proposal, now)
	if err != nil {
		return flowQuestionResult{}, flowQuestionError(err)
	}
	if err := revalidate(); err != nil {
		return flowQuestionResult{}, flowQuestionError(err)
	}
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return flowQuestionResult{}, err
	}
	if proposal.Plan != nil {
		if err := s.authorizeFlowMetadata(ctx, principal, *proposal.Plan); err != nil {
			return flowQuestionResult{}, err
		}
	}
	return flowQuestionResult{Proposal: proposal}, nil
}

func flowQuestionError(err error) error {
	switch {
	case errors.Is(err, ai.ErrFlowQuestionBudget):
		return apierror.Validation("flow question exceeds the operator planning resource budget")
	case errors.Is(err, ai.ErrFlowQuestionInput):
		return apierror.Validation("flow question is empty or malformed")
	case errors.Is(err, ai.ErrEgressDenied):
		return apierror.Forbidden("external AI consent is required for the configured model")
	default:
		return apierror.Unavailable("flow question planning is unavailable; retry or use the structured builder")
	}
}

// BuildFlowQuestionPlanner constructs a plan-only component, without a store
// or tool executor. Its calling service must authorize the explicit context
// and validate current tenant/source/retention/credential authority separately.
func BuildFlowQuestionPlanner(cfg *config.Config, log *slog.Logger, gate *ai.EgressGate) (ai.FlowQuestionPlanner, error) {
	question, completion, err := configuredFlowQuestionBudgets(cfg)
	if err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.AIModelEnabled() {
		return ai.NewBuiltinFlowQuestionPlanner(question)
	}
	if log == nil {
		log = slog.Default()
	}
	model, ok := buildModel(cfg, log).(ai.BudgetedRemoteCompleter)
	if !ok {
		return nil, ai.ErrFlowQuestionModelUnavailable
	}
	return ai.NewModelFlowQuestionPlanner(ai.NewGatedCompleter(model, gate), question, completion)
}

func configuredFlowQuestionBudgets(cfg *config.Config) (ai.FlowQuestionBudget, ai.CompletionBudget, error) {
	question, completion := ai.DefaultFlowQuestionBudget(), ai.DefaultCompletionBudget()
	if cfg != nil {
		for _, setting := range []struct {
			value  int
			target *int
		}{
			{cfg.FlowQuestionMaxBytes, &question.Bytes},
			{cfg.FlowQuestionMaxTokens, &question.Tokens},
			{cfg.FlowQuestionMaxNesting, &question.Nesting},
			{cfg.FlowQuestionModelOutputTokens, &completion.OutputTokens},
		} {
			if setting.value != 0 {
				*setting.target = setting.value
			}
		}
		if cfg.FlowQuestionModelResponseBytes != 0 {
			completion.ResponseBytes = int64(cfg.FlowQuestionModelResponseBytes)
		}
		if cfg.FlowQuestionModelTokenParameter != "" {
			completion.OpenAITokenParameter = cfg.FlowQuestionModelTokenParameter
		}
	}
	if question.Validate() != nil || completion.Validate() != nil {
		return ai.FlowQuestionBudget{}, ai.CompletionBudget{}, ai.ErrFlowQuestionBudget
	}
	return question, completion, nil
}
