// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/flow"
)

var ErrFlowQuestionModelUnavailable = errors.New("flow question model is temporarily unavailable")

// ModelFlowQuestionPlanner has no source/backend/tool capability. Its only
// completion door is the existing tenant-consent/redaction/durable-audit gate;
// it validates the entire response as native grammar before returning a plan.
type ModelFlowQuestionPlanner struct {
	completer  *GatedCompleter
	budget     FlowQuestionBudget
	system     string
	completion CompletionBudget
	native     *BuiltinFlowQuestionPlanner
}

var _ FlowQuestionPlanner = (*ModelFlowQuestionPlanner)(nil)

func NewModelFlowQuestionPlanner(completer *GatedCompleter, budget FlowQuestionBudget, policies ...CompletionBudget) (*ModelFlowQuestionPlanner, error) {
	if budget.Validate() != nil {
		return nil, ErrFlowQuestionBudget
	}
	if completer == nil || completer.inner == nil {
		return nil, ErrFlowQuestionModelUnavailable
	}
	inner := reflect.ValueOf(completer.inner)
	switch inner.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if inner.IsNil() {
			return nil, ErrFlowQuestionModelUnavailable
		}
	}
	if _, classified := completer.inner.(RemoteEgresser); !classified {
		return nil, ErrFlowQuestionModelUnavailable
	}
	if _, bounded := completer.inner.(BudgetedRemoteCompleter); !bounded {
		return nil, ErrFlowQuestionModelUnavailable
	}
	completion := DefaultCompletionBudget()
	if len(policies) > 1 {
		return nil, ErrFlowQuestionBudget
	}
	if len(policies) == 1 {
		completion = policies[0]
	}
	if err := completion.Validate(); err != nil {
		return nil, ErrFlowQuestionBudget
	}
	system, err := flowQuestionSystemPrompt()
	if err != nil {
		return nil, err
	}
	if len(system) > budget.Bytes {
		return nil, ErrFlowQuestionBudget
	}
	native, err := NewBuiltinFlowQuestionPlanner(budget)
	if err != nil {
		return nil, err
	}
	return &ModelFlowQuestionPlanner{completer: completer, budget: budget, system: system, completion: completion, native: native}, nil
}

func (p *ModelFlowQuestionPlanner) Plan(ctx context.Context, input FlowQuestionInput) (FlowQuestionProposal, error) {
	if err := ctx.Err(); err != nil {
		return FlowQuestionProposal{}, err
	}
	if p == nil || p.completer == nil || p.native == nil {
		return FlowQuestionProposal{}, ErrFlowQuestionModelUnavailable
	}
	if p.budget.Validate() != nil || len(input.Question) > p.budget.Bytes {
		return FlowQuestionProposal{}, ErrFlowQuestionBudget
	}
	if input.Now.IsZero() || strings.TrimSpace(input.Question) == "" || !utf8.ValidString(input.Question) || !utf8.ValidString(input.Locale) {
		return FlowQuestionProposal{}, ErrFlowQuestionInput
	}
	location, err := questionLocation(input.TimeZone)
	if err != nil {
		return FlowQuestionProposal{}, ErrFlowQuestionInput
	}
	remaining := p.budget.Bytes - len(p.system) - len(input.Question) - len(input.Locale) - len(input.TimeZone)
	if err := questionParentCost(ctx, input.Parent, p.budget, remaining); err != nil {
		return FlowQuestionProposal{}, err
	}
	var parent *FlowQuestionProposal
	if input.Parent != nil {
		normal, err := NormalizeFlowQuestionProposal(*input.Parent, input.Now)
		if err != nil || normal.Status != FlowQuestionReady {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
		parent = &normal
	}
	modelContext, err := p.modelContext(ctx, input, parent, location)
	if callerErr := ctx.Err(); callerErr != nil {
		return FlowQuestionProposal{}, callerErr
	}
	if modelContext.refused != nil {
		return *modelContext.refused, nil
	}
	if errors.Is(err, errQuestionContextUnresolved) {
		if modelContext.expected != nil {
			local := *modelContext.expected
			local.Assumptions = append(local.Assumptions, "The complete offline native parser preserved protected context; no model call was made.")
			return local, nil
		}
		return questionProtectedClarification(), nil
	}
	if err != nil {
		return FlowQuestionProposal{}, flowQuestionPlannerError(err)
	}
	raw, err := p.completer.completeWithBudget(ctx, p.system, modelContext.user, "flow_question", p.completion)
	if callerErr := ctx.Err(); callerErr != nil {
		return FlowQuestionProposal{}, callerErr
	}
	if err != nil {
		return FlowQuestionProposal{}, flowQuestionPlannerError(err)
	}

	proposal, err := decodeFlowQuestionProposalWithLiterals(ctx, raw, p.budget, input.Now, modelContext.literals)
	if callerErr := ctx.Err(); callerErr != nil {
		return FlowQuestionProposal{}, callerErr
	}
	if errors.Is(err, errQuestionLiteralMissing) || errors.Is(err, errQuestionLiteralSurrogate) {
		return questionProtectedClarification(), nil
	}
	if err != nil {
		return FlowQuestionProposal{}, err
	}
	if proposal.Plan != nil && modelMaskedSavedFilters(proposal.Plan.Filter) {
		return questionProtectedClarification(), nil
	}
	if proposal.Status == FlowQuestionReady {
		proposal.NeedsConfirmation = !questionModelIntentMatches(proposal, modelContext.expected) || modelContext.expected.NeedsConfirmation
	}
	if callerErr := ctx.Err(); callerErr != nil {
		return FlowQuestionProposal{}, callerErr
	}
	return proposal, nil
}

func flowQuestionPlannerError(err error) error {
	if errors.Is(err, ErrModelCompletionBudget) {
		return ErrFlowQuestionBudget
	}
	if errors.Is(err, ErrModelCompletionIncomplete) {
		return ErrFlowQuestionPlan
	}
	for _, safe := range []error{context.Canceled, context.DeadlineExceeded, ErrNoTenant, ErrEgressDenied, ErrEgressAuditUnavailable, ErrFlowQuestionBudget, ErrFlowQuestionInput, ErrFlowQuestionPlan, ErrFlowQuestionModelUnavailable} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrFlowQuestionModelUnavailable
}

var modelRedactionToken = regexp.MustCompile(`\[(?:secret|pan|ssn|ip|email|mac|phone|host|custom):[0-9a-f]{32}\]`)

func questionProtectedClarification() FlowQuestionProposal {
	return FlowQuestionProposal{Status: FlowQuestionClarify, Guidance: "Specify the protected filter context explicitly; unresolved, missing or surrogate values are not executed."}
}

func modelMaskedSavedFilters(group *flow.QueryFilterGroup) bool {
	if group == nil {
		return false
	}
	for _, saved := range group.Saved {
		if modelRedactionToken.MatchString(saved.ID) || strings.Contains(saved.ID, questionLiteralPrefix) {
			return true
		}
	}
	for _, child := range group.Groups {
		if modelMaskedSavedFilters(&child) {
			return true
		}
	}
	return false
}

// Bound parent source bytes/nodes before normalization copies or JSON encoding.
// The encoded envelope is checked again afterward; no history is truncated.
func questionParentCost(ctx context.Context, parent *FlowQuestionProposal, budget FlowQuestionBudget, remaining int) error {
	if remaining < 0 {
		return ErrFlowQuestionBudget
	}
	nodes := 0
	var visit func(reflect.Value, int) error
	visit = func(value reflect.Value, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > budget.Nesting || nodes >= budget.Tokens {
			return ErrFlowQuestionBudget
		}
		nodes++
		for value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return nil
			}
			value = value.Elem()
		}
		if value.Type() == reflect.TypeFor[time.Time]() {
			return nil
		}
		switch value.Kind() {
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				if err := visit(value.Field(index), depth+1); err != nil {
					return err
				}
			}
		case reflect.Slice, reflect.Array:
			for index := 0; index < value.Len(); index++ {
				if err := visit(value.Index(index), depth+1); err != nil {
					return err
				}
			}
		case reflect.String:
			if value.Len() > remaining {
				return ErrFlowQuestionBudget
			}
			remaining -= value.Len()
		}
		return nil
	}
	return visit(reflect.ValueOf(parent), 0)
}
