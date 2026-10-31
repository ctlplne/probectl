// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/flow"
)

var (
	ErrFlowQuestionBudget = errors.New("flow question exceeds operator planning resource budget")
	ErrFlowQuestionInput  = errors.New("flow question is empty or malformed")
	ErrFlowQuestionPlan   = errors.New("flow question proposal is not a valid registered read plan")
)

// FlowQuestionBudget is immutable operator cost policy, not result/query reach.
// It is never supplied by a question, model or conversation-history payload.
type FlowQuestionBudget struct {
	Bytes   int
	Tokens  int
	Nesting int
}

func DefaultFlowQuestionBudget() FlowQuestionBudget {
	return FlowQuestionBudget{Bytes: 8 << 20, Tokens: 1 << 20, Nesting: 32}
}

func (b FlowQuestionBudget) Validate() error {
	ceiling := int(^uint(0)>>1) - 1
	if b.Bytes < 1 || b.Bytes > ceiling || b.Tokens < 1 || b.Tokens > ceiling || b.Nesting < 1 || b.Nesting > ceiling {
		return ErrFlowQuestionBudget
	}
	return nil
}

// FlowQuestionInput contains no authority. Parent is a previously authorized
// application message chosen explicitly by the caller, never a transport
// session. The service supplies the clock and locale after authentication.
type FlowQuestionInput struct {
	Question string
	Parent   *FlowQuestionProposal
	Now      time.Time
	TimeZone string
	Locale   string
}

type FlowQuestionPeriod struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type FlowQuestionStatus string

const (
	FlowQuestionReady   FlowQuestionStatus = "ready"
	FlowQuestionClarify FlowQuestionStatus = "clarify"
	FlowQuestionRefused FlowQuestionStatus = "refused"
)

// FlowQuestionProposal is configuration only. A planner cannot read stores,
// choose a tenant, add grants or act; the shared service authorizes execution.
type FlowQuestionProposal struct {
	Status      FlowQuestionStatus        `json:"status"`
	Plan        *flow.QueryPlan           `json:"plan,omitempty"`
	Comparison  *flow.QueryViewComparison `json:"comparison,omitempty"`
	Previous    *FlowQuestionPeriod       `json:"previous,omitempty"`
	Display     *flow.QueryViewDisplay    `json:"display,omitempty"`
	Guidance    string                    `json:"guidance,omitempty"`
	Assumptions []string                  `json:"assumptions,omitempty"`
	// NeedsConfirmation is derived locally, never accepted from a model and
	// never an authorization grant. Execution must confirm the exact revision.
	NeedsConfirmation bool `json:"needs_confirmation,omitempty"`
}

// FlowQuestionPlanner proposes read-only registry grammar, not SQL or tools.
type FlowQuestionPlanner interface {
	Plan(context.Context, FlowQuestionInput) (FlowQuestionProposal, error)
}

// NormalizeFlowQuestionProposal derives previous bounds and independent mutable
// copies through the same validators used by structured/native saved views.
// Previous is derived output: a model cannot override comparison authority.
func NormalizeFlowQuestionProposal(input FlowQuestionProposal, now time.Time) (FlowQuestionProposal, error) {
	if !utf8.ValidString(input.Guidance) {
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	input.Assumptions = slices.Clone(input.Assumptions)
	for _, assumption := range input.Assumptions {
		if !utf8.ValidString(assumption) {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
	}
	switch input.Status {
	case FlowQuestionClarify, FlowQuestionRefused:
		if strings.TrimSpace(input.Guidance) == "" || input.Plan != nil || input.Comparison != nil || input.Display != nil || input.Previous != nil || input.NeedsConfirmation {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
		return input, nil
	case FlowQuestionReady:
		if input.Plan == nil || input.Plan.Cursor != "" {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
	default:
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	definition := flow.QueryViewDefinition{Plan: *input.Plan, Time: flow.QueryViewTime{Mode: "absolute"}, Comparison: input.Comparison}
	plan, previous, err := flow.MaterializeQueryView(definition, now)
	if err != nil {
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	input.Plan, input.Previous = &plan, nil
	if input.Comparison != nil {
		comparison := *input.Comparison
		input.Comparison = &comparison
	}
	if previous != nil {
		input.Previous = &FlowQuestionPeriod{From: previous.From, To: previous.To}
	}
	if input.Display != nil {
		display, err := flow.NormalizeQueryViewDisplay(*input.Display, plan)
		if err != nil {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
		input.Display = &display
	}
	return input, nil
}
