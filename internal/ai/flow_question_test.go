// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func questionReachPlan() flow.QueryPlan {
	now := time.Date(2026, 10, 29, 8, 0, 0, 123456789, time.UTC)
	// Preserve the original complete 50,000-row model corpus as capacity grows.
	plan := flow.QueryPlan{From: now.Add(-401 * 24 * time.Hour), To: now, View: "table", RowLimit: 50000, PageSize: flow.MaxPlanPageRows}
	for _, definition := range flow.QueryMetricDefinitions() {
		for _, calculation := range definition.Calculations {
			role := "additional"
			if len(plan.Metrics) == 0 {
				role = "primary"
			} else if len(plan.Metrics) < 4 {
				role = "secondary"
			}
			plan.Metrics = append(plan.Metrics, flow.QueryMetric{Measure: definition.Name, Calculation: calculation, Role: role})
		}
	}
	plan.Filter = &flow.QueryFilterGroup{Match: "any", Mode: "include"}
	for group := 0; group < 4; group++ {
		child := flow.QueryFilterGroup{Match: "all", Mode: "include"}
		for condition := 0; condition < 250; condition++ {
			child.Conditions = append(child.Conditions, flow.QueryPredicate{Field: "src_port", Op: flow.QueryEqual, Values: []string{strconv.Itoa(group*250 + condition)}})
		}
		plan.Filter.Groups = append(plan.Filter.Groups, child)
	}
	for _, field := range flow.QueryFields()[:8] {
		plan.GroupBy = append(plan.GroupBy, field.Name)
	}
	return plan
}

func TestFlowQuestionProposalKeepsFullNativeReachAndCopiesContext(t *testing.T) {
	plan := questionReachPlan()
	display := &flow.QueryViewDisplay{TimeStyle: "horizon", HorizonScale: "lane", LogMetrics: []string{plan.Metrics[0].Measure + ":" + plan.Metrics[0].Calculation}}
	proposal := FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan, Comparison: &flow.QueryViewComparison{Mode: "preceding"}, Display: display, Previous: &FlowQuestionPeriod{From: plan.To, To: plan.To.Add(time.Hour)}}
	normal, err := NormalizeFlowQuestionProposal(proposal, plan.To)
	if err != nil || normal.Plan.RowLimit != 50000 || normal.Plan.PageSize != 5000 || len(normal.Plan.GroupBy) != 8 || len(normal.Plan.Metrics) != 78 || normal.Plan.From != plan.From || normal.Plan.To.Nanosecond() != 123456789 || normal.Previous == nil || normal.Previous.To != plan.From {
		t.Fatal("question contract narrowed native grammar/range/precision", err)
	}
	normal.Plan.Filter.Groups[0].Conditions[0].Values[0] = "changed"
	normal.Plan.GroupBy[0] = "changed"
	normal.Plan.Metrics[0].Measure = "changed"
	normal.Display.LogMetrics[0] = "changed"
	if plan.Filter.Groups[0].Conditions[0].Values[0] != "0" || plan.GroupBy[0] == "changed" || plan.Metrics[0].Measure == "changed" || display.LogMetrics[0] == "changed" {
		t.Fatal("normalized proposal changed its parent history")
	}
	plan.View, plan.RowLimit, plan.PageSize = "matrix", 350, 350
	for _, field := range flow.QueryFields()[8:16] {
		plan.MatrixWith = append(plan.MatrixWith, field.Name)
	}
	normal, err = NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan}, plan.To)
	if err != nil || len(normal.Plan.GroupBy) != 8 || len(normal.Plan.MatrixWith) != 8 {
		t.Fatal("question contract lost8x8matrix", err)
	}
}

func TestFlowQuestionProposalNeverCarriesExecutablePartialOrTransientCursor(t *testing.T) {
	plan := questionReachPlan()
	for _, status := range []FlowQuestionStatus{FlowQuestionClarify, FlowQuestionRefused} {
		if _, err := NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: status, Plan: &plan, Guidance: "Clarify the requested field."}, plan.To); !errors.Is(err, ErrFlowQuestionPlan) {
			t.Fatal("non-ready proposal retained executable data")
		}
		if _, err := NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: status, Guidance: "Clarify the requested field."}, plan.To); err != nil {
			t.Fatal(err)
		}
	}
	plan.Cursor = "private-old-result-cursor"
	if _, err := NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan}, plan.To); !errors.Is(err, ErrFlowQuestionPlan) {
		t.Fatal("question inherited a transient result capability")
	}
}

func TestFlowQuestionLexerPreservesExactQuotedLiteralsAndSourcePositions(t *testing.T) {
	question := "show raw_bytes > 18446744073709551615 where src_as_name regex '^München\\d{2,3}(a|b)$' and src_addr equals \"2001:db8::1\""
	tokens, err := lexFlowQuestion(t.Context(), question, DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	var number, pattern, address bool
	for _, token := range tokens {
		if token.start < 0 || token.end > len(question) || token.start >= token.end {
			t.Fatal("invalid source position")
		}
		switch token.text {
		case "18446744073709551615":
			number = true
		case `^München\d{2,3}(a|b)$`:
			pattern = token.quoted
		case "2001:db8::1":
			address = token.quoted
		}
	}
	if !number || !pattern || !address {
		t.Fatal("lexer rounded integers, split quoted regex or changed a literal")
	}
}

func TestFlowQuestionLexerBoundsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		question string
		budget   FlowQuestionBudget
		want     error
	}{
		{"field", FlowQuestionBudget{Bytes: 4, Tokens: 10, Nesting: 2}, ErrFlowQuestionBudget},
		{"a b c", FlowQuestionBudget{Bytes: 20, Tokens: 2, Nesting: 2}, ErrFlowQuestionBudget},
		{"((a))", FlowQuestionBudget{Bytes: 20, Tokens: 20, Nesting: 1}, ErrFlowQuestionBudget},
		{"a)", DefaultFlowQuestionBudget(), ErrFlowQuestionInput},
		{"(a", DefaultFlowQuestionBudget(), ErrFlowQuestionInput},
		{"'private-unclosed", DefaultFlowQuestionBudget(), ErrFlowQuestionInput},
		{`"\uD800"`, DefaultFlowQuestionBudget(), ErrFlowQuestionInput},
		{string([]byte{255}), DefaultFlowQuestionBudget(), ErrFlowQuestionInput},
		{"private-input", FlowQuestionBudget{}, ErrFlowQuestionBudget},
	} {
		_, err := lexFlowQuestion(t.Context(), tc.question, tc.budget)
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "private") {
			t.Fatal("malformed/budget input accepted or echoed", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := lexFlowQuestion(ctx, "show flows", DefaultFlowQuestionBudget()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled question lexed")
	}
}
