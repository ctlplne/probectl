// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func questionProposalJSON(t *testing.T, proposal FlowQuestionProposal) string {
	t.Helper()
	normalized, err := NormalizeFlowQuestionProposal(proposal, questionClock())
	if err != nil {
		t.Fatal(err)
	}
	normalized.Previous = nil // Derived server output is deliberately not model input.
	raw, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFlowQuestionJSONPreservesFullGrammarAndDerivesComparison(t *testing.T) {
	plan := questionReachPlan()
	plan.Filter.Groups[0].Conditions[0] = flow.QueryPredicate{Field: "raw_bytes", Op: flow.QueryGreater, Values: []string{"18446744073709551615"}}
	raw := questionProposalJSON(t, FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan, Comparison: &flow.QueryViewComparison{Mode: "preceding"}, Display: &flow.QueryViewDisplay{TimeStyle: "horizon"}})
	result, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
	if err != nil || result.Status != FlowQuestionReady || result.Plan.RowLimit != 50000 || result.Plan.PageSize != 5000 || len(result.Plan.Metrics) != 78 || len(result.Plan.GroupBy) != 8 || result.Plan.To.Sub(result.Plan.From) != 401*24*time.Hour || result.Plan.To.Nanosecond() != 123456789 || result.Previous == nil || result.Previous.To != plan.From || result.Plan.Filter.Groups[0].Conditions[0].Values[0] != "18446744073709551615" {
		t.Fatal("typed model proposal narrowed reach, rounded a value or changed comparison", err)
	}
	plan.View, plan.RowLimit, plan.PageSize = "matrix", 350, 350
	for _, field := range flow.QueryFields()[8:16] {
		plan.MatrixWith = append(plan.MatrixWith, field.Name)
	}
	raw = questionProposalJSON(t, FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan})
	result, err = decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
	if err != nil || len(result.Plan.MatrixWith) != 8 || len(result.Plan.GroupBy) != 8 {
		t.Fatal("typed model proposal lost8x8matrix", err)
	}
}

func TestFlowQuestionJSONDoesNotImposeLegacyOneMiBOutputCeiling(t *testing.T) {
	plan := questionReachPlan()
	pattern := strings.Repeat("a", 1024)
	for group := range plan.Filter.Groups {
		for index := range plan.Filter.Groups[group].Conditions {
			plan.Filter.Groups[group].Conditions[index] = flow.QueryPredicate{Field: "src_as_name", Op: flow.QueryRegex, Values: []string{pattern}}
		}
	}
	raw := questionProposalJSON(t, FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan})
	if len(raw) <= 1<<20 {
		t.Fatal("acceptance did not reach the old model response ceiling")
	}
	result, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
	if err != nil || len(result.Plan.Filter.Groups) != 4 || len(result.Plan.Filter.Groups[3].Conditions) != 250 || result.Plan.Filter.Groups[3].Conditions[249].Values[0] != pattern {
		t.Fatal("operator-bounded response lost full1000condition/1KBregex reach", err)
	}
}

func TestFlowQuestionJSONRejectsAmbiguousAuthorityAndCoercions(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{"status":"ready"}`, `{"status":null,"guidance":"private"}`,
		`{"Status":"clarify","guidance":"private"}`, `{"status":"clarify","status":"refused","guidance":"private"}`,
		`{"status":"clarify","sta\u0074us":"refused","guidance":"private"}`,
		`{"status":"clarify","guidance":"private","sql":"SELECT * FROM flows"}`,
		`{"status":"clarify","guidance":"private","tenant_id":"other"}`,
		`{"status":"clarify","guidance":"private","tools":[]}`,
		`{"status":"clarify","guidance":"private","previous":null}`,
		`{"status":"ready","plan":{"TenantID":"other"}}`,
		`{"status":"ready","plan":{"Row_Limit":50000}}`,
		`{"status":"ready","plan":{"row_limit":null}}`,
		`{"status":"ready","plan":{"group_by":null}}`,
		`{"status":"ready","plan":{"from":null}}`,
		`{"status":"ready","plan":{"row_limit":1,"row_limit":50000}}`,
		`{"status":"ready","plan":{"row_limit":1.0}}`,
		`{"status":"ready","plan":{"row_limit":1e1}}`,
		`{"status":"ready","plan":{"row_limit":18446744073709551615}}`,
		`{"status":"ready","plan":{"filter":{"conditions":[{"field":"raw_bytes","op":"gt","values":[18446744073709551615]}]}}}`,
		`{"status":"ready","plan":{"filter":{"conditions":[{"field":"src_port","Field":"dst_port","op":"eq","values":["443"]}]}}}`,
		`{"status":"ready","plan":{"filter":{"conditions":[{"field":"tenant_id","op":"eq","values":["other"]}]}}}`,
		`{"status":"ready","plan":{"filter":{"saved":[{"id":"private","tenant":"other"}]}}}`,
		`{"status":"ready","plan":{"cursor":"private-old-result"}}`,
		`{"status":"ready","plan":{"from":"not-a-time"}}`,
		`{"status":"ready","plan":{},"comparison":{"mode":"absolute","from":"not-a-time"}}`,
		`{"status":"ready","plan":{},"display":{"total_overlay":null}}`,
		`{"status":"clarify","plan":{},"guidance":"private"}`,
		`{"status":"refused","guidance":"private","display":{}}`,
		`{"status":"clarify","guidance":"private"} {}`,
		`{"status":"clarify","guidance":"private"} trailing prose`,
		"```json\n{\"status\":\"clarify\",\"guidance\":\"private\"}\n```",
		`{"status":"clarify","guidance":"private\ud800"}`,
		`{"status":"clarify","guidance":"private\udc00"}`,
		`{"status":"clarify","guidance":"private\ud800\u0041"}`,
		string([]byte{255}),
	} {
		proposal, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
		if !errors.Is(err, ErrFlowQuestionPlan) || !reflect.DeepEqual(proposal, FlowQuestionProposal{}) || strings.Contains(err.Error(), "private") {
			t.Fatalf("malformed model proposal accepted or copied private text; input=%q error=%v", raw, err)
		}
	}
}

func TestFlowQuestionJSONRetainsUnicodeAndSQLLookingLiteralData(t *testing.T) {
	for _, raw := range []string{
		`{"status":"clarify","guidance":"Choose a window 🚀"}`,
		`{"status":"clarify","guidance":"Choose a window \ud83d\ude80"}`,
		`{"status":"clarify","guidance":"Literal backslash \\ud800 remains data"}`,
	} {
		proposal, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
		if err != nil || proposal.Status != FlowQuestionClarify {
			t.Fatal("valid Unicode or escaped backslash rejected", err)
		}
	}
	raw := `{"status":"ready","plan":{"filter":{"conditions":[{"field":"src_as_name","op":"eq","values":["DROP TABLE flows; tenant_id=other"]}]}}}`
	proposal, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock())
	if err != nil || proposal.Plan.Filter.Conditions[0].Values[0] != "DROP TABLE flows; tenant_id=other" {
		t.Fatal("a typed bound literal became a command or changed", err)
	}
}

func TestFlowQuestionJSONOperatorResourcesAndCancellation(t *testing.T) {
	raw := `{"status":"ready","plan":{}}`
	for _, budget := range []FlowQuestionBudget{
		{}, {Bytes: len(raw) - 1, Tokens: 100, Nesting: 32},
		{Bytes: len(raw), Tokens: 2, Nesting: 32}, {Bytes: len(raw), Tokens: 100, Nesting: 0},
	} {
		if _, err := decodeFlowQuestionProposal(t.Context(), raw, budget, questionClock()); !errors.Is(err, ErrFlowQuestionBudget) {
			t.Fatal("invalid/exhausted operator resource policy ignored", err)
		}
	}
	if _, err := decodeFlowQuestionProposal(t.Context(), raw, FlowQuestionBudget{Bytes: len(raw), Tokens: 100, Nesting: 32}, questionClock()); err != nil {
		t.Fatal("exact byte budget refused complete response", err)
	}
	if _, err := decodeFlowQuestionProposal(t.Context(), `{"status":"ready","plan":{"filter":{"conditions":[]}}}`, FlowQuestionBudget{Bytes: 1024, Tokens: 100, Nesting: 1}, questionClock()); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("deep response ignored operator structure policy", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := decodeFlowQuestionProposal(ctx, raw, DefaultFlowQuestionBudget(), questionClock()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled model response decoded", err)
	}
	if _, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), time.Time{}); !errors.Is(err, ErrFlowQuestionInput) {
		t.Fatal("model input supplied no authoritative clock", err)
	}
}
