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
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func questionTestLiteralBuilder(t *testing.T) *questionLiteralBuilder {
	t.Helper()
	builder, err := newQuestionLiteralBuilder(DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func questionTestLiteral(t *testing.T, builder *questionLiteralBuilder, value string, required bool) questionLiteralRef {
	t.Helper()
	ref, err := builder.add(t.Context(), value, required)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func questionLiteralWire(t *testing.T, field string, op flow.QueryOperator, values ...any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"status": "ready", "plan": map[string]any{
		"filter": map[string]any{"conditions": []any{map[string]any{"field": field, "op": op, "values": values}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestQuestionLiteralBindingPreservesExactNativeValues(t *testing.T) {
	for _, test := range []struct {
		field string
		op    flow.QueryOperator
		value string
	}{
		{"src_as_name", flow.QueryRegex, `^(edge[0-9]+\.example\.test|10\.2\.3\.4)$`},
		{"src_as_name", flow.QueryContains, "quoted \"name\" \\ path 😀\u2028\u2029 <>&\n\t"},
		{"src_as_name", flow.QueryEqual, "SELECT * FROM flows WHERE tenant_id = 'other'; DROP TABLE flows"},
		{"src_as_name", flow.QueryEqual, ""},
		{"src_addr", flow.QueryEqual, "2001:db8::1234"},
		{"src_addr", flow.QueryCIDR, "2001:db8::/32"},
		{"raw_bytes", flow.QueryGreater, "18446744073709551615"},
	} {
		t.Run(test.field+"/"+string(test.op), func(t *testing.T) {
			builder := questionTestLiteralBuilder(t)
			ref := questionTestLiteral(t, builder, test.value, true)
			raw := questionLiteralWire(t, test.field, test.op, ref)
			result, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), builder.seal())
			if err != nil || result.Plan == nil || result.Plan.Filter.Conditions[0].Values[0] != test.value {
				t.Fatal("exact bound literal changed or failed native validation", err)
			}
			if test.value != "" && strings.Contains(raw, test.value) {
				t.Fatal("source literal entered reference wire")
			}
		})
	}
}

func TestQuestionLiteralBindingRejectsForeignOrUntypedReferences(t *testing.T) {
	builder, other := questionTestLiteralBuilder(t), questionTestLiteralBuilder(t)
	ref := questionTestLiteral(t, builder, "private exact source", true)
	foreign := questionTestLiteral(t, other, "private exact source", true)
	if ref == foreign {
		t.Fatal("independent requests share a literal namespace")
	}
	bindings := builder.seal()
	validRef, _ := json.Marshal(ref)
	id, _ := json.Marshal(ref.LiteralRef)
	for _, value := range []string{
		`{"literal_ref":"unknown"}`,
		`{"literal_ref":null}`, `{"literal_ref":42}`, `{"Literal_Ref":` + string(id) + `}`,
		`{"literal_ref":` + string(id) + `,"literal_ref":` + string(id) + `}`,
		`{"literal_ref":` + string(id) + `,"literal\u005fref":` + string(id) + `}`,
		`{"literal_ref":` + string(id) + `,"sql":"private"}`,
		`{"literal_ref":{"literal_ref":` + string(id) + `}}`, `{}`, `[]`, `null`,
	} {
		raw := questionLiteralWire(t, "src_as_name", flow.QueryEqual, json.RawMessage(value))
		result, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), bindings)
		if !errors.Is(err, ErrFlowQuestionPlan) || !reflect.DeepEqual(result, FlowQuestionProposal{}) || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid reference acquired a partial plan or private diagnostic", err)
		}
	}
	raw := questionLiteralWire(t, "src_as_name", flow.QueryEqual, foreign)
	if _, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), bindings); !errors.Is(err, ErrFlowQuestionPlan) {
		t.Fatal("another request's equal-value reference resolved", err)
	}
	raw = questionLiteralWire(t, "src_as_name", flow.QueryEqual, ref)
	if _, err := decodeFlowQuestionProposal(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock()); !errors.Is(err, ErrFlowQuestionPlan) {
		t.Fatal("ordinary typed decoder accepted private model reference", err)
	}
	for _, raw := range []string{
		`{"status":"ready","plan":{"filter":{"conditions":[{"field":` + string(validRef) + `,"op":"eq","values":["x"]}]}}}`,
		`{"status":"ready","plan":{"filter":{"conditions":[{"field":"src_as_name","op":` + string(validRef) + `,"values":["x"]}]}}}`,
		`{"status":"ready","plan":{"group_by":[` + string(validRef) + `]}}`,
		`{"status":"clarify","guidance":` + string(validRef) + `}`,
		`{"status":"ready","plan":{"filter":{"saved":[{"id":` + string(validRef) + `}]}}}`,
	} {
		if _, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), bindings); !errors.Is(err, ErrFlowQuestionPlan) {
			t.Fatal("reference resolved outside typed predicate values", err)
		}
	}
}

func TestQuestionLiteralMissingConstraintNeverBroadensPlan(t *testing.T) {
	builder := questionTestLiteralBuilder(t)
	ref := questionTestLiteral(t, builder, "private exact source", false)
	if again := questionTestLiteral(t, builder, "private exact source", true); again != ref {
		t.Fatal("same request duplicated an exact value instead of tightening requirement")
	}
	bindings := builder.seal()
	for _, raw := range []string{
		`{"status":"ready","plan":{}}`,
		questionLiteralWire(t, "src_as_name", flow.QueryEqual, "private exact source"),
	} {
		proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), bindings)
		if !errors.Is(err, errQuestionLiteralMissing) || proposal.Plan != nil || strings.Contains(err.Error(), "private exact") {
			t.Fatal("missing reference was silently omitted/copied/interpolated", err)
		}
	}
	for _, surrogate := range []string{ref.LiteralRef, "prefix" + ref.LiteralRef + "suffix", "[host:0123456789abcdef0123456789abcdef]"} {
		proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), questionLiteralWire(t, "src_as_name", flow.QueryRegex, surrogate), DefaultFlowQuestionBudget(), questionClock(), bindings)
		if !errors.Is(err, ErrFlowQuestionPlan) || proposal.Plan != nil {
			t.Fatal("plain or interpolated surrogate became a source filter", err)
		}
	}
	for _, status := range []string{"clarify", "refused"} {
		proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), `{"status":"`+status+`","guidance":"Choose an explicit filter."}`, DefaultFlowQuestionBudget(), questionClock(), bindings)
		if err != nil || proposal.Plan != nil || string(proposal.Status) != status {
			t.Fatal("safe non-executable clarification/refusal was denied", err)
		}
	}
	if _, err := builder.add(t.Context(), "later mutation", false); !errors.Is(err, ErrFlowQuestionInput) || builder.seal() != nil {
		t.Fatal("sealed private bindings remained mutable")
	}
	privateType := reflect.TypeFor[questionLiteralBindings]()
	if privateType.Implements(reflect.TypeFor[json.Marshaler]()) || reflect.PointerTo(privateType).Implements(reflect.TypeFor[json.Marshaler]()) {
		t.Fatal("private binding catalog exposes custom JSON marshaling")
	}
	for index := 0; index < privateType.NumField(); index++ {
		if privateType.Field(index).IsExported() {
			t.Fatal("private binding catalog exposes a serialized field")
		}
	}
}

func TestQuestionLiteralBindingStillRequiresNativeValidation(t *testing.T) {
	for _, test := range []struct {
		field string
		op    flow.QueryOperator
		value string
	}{
		{"src_as_name", flow.QueryRegex, strings.Repeat("a", flow.MaxQueryRegexBytes+1)},
		{"src_as_name", flow.QueryRegex, "[invalid"},
		{"src_addr", flow.QueryCIDR, "invalid private prefix"},
		{"raw_bytes", flow.QueryGreater, "18446744073709551616"},
	} {
		builder := questionTestLiteralBuilder(t)
		ref := questionTestLiteral(t, builder, test.value, true)
		proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), questionLiteralWire(t, test.field, test.op, ref), DefaultFlowQuestionBudget(), questionClock(), builder.seal())
		if !errors.Is(err, ErrFlowQuestionPlan) || proposal.Plan != nil || strings.Contains(err.Error(), test.value) {
			t.Fatal("private reference bypassed native validation or exposed source diagnostic", err)
		}
	}
}

func TestQuestionLiteralBindingChecksExpandedBytesBeforeAllocation(t *testing.T) {
	builder := questionTestLiteralBuilder(t)
	value := strings.Repeat("<", 4096) // Every byte expands to six JSON bytes.
	ref := questionTestLiteral(t, builder, value, true)
	bindings := builder.seal()
	raw := questionLiteralWire(t, "src_as_name", flow.QueryIn, ref, "ordinary", ref)
	encodedRef, _ := json.Marshal(ref)
	encodedValue, _ := json.Marshal(value)
	exactBytes := len(raw) + 2*(len(encodedValue)-len(encodedRef))
	budget := DefaultFlowQuestionBudget()
	budget.Bytes = exactBytes
	proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, budget, questionClock(), bindings)
	if err != nil || len(proposal.Plan.Filter.Conditions[0].Values) != 2 || !slices.Contains(proposal.Plan.Filter.Conditions[0].Values, value) || !slices.Contains(proposal.Plan.Filter.Conditions[0].Values, "ordinary") {
		t.Fatal("exact expanded budget or mixed literal positions failed", err)
	}
	budget.Bytes--
	if proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, budget, questionClock(), bindings); !errors.Is(err, ErrFlowQuestionBudget) || proposal.Plan != nil {
		t.Fatal("repeated references amplified beyond expanded byte budget", err)
	}
	budget = DefaultFlowQuestionBudget()
	budget.Tokens = 3
	if _, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, budget, questionClock(), bindings); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("reference decoding bypassed token budget", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := decodeFlowQuestionProposalWithLiterals(ctx, raw, DefaultFlowQuestionBudget(), questionClock(), bindings); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled binding published a plan", err)
	}
}

func TestQuestionLiteralBindingPreservesFullReachConcurrently(t *testing.T) {
	plan := questionReachPlan()
	builder := questionTestLiteralBuilder(t)
	pattern := strings.Repeat("a", flow.MaxQueryRegexBytes)
	ref := questionTestLiteral(t, builder, pattern, true)
	for group := range plan.Filter.Groups {
		for index := range plan.Filter.Groups[group].Conditions {
			plan.Filter.Groups[group].Conditions[index] = flow.QueryPredicate{Field: "src_as_name", Op: flow.QueryRegex, Values: []string{"literal-marker"}}
		}
	}
	raw := questionProposalJSON(t, FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan})
	encodedRef, _ := json.Marshal(ref)
	raw = strings.ReplaceAll(raw, `"literal-marker"`, string(encodedRef))
	bindings := builder.seal()
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			proposal, err := decodeFlowQuestionProposalWithLiterals(t.Context(), raw, DefaultFlowQuestionBudget(), questionClock(), bindings)
			if err != nil || proposal.Plan == nil || len(proposal.Plan.Metrics) != 78 || proposal.Plan.RowLimit != 50000 || proposal.Plan.PageSize != 5000 || len(proposal.Plan.GroupBy) != 8 || len(proposal.Plan.Filter.Groups) != 4 || proposal.Plan.Filter.Groups[3].Conditions[249].Values[0] != pattern {
				t.Error("binding narrowed complete native grammar", err)
			}
		})
	}
	workers.Wait()
	if plan.Filter.Groups[0].Conditions[0].Values[0] != "literal-marker" {
		t.Fatal("binding mutated caller-owned query")
	}
}

func TestQuestionLiteralSourceAdmissionIsFiniteAndExact(t *testing.T) {
	for _, value := range []string{"plain", "<>&\x00\b\f\n\r\t\"\\😀\u2028\u2029", "", "\uFFFD"} {
		encoded, _ := json.Marshal(value)
		if size, err := questionLiteralEncodedSize(t.Context(), value, len(encoded)); err != nil || size != len(encoded) {
			t.Fatal("literal JSON size differs from actual encoding", err)
		}
		if _, err := questionLiteralEncodedSize(t.Context(), value, len(encoded)-1); !errors.Is(err, ErrFlowQuestionBudget) {
			t.Fatal("literal encoding exceeded exact budget", err)
		}
	}
	builder := questionTestLiteralBuilder(t)
	if _, err := builder.add(t.Context(), string([]byte{255}), false); !errors.Is(err, ErrFlowQuestionInput) {
		t.Fatal("source literal silently replaced invalid UTF8", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := builder.add(ctx, "private", false); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled source was retained", err)
	}
	if _, err := builder.add(t.Context(), strings.Repeat("<", DefaultFlowQuestionBudget().Bytes/6+1), false); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("source encoding exceeded operator resource bound", err)
	}
	if _, err := newQuestionLiteralBuilder(FlowQuestionBudget{}); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("missing source resource policy accepted", err)
	}
}
