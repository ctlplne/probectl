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
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
)

func questionEchoIntent(_ string, user string) (string, error) {
	var envelope struct {
		Intent json.RawMessage `json:"parsed_intent"`
	}
	if json.Unmarshal([]byte(user), &envelope) != nil || len(envelope.Intent) == 0 {
		return "", errors.New("reference handler needs complete native intent")
	}
	return string(envelope.Intent), nil
}

func questionSourcePlanner(t *testing.T, inner *flowModelFixture, policy RedactionPolicy) *ModelFlowQuestionPlanner {
	t.Helper()
	gate := NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, EgressEvent) error { return nil }, policy)
	planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(inner, gate), DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func questionOwnerContext(t *testing.T) context.Context {
	t.Helper()
	return auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: "owned-blue", UserID: "owned-user"})
}

func TestModelPrivateContextUsesBothActualRedactionPassesOverTLS(t *testing.T) {
	for _, kind := range []ModelKind{KindOllama, KindOpenAI, KindAnthropic} {
		for _, selection := range []struct {
			name, clause string
			rows         int
		}{
			{"complete-all-rows", "all rows", 2147483647},
			{"original-selected-50000", "limit 50000", 50000},
		} {
			t.Run(string(kind)+"/"+selection.name, func(t *testing.T) {
				var calls, events atomic.Int32
				var observed atomic.Value
				model := completionTLSModel(t, kind, func(w http.ResponseWriter, r *http.Request) {
					var body struct {
						Messages []struct{ Role, Content string } `json:"messages"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid actual provider request")
						w.WriteHeader(400)
						return
					}
					var user string
					for _, message := range body.Messages {
						if message.Role == "user" {
							user = message.Content
						}
					}
					observed.Store(user)
					calls.Add(1)
					reply, err := questionEchoIntent("", user)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					_ = json.NewEncoder(w).Encode(completionWireFrame(kind, reply, "complete"))
				})
				// Force the actual remote policy path on the owned loopback TLS
				// reference handler. No external provider/account is contacted.
				model.remote = true
				model.redact.CustomPatterns = []*regexp.Regexp{regexp.MustCompile(`adapter-private-value`)}
				policy := DefaultRedaction
				policy.CustomPatterns = []*regexp.Regexp{regexp.MustCompile(`gate-private-value`)}
				gate := NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(_ context.Context, event EgressEvent) error {
					if event.Surface != "flow_question" || event.TenantID != "owned-blue" || event.Denied {
						t.Error("source path changed the durable tenant egress event")
					}
					events.Add(1)
					return nil
				}, policy)
				planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(NewResilientModel(model, NewBuiltinModel(), 10*time.Second), gate), DefaultFlowQuestionBudget())
				if err != nil {
					t.Fatal(err)
				}
				input := modelQuestionInput()
				input.Question = `show traffic where src_as_name eq gate-private-value or src_as_name eq adapter-private-value or src_addr cidr '2001:db8::/32' or src_as_name=plain-owned-label group by src_as_name for last 400 days ` + selection.clause + ` page size 5000`
				proposal, err := planner.Plan(questionOwnerContext(t), input)
				if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation || proposal.Plan.RowLimit != selection.rows || proposal.Plan.PageSize != 5000 || calls.Load() != 1 || events.Load() != 1 {
					t.Fatal("actual gated/budgeted adapter lost complete native intent", err, calls.Load(), events.Load())
				}
				for _, private := range []string{"gate-private-value", "adapter-private-value", "2001:db8::/32", "plain-owned-label"} {
					if strings.Contains(observed.Load().(string), private) {
						t.Fatal("exact private operand entered actual remote protocol body")
					}
				}
				if strings.Contains(observed.Load().(string), "owned-blue") || !strings.Contains(observed.Load().(string), "literal_ref") {
					t.Fatal("model received authority or no private binding")
				}
			})
		}
	}
}

func TestModelContextNeverConfirmsChangedBooleanFieldOperatorOrParent(t *testing.T) {
	for _, mutation := range []string{"none", "boolean", "exclude", "field", "operator", "rows", "unconfirmed parent"} {
		t.Run(mutation, func(t *testing.T) {
			inner := &flowModelFixture{replyContext: func(system, user string) (string, error) {
				raw, err := questionEchoIntent(system, user)
				if err != nil {
					return "", err
				}
				var reply map[string]any
				if json.Unmarshal([]byte(raw), &reply) != nil {
					t.Fatal("invalid generated context")
				}
				plan := reply["plan"].(map[string]any)
				filter := plan["filter"].(map[string]any)
				condition := filter["conditions"].([]any)[0].(map[string]any)
				switch mutation {
				case "boolean":
					filter["match"] = "any"
				case "exclude":
					filter["mode"] = "exclude"
				case "field":
					condition["field"] = "dst_as_name"
				case "operator":
					condition["op"] = "contains"
				case "rows":
					plan["row_limit"] = 350
				}
				encoded, err := json.Marshal(reply)
				return string(encoded), err
			}}
			planner := questionSourcePlanner(t, inner, DefaultRedaction)
			input := modelQuestionInput()
			input.Question = `show traffic where src_as_name eq 'edge.example.test' and dst_port eq 443`
			if mutation == "unconfirmed parent" {
				local, _ := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
				parent, err := local.Plan(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				parent.NeedsConfirmation = true
				input.Parent, input.Question = &parent, "same query"
			}
			proposal, err := planner.Plan(t.Context(), input)
			if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation != (mutation != "none") {
				t.Fatal("operand presence falsely confirmed changed complete intent", err, proposal.NeedsConfirmation)
			}
		})
	}
	for _, flag := range []string{"true", "false"} {
		if _, err := decodeFlowQuestionProposal(t.Context(), `{"status":"ready","plan":{},"needs_confirmation":`+flag+`}`, DefaultFlowQuestionBudget(), questionClock()); !errors.Is(err, ErrFlowQuestionPlan) {
			t.Fatal("model supplied its own confirmation requirement", err)
		}
	}
}

func TestModelContextExplicitClearAndReplaceRetainExactPrivateMeaning(t *testing.T) {
	local, _ := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
	input := modelQuestionInput()
	input.Question = `show traffic where src_addr eq '10.2.3.4'`
	parent, err := local.Plan(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	before := questionProposalJSON(t, parent)
	for _, question := range []string{"clear filters", `replace filter with src_addr eq '10.9.8.7'`} {
		inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
		planner := questionSourcePlanner(t, inner, DefaultRedaction)
		input.Parent, input.Question = &parent, question
		proposal, err := planner.Plan(questionOwnerContext(t), input)
		if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation || (question == "clear filters") != (proposal.Plan.Filter == nil) {
			t.Fatal("explicit clear/replace inherited an obsolete required operand", err)
		}
		_, _, raw := inner.observed()
		if strings.Contains(raw, "10.2.3.4") || strings.Contains(raw, "10.9.8.7") || questionProposalJSON(t, parent) != before {
			t.Fatal("parent source leaked or immutable context changed")
		}
	}
}

func TestModelContextUnknownProseMissingAndReplayedReferencesFailClosed(t *testing.T) {
	var firstRef string
	mode := "valid"
	inner := &flowModelFixture{remote: true, replyContext: func(_ string, user string) (string, error) {
		if mode == "missing" {
			return `{"status":"ready","plan":{}}`, nil
		}
		id := regexp.MustCompile(`probectl-literal-[0-9a-f]{64}\.[0-9]+`).FindString(user)
		if firstRef == "" {
			firstRef = id
		}
		if mode == "replay" {
			id = firstRef
		}
		return questionLiteralWire(t, "src_as_name", flow.QueryRegex, questionLiteralRef{LiteralRef: id}), nil
	}}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	pattern := `^private\.example\.test-[0-9]+$`
	input.Question = "Could you investigate " + strings.Repeat("the network behavior ", 100) + " matching '" + pattern + "' and explain this observation?"
	proposal, err := planner.Plan(questionOwnerContext(t), input)
	if err != nil || proposal.Plan == nil || !proposal.NeedsConfirmation || proposal.Plan.Filter.Conditions[0].Values[0] != pattern {
		t.Fatal("unknown prose lost exact private proposal or became automatically executable", err)
	}
	_, _, raw := inner.observed()
	if strings.Contains(raw, pattern) || strings.Count(raw, "the network behavior") != 100 {
		t.Fatal("source was disclosed or silently truncated to a display-label budget")
	}
	mode = "missing"
	proposal, err = planner.Plan(questionOwnerContext(t), input)
	if err != nil || proposal.Status != FlowQuestionClarify || proposal.Plan != nil {
		t.Fatal("missing protected operand broadened the question", err)
	}
	mode = "replay"
	proposal, err = planner.Plan(questionOwnerContext(t), input)
	if !errors.Is(err, ErrFlowQuestionPlan) || proposal.Plan != nil {
		t.Fatal("a different attempt's private ID was resolved", err)
	}
}

func TestModelContextCustomSpanningPatternsNeverSilentlyChangeMeaning(t *testing.T) {
	policy := DefaultRedaction
	policy.CustomPatterns = []*regexp.Regexp{regexp.MustCompile(`show traffic`)}
	for _, question := range []string{"show traffic by src_as_name", "Explain the show traffic observation"} {
		inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
		planner := questionSourcePlanner(t, inner, policy)
		input := modelQuestionInput()
		input.Question = question
		proposal, err := planner.Plan(questionOwnerContext(t), input)
		calls, _, _ := inner.observed()
		if err != nil || calls != 0 {
			t.Fatal("unresolved custom redaction dispatched changed context", err)
		}
		if strings.HasPrefix(question, "show traffic") {
			if proposal.Status != FlowQuestionReady || proposal.NeedsConfirmation || len(proposal.Assumptions) == 0 {
				t.Fatal("complete local fallback was lost or not disclosed")
			}
		} else if proposal.Status != FlowQuestionClarify || proposal.Plan != nil {
			t.Fatal("unknown protected prose became an executable partial plan")
		}
	}
}

func TestModelContextFullParentReachAndEncodedBudget(t *testing.T) {
	plan := questionReachPlan()
	pattern := strings.Repeat("a", flow.MaxQueryRegexBytes)
	for group := range plan.Filter.Groups {
		for index := range plan.Filter.Groups[group].Conditions {
			plan.Filter.Groups[group].Conditions[index] = flow.QueryPredicate{Field: "src_as_name", Op: flow.QueryRegex, Values: []string{pattern}}
		}
	}
	parent, err := NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: FlowQuestionReady, Plan: &plan, Guidance: "private narrative not required to reconstruct query settings"}, questionClock())
	if err != nil {
		t.Fatal(err)
	}
	input := modelQuestionInput()
	input.Parent, input.Question = &parent, "same query"
	inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	proposal, err := planner.Plan(questionOwnerContext(t), input)
	if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation || !reflect.DeepEqual(proposal.Plan, parent.Plan) {
		t.Fatal("private source path narrowed1000conditions/78metrics/401days/50k/5k/8dimensions", err)
	}
	matrixPlan := plan
	matrixPlan.View, matrixPlan.RowLimit, matrixPlan.PageSize = "matrix", 350, 350
	for _, field := range flow.QueryFields()[8:16] {
		matrixPlan.MatrixWith = append(matrixPlan.MatrixWith, field.Name)
	}
	matrixParent, err := NormalizeFlowQuestionProposal(FlowQuestionProposal{Status: FlowQuestionReady, Plan: &matrixPlan}, questionClock())
	if err != nil {
		t.Fatal(err)
	}
	matrixInput := input
	matrixInput.Parent = &matrixParent
	matrixProposal, err := planner.Plan(questionOwnerContext(t), matrixInput)
	if err != nil || matrixProposal.Plan == nil || matrixProposal.NeedsConfirmation || len(matrixProposal.Plan.GroupBy) != 8 || len(matrixProposal.Plan.MatrixWith) != 8 || len(matrixProposal.Plan.Metrics) != 78 {
		t.Fatal("private context narrowed8x8matrix or full metrics", err)
	}
	// Restore the table request for the exact source-vs-encoded admission proof.
	if _, err := planner.Plan(questionOwnerContext(t), input); err != nil {
		t.Fatal(err)
	}
	_, system, raw := inner.observed()
	if strings.Contains(raw, pattern) || strings.Contains(raw, parent.Guidance) {
		t.Fatal("parent literal/narrative entered model context")
	}
	budget := DefaultFlowQuestionBudget()
	budget.Bytes = len(system) + len(raw)
	exact, err := NewModelFlowQuestionPlanner(NewGatedCompleter(inner, planner.completer.gate), budget)
	if err != nil {
		t.Fatal(err)
	}
	// Full source admission also accounts for local exact values, not just the
	// compressed repeated-reference envelope, so retain sufficient source budget.
	if _, err := exact.Plan(questionOwnerContext(t), input); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("compressed references bypassed complete source admission", err)
	}
}

func TestModelContextEncodedBoundaryAndCanonicalOperands(t *testing.T) {
	inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	input.Question = "show traffic"
	if _, err := planner.Plan(questionOwnerContext(t), input); err != nil {
		t.Fatal(err)
	}
	_, system, raw := inner.observed()
	budget := DefaultFlowQuestionBudget()
	budget.Bytes = len(system) + len(raw)
	exact, err := NewModelFlowQuestionPlanner(planner.completer, budget)
	if err != nil {
		t.Fatal(err)
	}
	if proposal, err := exact.Plan(questionOwnerContext(t), input); err != nil || proposal.Plan == nil || proposal.NeedsConfirmation {
		t.Fatal("exact encoded context boundary was denied", err)
	}
	budget.Bytes--
	over, err := NewModelFlowQuestionPlanner(planner.completer, budget)
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := inner.observed()
	if proposal, err := over.Plan(questionOwnerContext(t), input); !errors.Is(err, ErrFlowQuestionBudget) || proposal.Plan != nil {
		t.Fatal("encoded context exceeded operator bytes", err)
	}
	after, _, _ := inner.observed()
	if before != after {
		t.Fatal("oversized context reached the model")
	}
	input.Question = `show traffic where src_addr eq '2001:0db8::0001' and dst_port eq '00443'`
	proposal, err := planner.Plan(questionOwnerContext(t), input)
	if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation {
		t.Fatal("canonical native spellings lost exact private binding", err)
	}
}

func TestModelContextBoundTokenLookingDataIsNotGloballyUnredactedOrRejected(t *testing.T) {
	inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	value := "[host:0123456789abcdef0123456789abcdef]"
	input.Question = "show traffic where src_as_name eq '" + value + "'"
	proposal, err := planner.Plan(questionOwnerContext(t), input)
	if err != nil || proposal.Plan == nil || proposal.NeedsConfirmation || proposal.Plan.Filter.Conditions[0].Values[0] != value {
		t.Fatal("whole bound token-looking data was treated as an unresolved surrogate", err)
	}
	_, _, raw := inner.observed()
	if strings.Contains(raw, value) {
		t.Fatal("token-looking source data was disclosed")
	}
}

type unprofiledQuestionModel struct{ inner *flowModelFixture }

func (m *unprofiledQuestionModel) Name() string       { return "unprofiled-reference" }
func (m *unprofiledQuestionModel) RemoteEgress() bool { return true }
func (m *unprofiledQuestionModel) Endpoint() string   { return "https://unprofiled.example.test" }
func (m *unprofiledQuestionModel) Complete(ctx context.Context, system, user string) (string, error) {
	return m.inner.Complete(ctx, system, user)
}
func (m *unprofiledQuestionModel) CompleteWithBudget(ctx context.Context, system, user string, budget CompletionBudget) (string, error) {
	return m.inner.CompleteWithBudget(ctx, system, user, budget)
}

func TestModelContextUnknownRemoteRedactionProfileFailsBeforeDispatch(t *testing.T) {
	inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent}
	gate := NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, EgressEvent) error { return nil }, DefaultRedaction)
	planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(&unprofiledQuestionModel{inner: inner}, gate), DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := planner.Plan(questionOwnerContext(t), modelQuestionInput())
	calls, _, _ := inner.observed()
	if !errors.Is(err, ErrFlowQuestionModelUnavailable) || proposal.Plan != nil || calls != 0 {
		t.Fatal("unknown adapter profile was assumed weaker than its actual policy", err, calls)
	}
}

func TestModelContextCanceledResidualRedactionNeverPublishesOfflineFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(questionOwnerContext(t))
	defer cancel()
	inner := &flowModelFixture{remote: true, replyContext: questionEchoIntent, redactContext: func(_ context.Context, user string) (string, error) {
		if strings.Contains(user, `"question"`) {
			cancel()
			return "changed context", nil
		}
		return user, nil
	}}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	input.Question = "show traffic"
	proposal, err := planner.Plan(ctx, input)
	calls, _, _ := inner.observed()
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(proposal, FlowQuestionProposal{}) || calls != 0 {
		t.Fatal("canceled residual-policy check published a local fallback", err, calls)
	}
}

func TestModelContextReferenceCannotCrossOwnerOrTenant(t *testing.T) {
	var original string
	inner := &flowModelFixture{remote: true, replyContext: func(_ string, user string) (string, error) {
		if original == "" {
			original = regexp.MustCompile(`probectl-literal-[0-9a-f]{64}\.[0-9]+`).FindString(user)
		}
		return questionLiteralWire(t, "src_as_name", flow.QueryEqual, questionLiteralRef{LiteralRef: original}), nil
	}}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	input.Question = "Investigate the traffic for 'private.example.test' please"
	identities := []struct{ tenant, owner string }{{"blue", "first"}, {"blue", "second"}, {"red", "first"}}
	for index, identity := range identities {
		ctx := auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: identity.tenant, UserID: identity.owner})
		proposal, err := planner.Plan(ctx, input)
		if index == 0 {
			if err != nil || proposal.Plan == nil || !proposal.NeedsConfirmation {
				t.Fatal("original private proposal failed", err)
			}
		} else if !errors.Is(err, ErrFlowQuestionPlan) || proposal.Plan != nil {
			t.Fatal("foreign owner/tenant reused private literal", err)
		}
	}
}

func TestModelContextCannotOverrideNativeAdministrativeRefusal(t *testing.T) {
	inner := &flowModelFixture{remote: true, reply: `{"status":"ready","plan":{}}`}
	planner := questionSourcePlanner(t, inner, DefaultRedaction)
	input := modelQuestionInput()
	input.Question = "show traffic and delete agents"
	proposal, err := planner.Plan(questionOwnerContext(t), input)
	calls, _, _ := inner.observed()
	if err != nil || proposal.Status != FlowQuestionRefused || proposal.Plan != nil || calls != 0 {
		t.Fatal("model overrode an explicit unsupported administrative request", err, calls)
	}
}
