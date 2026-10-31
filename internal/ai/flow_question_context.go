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
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/flow"
)

type flowQuestionModelContext struct {
	user     string
	literals *questionLiteralBindings
	expected *FlowQuestionProposal
	refused  *FlowQuestionProposal
}

type questionModelEnvelope struct {
	Question string                `json:"question"`
	Parent   *FlowQuestionProposal `json:"parent,omitempty"`
	Intent   *FlowQuestionProposal `json:"parsed_intent,omitempty"`
	Now      string                `json:"now"`
	TimeZone string                `json:"time_zone"`
	Locale   string                `json:"locale"`
}

func (p *ModelFlowQuestionPlanner) modelContext(ctx context.Context, input FlowQuestionInput, parent *FlowQuestionProposal, location *time.Location) (flowQuestionModelContext, error) {
	result := flowQuestionModelContext{}
	expected, err := p.native.Plan(ctx, input)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrFlowQuestionBudget) {
		return result, err
	}
	if err == nil && expected.Status == FlowQuestionReady {
		result.expected = &expected
	}
	if err == nil && expected.Status == FlowQuestionRefused {
		result.refused = &expected
		return result, nil
	}
	literals, err := newQuestionLiteralBuilder(p.budget)
	if err != nil {
		return result, err
	}
	protected := func(value string) (bool, error) {
		redacted, err := p.completer.previewCompletionPrompt(ctx, value)
		return redacted != value, err
	}
	question, err := questionPrivateSource(ctx, input.Question, p.budget, literals, result.expected, protected)
	if err != nil {
		return result, err
	}
	envelope := questionModelEnvelope{Question: question, Parent: parent, Intent: result.expected, Now: input.Now.UTC().Format(time.RFC3339Nano), TimeZone: location.String(), Locale: input.Locale}
	encoder := questionContextEncoder{ctx: ctx, budget: p.budget, limit: p.budget.Bytes - len(p.system), literals: literals, protected: protected}
	if err := encoder.value(reflect.ValueOf(envelope), 0); err != nil {
		return result, err
	}
	result.user = encoder.out.String()
	preview, err := p.completer.previewCompletionPrompt(ctx, result.user)
	if err != nil {
		return result, err
	}
	if preview != result.user {
		// Custom patterns can span words or alter reference/grammar bytes.
		// Preserve the real policies; never dispatch silently changed context.
		return result, errQuestionContextUnresolved
	}
	result.literals = literals.seal()
	return result, nil
}

// Whole quoted values and policy-sensitive unquoted words remain local.
// Contractions are ordinary prose. Source offsets preserve every other byte.
func questionPrivateSource(ctx context.Context, question string, budget FlowQuestionBudget, literals *questionLiteralBuilder, expected *FlowQuestionProposal, protected func(string) (bool, error)) (string, error) {
	tokens, err := questionPrivateSourceTokens(ctx, question, budget, expected != nil)
	if err != nil {
		return "", err
	}
	operands := questionExpectedOperandValues(expected)
	encoder := questionContextEncoder{ctx: ctx, budget: budget, limit: budget.Bytes}
	previous := 0
	for _, token := range tokens {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		value, start, end, quoted := token.text, token.start, token.end, token.quoted
		changed, err := protected(value)
		if err != nil {
			return "", err
		}
		if !quoted && !changed && !questionNativeOperand(value, operands) {
			continue
		}
		hint := questionPublicLiteralHint(value)
		required := expected == nil && hint == ""
		ref, err := literals.add(ctx, value, required)
		if err != nil {
			return "", err
		}
		annotation, err := json.Marshal(struct {
			LiteralRef string `json:"literal_ref"`
			PublicHint string `json:"public_hint,omitempty"`
		}{ref.LiteralRef, hint})
		if err != nil {
			return "", ErrFlowQuestionInput
		}
		if err := encoder.write(question[previous:start]); err != nil {
			return "", err
		}
		if err := encoder.write(string(annotation)); err != nil {
			return "", err
		}
		previous = end
	}
	if err := encoder.write(question[previous:]); err != nil {
		return "", err
	}
	return encoder.out.String(), nil
}

// Fully parsed native questions supply exact lexer offsets, including adjacent
// operators (field=value). Unknown prose keeps contractions and conservative
// whole-word policy recognition; the final full-policy preview still applies.
func questionPrivateSourceTokens(ctx context.Context, question string, budget FlowQuestionBudget, native bool) ([]questionToken, error) {
	if native {
		return lexFlowQuestion(ctx, question, budget)
	}
	var tokens []questionToken
	for offset := 0; offset < len(question); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, size := utf8.DecodeRuneInString(question[offset:])
		if unicode.IsSpace(r) || strings.ContainsRune(",;(){}[]", r) {
			offset += size
			continue
		}
		if len(tokens) >= budget.Tokens {
			return nil, ErrFlowQuestionBudget
		}
		start := offset
		quoted := r == '\'' || r == '"' || r == '`'
		value, end, err := questionPrivateWord(question, offset, quoted)
		if err != nil {
			return nil, errQuestionContextUnresolved
		}
		tokens = append(tokens, questionToken{text: value, start: start, end: end, quoted: quoted})
		offset = end
	}
	return tokens, nil
}

func questionExpectedOperandValues(expected *FlowQuestionProposal) map[string]bool {
	values := map[string]bool{}
	if expected == nil || expected.Plan == nil {
		return values
	}
	var visit func(*flow.QueryFilterGroup)
	visit = func(group *flow.QueryFilterGroup) {
		if group == nil {
			return
		}
		for _, predicate := range group.Conditions {
			for _, value := range predicate.Values {
				values[value] = true
			}
		}
		for index := range group.Groups {
			visit(&group.Groups[index])
		}
	}
	visit(expected.Plan.Filter)
	return values
}

func questionNativeOperand(value string, values map[string]bool) bool {
	if values[value] || values[strings.TrimSpace(value)] {
		return true
	}
	if number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil && values[strconv.FormatUint(number, 10)] {
		return true
	}
	if address, err := netip.ParseAddr(value); err == nil && values[address.Unmap().String()] {
		return true
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && values[prefix.Masked().String()] {
		return true
	}
	return false
}

func questionPrivateWord(question string, offset int, quoted bool) (string, int, error) {
	if quoted {
		return quotedQuestionValue(question, offset, question[offset])
	}
	end := offset
	for end < len(question) {
		r, size := utf8.DecodeRuneInString(question[end:])
		if unicode.IsSpace(r) || strings.ContainsRune(",;(){}[]\"`", r) {
			break
		}
		end += size
	}
	return question[offset:end], end, nil
}

func questionPublicLiteralHint(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	for _, name := range []string{"table", "bar", "line", "timeline", "matrix", "raw", "rollup", "auto", "horizon", "stacked", "stacked_area", "area", "overlaid", "all", "any", "include", "exclude"} {
		if key == name {
			return name
		}
	}
	for _, field := range flow.QueryFields() {
		if key == field.Name {
			return field.Name
		}
		for _, operator := range field.Operators {
			if key == string(operator) {
				return string(operator)
			}
		}
	}
	for _, metric := range flow.QueryMetricDefinitions() {
		if key == metric.Name {
			return metric.Name
		}
		for _, calculation := range metric.Calculations {
			if key == calculation {
				return calculation
			}
		}
	}
	return ""
}

func questionModelIntentMatches(proposal FlowQuestionProposal, expected *FlowQuestionProposal) bool {
	return expected != nil && reflect.DeepEqual(proposal.Plan, expected.Plan) && reflect.DeepEqual(proposal.Comparison, expected.Comparison) && reflect.DeepEqual(proposal.Display, expected.Display)
}
