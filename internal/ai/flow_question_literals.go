// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
)

var errQuestionLiteralMissing = errors.New("flow question needs clarification of a protected filter constraint")
var errQuestionLiteralSurrogate = errors.New("flow question contains an unresolved literal surrogate")

const questionLiteralPrefix = "probectl-literal-"

// This wire choice is internal to model proposals. It is never a public query
// expression, source lookup, tenant selector or executable string template.
type questionLiteralRef struct {
	LiteralRef string `json:"literal_ref"`
}

type questionLiteralEntry struct {
	encoded  string // One complete JSON string, encoded locally from admitted data.
	required bool   // Explicit constraint, not every incidental word in a question.
}

// Bindings are immutable after construction and scoped to ONE planning attempt.
// They deliberately contain no tenant/owner authority or process-wide lookup.
// The caller must authenticate their source question/parent before construction.
type questionLiteralBindings struct {
	entries map[string]questionLiteralEntry
}

type questionLiteralBuilder struct {
	budget    FlowQuestionBudget
	nonce     string
	remaining int
	entries   map[string]questionLiteralEntry
	byValue   map[string]string
	sealed    bool
}

func newQuestionLiteralBuilder(budget FlowQuestionBudget) (*questionLiteralBuilder, error) {
	if budget.Validate() != nil {
		return nil, ErrFlowQuestionBudget
	}
	nonce, err := crypto.Random(32)
	if err != nil {
		return nil, ErrFlowQuestionModelUnavailable
	}
	return &questionLiteralBuilder{
		budget: budget, nonce: hex.EncodeToString(nonce), remaining: budget.Bytes,
		entries: map[string]questionLiteralEntry{}, byValue: map[string]string{},
	}, nil
}

func (b *questionLiteralBuilder) add(ctx context.Context, value string, required bool) (questionLiteralRef, error) {
	if err := ctx.Err(); err != nil {
		return questionLiteralRef{}, err
	}
	if b == nil || b.sealed {
		return questionLiteralRef{}, ErrFlowQuestionInput
	}
	if len(value) > b.budget.Bytes {
		return questionLiteralRef{}, ErrFlowQuestionBudget
	}
	if id, exists := b.byValue[value]; exists {
		entry := b.entries[id]
		entry.required = entry.required || required
		b.entries[id] = entry
		return questionLiteralRef{LiteralRef: id}, nil
	}
	if len(b.entries) >= b.budget.Tokens {
		return questionLiteralRef{}, ErrFlowQuestionBudget
	}
	// Measure encoded expansion before allocation. HTML-sensitive/control bytes
	// and Unicode line separators may be longer in JSON than in the source.
	size, err := questionLiteralEncodedSize(ctx, value, b.remaining)
	if err != nil {
		return questionLiteralRef{}, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) != size {
		return questionLiteralRef{}, ErrFlowQuestionInput
	}
	if err := ctx.Err(); err != nil {
		return questionLiteralRef{}, err
	}
	id := questionLiteralPrefix + b.nonce + "." + strconv.Itoa(len(b.entries)+1)
	if len(id) > b.remaining-size {
		return questionLiteralRef{}, ErrFlowQuestionBudget
	}
	b.remaining -= size + len(id)
	b.entries[id] = questionLiteralEntry{encoded: string(encoded), required: required}
	b.byValue[value] = id
	return questionLiteralRef{LiteralRef: id}, nil
}

func (b *questionLiteralBuilder) seal() *questionLiteralBindings {
	if b == nil || b.sealed {
		return nil
	}
	b.sealed = true
	result := &questionLiteralBindings{entries: b.entries}
	b.entries, b.byValue = nil, nil // The sealed map has no remaining mutable alias.
	return result
}

func questionLiteralEncodedSize(ctx context.Context, value string, limit int) (int, error) {
	if limit < 2 {
		return 0, ErrFlowQuestionBudget
	}
	size := 2 // Quotes.
	for offset := 0; offset < len(value); {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		r, width := utf8.DecodeRuneInString(value[offset:])
		if r == utf8.RuneError && width == 1 {
			return 0, ErrFlowQuestionInput
		}
		cost := width
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			if r < 0x20 {
				cost = 6
			}
		}
		if cost > limit-size {
			return 0, ErrFlowQuestionBudget
		}
		size += cost
		offset += width
	}
	return size, nil
}

type questionLiteralReplacement struct {
	start, end int
	encoded    string
}

// Resolve only complete reference objects at typed predicate-value positions.
// There is no search/replace of substrings, no global unredaction and no remote
// callback. The full original shape must validate before any splice occurs.
func (r *questionJSONReader) literalValues(depth int) error {
	if depth > r.budget.Nesting {
		return ErrFlowQuestionBudget
	}
	token, err := r.token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return ErrFlowQuestionPlan
	}
	for r.decoder.More() {
		if err := r.literalValue(depth + 1); err != nil {
			return err
		}
	}
	return r.close(']')
}

func (r *questionJSONReader) literalValue(depth int) error {
	if depth > r.budget.Nesting {
		return ErrFlowQuestionBudget
	}
	token, err := r.token()
	if err != nil {
		return err
	}
	if text, ordinary := token.(string); ordinary {
		if strings.Contains(text, questionLiteralPrefix) || modelRedactionToken.MatchString(text) {
			return errors.Join(ErrFlowQuestionPlan, errQuestionLiteralSurrogate)
		}
		return nil
	}
	if token != json.Delim('{') {
		return ErrFlowQuestionPlan
	}
	start := int(r.decoder.InputOffset()) - 1
	if depth+1 > r.budget.Nesting {
		return ErrFlowQuestionBudget
	}
	key, err := r.token()
	if err != nil {
		return err
	}
	if key != "literal_ref" {
		return ErrFlowQuestionPlan
	}
	value, err := r.token()
	if err != nil {
		return err
	}
	id, ok := value.(string)
	if !ok || r.decoder.More() {
		return ErrFlowQuestionPlan
	}
	if err := r.close('}'); err != nil {
		return err
	}
	entry, exists := r.literals.entries[id]
	if !exists {
		return ErrFlowQuestionPlan
	}
	end := int(r.decoder.InputOffset())
	delta := len(entry.encoded) - (end - start)
	if delta > r.budget.Bytes-r.expanded {
		return ErrFlowQuestionBudget
	}
	r.expanded += delta
	r.replacements = append(r.replacements, questionLiteralReplacement{start: start, end: end, encoded: entry.encoded})
	r.usedLiterals[id] = true
	return nil
}

func (r *questionJSONReader) bindLiterals(raw string) (string, error) {
	if len(r.replacements) == 0 {
		return raw, nil
	}
	var out strings.Builder
	out.Grow(r.expanded)
	previous := 0
	for _, replacement := range r.replacements {
		if err := r.ctx.Err(); err != nil {
			return "", err
		}
		out.WriteString(raw[previous:replacement.start])
		out.WriteString(replacement.encoded)
		previous = replacement.end
	}
	out.WriteString(raw[previous:])
	return out.String(), nil
}
