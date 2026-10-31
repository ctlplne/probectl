// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/wire"
)

// decodeFlowQuestionProposal accepts exactly one typed proposal, never a JSON
// fragment extracted from prose. Shape validation happens before decoding so
// encoding/json's duplicate/case-fold/null coercions cannot change its meaning.
func decodeFlowQuestionProposal(ctx context.Context, raw string, budget FlowQuestionBudget, now time.Time) (FlowQuestionProposal, error) {
	return decodeFlowQuestionProposalWithLiterals(ctx, raw, budget, now, nil)
}

func decodeFlowQuestionProposalWithLiterals(ctx context.Context, raw string, budget FlowQuestionBudget, now time.Time, literals *questionLiteralBindings) (FlowQuestionProposal, error) {
	if err := ctx.Err(); err != nil {
		return FlowQuestionProposal{}, err
	}
	if budget.Validate() != nil || len(raw) > budget.Bytes {
		return FlowQuestionProposal{}, ErrFlowQuestionBudget
	}
	if now.IsZero() {
		return FlowQuestionProposal{}, ErrFlowQuestionInput
	}
	if !utf8.ValidString(raw) || !questionJSONUnicode(ctx, raw) {
		if err := ctx.Err(); err != nil {
			return FlowQuestionProposal{}, err
		}
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	reader := questionJSONReader{
		ctx: ctx, decoder: json.NewDecoder(strings.NewReader(raw)), budget: budget,
		fields:   map[reflect.Type]map[string]reflect.Type{},
		literals: literals, usedLiterals: map[string]bool{}, expanded: len(raw),
	}
	reader.decoder.UseNumber()
	if err := reader.value(reflect.TypeFor[FlowQuestionProposal](), 0); err != nil {
		return FlowQuestionProposal{}, err
	}
	if _, err := reader.decoder.Token(); err != io.EOF {
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	raw, err := reader.bindLiterals(raw)
	if err != nil {
		return FlowQuestionProposal{}, err
	}
	var proposal FlowQuestionProposal
	if json.Unmarshal([]byte(raw), &proposal) != nil {
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	result, err := NormalizeFlowQuestionProposal(proposal, now)
	if err != nil {
		return FlowQuestionProposal{}, ErrFlowQuestionPlan
	}
	if err := ctx.Err(); err != nil {
		return FlowQuestionProposal{}, err
	}
	if result.Status == FlowQuestionReady && literals != nil {
		for id, entry := range literals.entries {
			if err := ctx.Err(); err != nil {
				return FlowQuestionProposal{}, err
			}
			if entry.required && !reader.usedLiterals[id] {
				return FlowQuestionProposal{}, errQuestionLiteralMissing
			}
		}
	}
	return result, nil
}

type questionJSONReader struct {
	ctx          context.Context
	decoder      *json.Decoder
	budget       FlowQuestionBudget
	tokens       int
	fields       map[reflect.Type]map[string]reflect.Type
	literals     *questionLiteralBindings
	usedLiterals map[string]bool
	replacements []questionLiteralReplacement
	expanded     int
}

func (r *questionJSONReader) token() (json.Token, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if r.tokens >= r.budget.Tokens {
		return nil, ErrFlowQuestionBudget
	}
	r.tokens++
	token, err := r.decoder.Token()
	if err != nil {
		return nil, ErrFlowQuestionPlan
	}
	return token, nil
}

func (r *questionJSONReader) value(typ reflect.Type, depth int) error {
	if depth > r.budget.Nesting {
		return ErrFlowQuestionBudget
	}
	token, err := r.token()
	if err != nil {
		return err
	}
	if typ.Kind() == reflect.Pointer && token == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if token == nil {
		return ErrFlowQuestionPlan
	}
	if typ == reflect.TypeFor[time.Time]() {
		if _, ok := token.(string); !ok {
			return ErrFlowQuestionPlan
		}
		return nil // time.Time's own decoder validates the exact timestamp next.
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrFlowQuestionPlan
		}
		allowed, seen := r.objectFields(typ), map[string]bool{}
		for r.decoder.More() {
			keyToken, err := r.token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return ErrFlowQuestionPlan
			}
			field, ok := allowed[key]
			if !ok {
				return ErrFlowQuestionPlan
			}
			seen[key] = true
			if typ == reflect.TypeFor[flow.QueryPredicate]() && key == "values" && r.literals != nil {
				if err := r.literalValues(depth + 1); err != nil {
					return err
				}
				continue
			}
			if err := r.value(field, depth+1); err != nil {
				return err
			}
		}
		return r.close('}')
	case reflect.Slice, reflect.Array:
		if token != json.Delim('[') {
			return ErrFlowQuestionPlan
		}
		for r.decoder.More() {
			if err := r.value(typ.Elem(), depth+1); err != nil {
				return err
			}
		}
		return r.close(']')
	case reflect.String:
		if _, ok := token.(string); !ok {
			return ErrFlowQuestionPlan
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrFlowQuestionPlan
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		number, ok := token.(json.Number)
		if !ok {
			return ErrFlowQuestionPlan
		}
		if _, err := strconv.ParseInt(string(number), 10, typ.Bits()); err != nil {
			return ErrFlowQuestionPlan
		}
	default:
		// The plan has no untyped maps/interfaces, backend expressions or tools.
		return ErrFlowQuestionPlan
	}
	return nil
}

func (r *questionJSONReader) close(want json.Delim) error {
	token, err := r.token()
	if err != nil {
		return err
	}
	if token != want {
		return ErrFlowQuestionPlan
	}
	return nil
}

func (r *questionJSONReader) objectFields(typ reflect.Type) map[string]reflect.Type {
	if fields, ok := r.fields[typ]; ok {
		return fields
	}
	fields := questionWireFields(typ)
	r.fields[typ] = fields
	return fields
}

func questionWireFields(typ reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.PkgPath != "" || name == "-" || name == "" {
			continue
		}
		if typ == reflect.TypeFor[FlowQuestionProposal]() && (name == "previous" || name == "needs_confirmation") {
			continue // Derived server output, never a model-supplied query period.
		}
		fields[name] = field.Type
	}
	return fields
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Refuse those
// instead of silently changing an exact filter literal. Valid surrogate pairs,
// literal Unicode and escaped backslashes keep their original meaning.
func questionJSONUnicode(ctx context.Context, raw string) bool {
	return wire.ExactJSONUnicode(ctx, raw)
}
