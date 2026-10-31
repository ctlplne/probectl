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
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

var errQuestionContextUnresolved = errors.New("flow question protected context needs clarification")

// Encode the entire admitted context with finite allocation. Predicate values
// become whole private references; narrative/derived parent output is omitted.
type questionContextEncoder struct {
	ctx              context.Context
	budget           FlowQuestionBudget
	limit            int
	nodes            int
	out              strings.Builder
	literals         *questionLiteralBuilder
	protected        func(string) (bool, error)
	requiredOperands bool
}

func (e *questionContextEncoder) write(value string) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if len(value) > e.limit-e.out.Len() {
		return ErrFlowQuestionBudget
	}
	e.out.WriteString(value)
	return nil
}

func (e *questionContextEncoder) quoted(value string) error {
	if _, err := questionLiteralEncodedSize(e.ctx, value, e.limit-e.out.Len()); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrFlowQuestionInput
	}
	return e.write(string(encoded))
}

func (e *questionContextEncoder) value(value reflect.Value, depth int) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	if depth > e.budget.Nesting || e.nodes >= e.budget.Tokens {
		return ErrFlowQuestionBudget
	}
	e.nodes++
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return e.write("null")
		}
		value = value.Elem()
	}
	if value.Type() == reflect.TypeFor[time.Time]() {
		encoded, err := value.Interface().(time.Time).MarshalJSON()
		if err != nil {
			return ErrFlowQuestionInput
		}
		return e.write(string(encoded))
	}
	switch value.Kind() {
	case reflect.Struct:
		return e.object(value, depth)
	case reflect.Slice, reflect.Array:
		return e.array(value, depth)
	case reflect.String:
		return e.quoted(value.String())
	case reflect.Bool:
		return e.write(strconv.FormatBool(value.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.write(strconv.FormatInt(value.Int(), 10))
	default:
		return ErrFlowQuestionInput
	}
}

func (e *questionContextEncoder) object(value reflect.Value, depth int) error {
	if err := e.write("{"); err != nil {
		return err
	}
	first := true
	for index := 0; index < value.NumField(); index++ {
		field := value.Type().Field(index)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.PkgPath != "" || name == "" || name == "-" || questionContextOmit(value.Type(), name) {
			continue
		}
		entry := value.Field(index)
		if options == "omitempty" && questionContextEmpty(entry) {
			continue
		}
		if !first {
			if err := e.write(","); err != nil {
				return err
			}
		}
		first = false
		if err := e.quoted(name); err != nil {
			return err
		}
		if err := e.write(":"); err != nil {
			return err
		}
		if err := e.field(value.Type(), name, entry, depth+1); err != nil {
			return err
		}
	}
	return e.write("}")
}

func (e *questionContextEncoder) field(owner reflect.Type, name string, value reflect.Value, depth int) error {
	if owner == reflect.TypeFor[questionModelEnvelope]() && name == "parsed_intent" {
		// The independent native parser supplies canonical required operands.
		// Raw question spellings may canonicalize (IPv6/unsigned integers), while
		// an unchanged parent is optional when the explicit intent clears it.
		previous := e.requiredOperands
		e.requiredOperands = true
		defer func() { e.requiredOperands = previous }()
	}
	if owner == reflect.TypeFor[flow.QueryPredicate]() && name == "values" {
		return e.predicateValues(value, depth)
	}
	if owner == reflect.TypeFor[flow.QuerySavedFilterRef]() && name == "id" {
		changed, err := e.protected(value.String())
		if err != nil {
			return err
		}
		if changed {
			// Saved IDs require their own tenant/version-aware role. Never turn
			// a predicate reference into an ID or re-resolve a masked token.
			return errQuestionContextUnresolved
		}
	}
	return e.value(value, depth)
}

func (e *questionContextEncoder) array(value reflect.Value, depth int) error {
	if err := e.write("["); err != nil {
		return err
	}
	for index := 0; index < value.Len(); index++ {
		if index > 0 {
			if err := e.write(","); err != nil {
				return err
			}
		}
		if err := e.value(value.Index(index), depth+1); err != nil {
			return err
		}
	}
	return e.write("]")
}

func (e *questionContextEncoder) predicateValues(value reflect.Value, depth int) error {
	if err := e.write("["); err != nil {
		return err
	}
	for index := 0; index < value.Len(); index++ {
		if depth+1 > e.budget.Nesting || e.nodes >= e.budget.Tokens {
			return ErrFlowQuestionBudget
		}
		e.nodes++
		if index > 0 {
			if err := e.write(","); err != nil {
				return err
			}
		}
		ref, err := e.literals.add(e.ctx, value.Index(index).String(), e.requiredOperands)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(ref)
		if err != nil {
			return ErrFlowQuestionInput
		}
		if err := e.write(string(encoded)); err != nil {
			return err
		}
	}
	return e.write("]")
}

func questionContextOmit(owner reflect.Type, name string) bool {
	if owner != reflect.TypeFor[FlowQuestionProposal]() {
		return false
	}
	switch name {
	case "previous", "guidance", "assumptions", "needs_confirmation":
		return true
	default:
		return false
	}
}

func questionContextEmpty(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return value.Len() == 0
	case reflect.Struct:
		return false // encoding/json does not omit a zero struct.
	default:
		return value.IsZero()
	}
}
