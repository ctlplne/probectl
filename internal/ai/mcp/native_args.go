// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/flow"
)

const nativeFlowRequestBytes = flow.MaxPlanGrammarBytes + 16*1024

// Native arguments reject duplicates, case-fold aliases, unknown fields and
// trailing data before decoding into the same typed public registry grammar.
func decodeNativeArgs(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if err := nativeJSONSyntax(raw, nativeFlowRequestBytes); err != nil {
		return err
	}
	if err := nativeArgumentShape(raw, reflect.TypeOf(dst), 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return argErr("native flow arguments do not match the declared types")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return argErr("native flow arguments contain trailing data")
	}
	return nil
}

func nativeJSONSyntax(raw json.RawMessage, maxBytes int) error {
	return boundedJSONObjectSyntax(raw, maxBytes, true)
}

func boundedJSONObjectSyntax(raw json.RawMessage, maxBytes int, foldKeys bool) error {
	if len(raw) > maxBytes || !utf8.Valid(raw) || !json.Valid(raw) {
		return argErr("invalid native flow JSON or byte budget")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return argErr("native flow arguments must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if depth > 32 || nodes > 1<<20 {
			return argErr("native flow JSON exceeds structural budget")
		}
		token, err := dec.Token()
		if err != nil {
			return argErr("invalid native flow JSON")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				token, err := dec.Token()
				if err != nil {
					return argErr("invalid native flow object")
				}
				key, ok := token.(string)
				if !ok {
					return argErr("invalid native flow field")
				}
				if foldKeys {
					key = strings.ToLower(key)
				}
				if seen[key] {
					return argErr("duplicate native flow field")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return argErr("invalid native flow JSON container")
		}
		if _, err := dec.Token(); err != nil {
			return argErr("invalid native flow JSON closing delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	return nil
}

// encoding/json accepts case-insensitive field aliases. Require canonical
// public JSON names instead so the schema and the accepted authority agree.
func nativeArgumentShape(raw json.RawMessage, typ reflect.Type, depth int) error {
	if depth > 32 {
		return argErr("native flow JSON exceeds structural budget")
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || typ == reflect.TypeFor[time.Time]() {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return argErr("native flow object is invalid")
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			allowed[name] = field.Type
		}
		for key, value := range fields {
			field, ok := allowed[key]
			if !ok {
				return argErr("unknown or noncanonical native flow field")
			}
			if err := nativeArgumentShape(value, field, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return argErr("native flow array is invalid")
		}
		for _, value := range values {
			if err := nativeArgumentShape(value, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map, reflect.Interface:
		return argErr("native flow arguments require declared field types")
	}
	return nil
}
