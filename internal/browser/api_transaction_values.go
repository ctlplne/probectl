// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
)

var (
	errAPIInvalidReference     = errors.New("invalid transaction variable reference")
	errAPICaptureUnavailable   = errors.New("transaction capture is unavailable")
	errAPICaptureNotScalar     = errors.New("transaction capture requires a scalar value")
	errAPISecretUnavailable    = errors.New("transaction secret is unavailable")
	errAPIRequestValueTooLarge = errors.New("transaction request value exceeds its limit")
)

// apiSecretResolver accepts an alias. The caller binds that alias to the
// enrolled tenant's local secret configuration before constructing the driver.
type apiSecretResolver func(ctx context.Context, alias, origin string) ([]byte, func(), error)

// apiTransactionValues belongs to one run. Captures are kept as complete JSON
// values so a whole-value substitution preserves exact numbers and JSON types.
type apiTransactionValues struct {
	captures map[string]apiCapturedValue
	secret   apiSecretResolver
	origin   string
}

type apiCapturedValue struct {
	value  json.RawMessage
	origin string
}

type apiValueReference struct {
	source string
	name   string
}

func parseAPIValueReference(raw string) (apiValueReference, error) {
	source, name, ok := strings.Cut(raw, ".")
	if !ok || (source != "capture" && source != "secret") || !validAPIAlias(name) {
		return apiValueReference{}, errAPIInvalidReference
	}
	return apiValueReference{source: source, name: name}, nil
}

// ValidAPISecretAlias checks the name accepted in an agent-owned binding.
func ValidAPISecretAlias(name string) bool { return validAPIAlias(name) }

func validAPIAlias(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		letter := 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
		valid := letter || c == '_' || i > 0 && ('0' <= c && c <= '9' || c == '-')
		if !valid {
			return false
		}
	}
	return true
}

func (v apiTransactionValues) capture(name string) (json.RawMessage, error) {
	value, ok := v.captures[name]
	if !ok || v.origin == "" || value.origin != v.origin || !json.Valid(value.value) {
		return nil, errAPICaptureUnavailable
	}
	return value.value, nil
}

// render expands references in a header or textual request body. It uses one
// bounded buffer and never includes a template, capture or secret in errors.
func (v apiTransactionValues) render(ctx context.Context, template string, limit int) (string, error) {
	var out strings.Builder
	write := func(part string) error {
		if len(part) > limit-out.Len() {
			return errAPIRequestValueTooLarge
		}
		out.WriteString(part)
		return nil
	}
	for {
		literal, remainder, hasRef := strings.Cut(template, "${")
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := write(literal); err != nil {
			return "", err
		}
		if !hasRef {
			return out.String(), nil
		}
		raw, tail, closed := strings.Cut(remainder, "}")
		if !closed {
			return "", errAPIInvalidReference
		}
		ref, err := parseAPIValueReference(raw)
		if err != nil {
			return "", err
		}
		if err := v.appendScalar(ctx, ref, write); err != nil {
			return "", err
		}
		template = tail
	}
}

func (v apiTransactionValues) appendScalar(ctx context.Context, ref apiValueReference, write func(string) error) error {
	if ref.source == "secret" {
		if v.secret == nil || !strings.HasPrefix(v.origin, "https://") {
			return errAPISecretUnavailable
		}
		value, release, err := v.secret(ctx, ref.name, v.origin)
		if release != nil {
			defer release()
		}
		if err != nil || len(value) == 0 || release == nil {
			return errAPISecretUnavailable
		}
		return write(string(value))
	}
	raw, err := v.capture(ref.name)
	if err != nil {
		return err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return errAPICaptureUnavailable
	}
	switch scalar := value.(type) {
	case string:
		return write(scalar)
	case json.Number:
		return write(scalar.String())
	case bool:
		if scalar {
			return write("true")
		}
		return write("false")
	default:
		return errAPICaptureNotScalar
	}
}

// renderJSONString emits a safely escaped JSON value. Only a whole capture
// reference may substitute a non-string value. Secrets always become strings.
func (v apiTransactionValues) renderJSONString(ctx context.Context, template string, limit int) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if raw, ok := strings.CutPrefix(template, "${"); ok {
		if name, tail, closed := strings.Cut(raw, "}"); closed && tail == "" {
			ref, err := parseAPIValueReference(name)
			if err != nil {
				return nil, err
			}
			if ref.source == "capture" {
				value, err := v.capture(ref.name)
				if len(value) > limit {
					return nil, errAPIRequestValueTooLarge
				}
				return value, err
			}
		}
	}
	rendered, err := v.render(ctx, template, limit)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rendered)
	if len(encoded) > limit {
		return nil, errAPIRequestValueTooLarge
	}
	return encoded, err
}
