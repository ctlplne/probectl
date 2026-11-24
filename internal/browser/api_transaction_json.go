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
	"io"
	"maps"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	errAPIJSONDocument = errors.New("transaction response is not one unambiguous JSON value")
	errAPIJSONPath     = errors.New("transaction JSON path is invalid or unsupported")
	errAPIJSONWork     = errors.New("transaction JSON selection exceeds its work limit")
)

func decodeAPIJSON(ctx context.Context, raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readAPIJSON(ctx, decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errAPIJSONDocument
	}
	return value, nil
}

func readAPIJSON(ctx context.Context, decoder *json.Decoder) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errAPIJSONDocument
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, errAPIJSONDocument
			}
			if _, found := object[key]; found {
				return nil, errAPIJSONDocument
			}
			child, err := readAPIJSON(ctx, decoder)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errAPIJSONDocument
		}
		return object, nil
	case json.Delim('['):
		array := []any{}
		for decoder.More() {
			child, err := readAPIJSON(ctx, decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errAPIJSONDocument
		}
		return array, nil
	default:
		return token, nil
	}
}

type apiJSONSegment struct {
	descend   bool
	selectors []apiJSONSelector
}

type apiJSONSelector struct {
	kind       byte
	name       string
	index      int64
	arraySlice apiJSONArraySlice
}

type apiJSONArraySlice struct {
	start, end *int64
	step       int64
}

func parseAPIJSONPath(path string) ([]apiJSONSegment, error) {
	path, ok := strings.CutPrefix(strings.TrimSpace(path), "$")
	if !ok {
		return nil, errAPIJSONPath
	}
	var segments []apiJSONSegment
	for path != "" {
		segment := apiJSONSegment{}
		if after, ok := strings.CutPrefix(path, ".."); ok {
			segment.descend, path = true, after
		} else if after, ok := strings.CutPrefix(path, "."); ok {
			path = after
			if strings.HasPrefix(path, "[") {
				return nil, errAPIJSONPath
			}
		} else if !strings.HasPrefix(path, "[") {
			return nil, errAPIJSONPath
		}
		if after, ok := strings.CutPrefix(path, "["); ok {
			var err error
			segment.selectors, path, err = parseAPIJSONSelectorList(after)
			if err != nil {
				return nil, err
			}
		} else if after, ok := strings.CutPrefix(path, "*"); ok {
			segment.selectors, path = []apiJSONSelector{{kind: '*'}}, after
		} else {
			size := apiJSONShorthandLength(path)
			if size == 0 {
				return nil, errAPIJSONPath
			}
			segment.selectors, path = []apiJSONSelector{{kind: 'n', name: path[:size]}}, path[size:]
		}
		segments = append(segments, segment)
	}
	return segments, nil
}

func apiJSONShorthandLength(path string) int {
	size := 0
	for size < len(path) {
		r, width := utf8.DecodeRuneInString(path[size:])
		valid := r == '_' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' ||
			r >= utf8.RuneSelf && (r != utf8.RuneError || width > 1) || size > 0 && '0' <= r && r <= '9'
		if !valid {
			break
		}
		size += width
	}
	return size
}

func parseAPIJSONSelectorList(input string) ([]apiJSONSelector, string, error) {
	var selectors []apiJSONSelector
	for {
		input = strings.TrimLeft(input, " \t\r\n")
		if input == "" {
			return nil, "", errAPIJSONPath
		}
		var selector apiJSONSelector
		if input[0] == '\'' || input[0] == '"' {
			name, tail, err := apiJSONQuotedName(input)
			if err != nil {
				return nil, "", err
			}
			selector, input = apiJSONSelector{kind: 'n', name: name}, tail
		} else {
			end := strings.IndexAny(input, ",]")
			if end < 0 {
				return nil, "", errAPIJSONPath
			}
			value := strings.TrimSpace(input[:end])
			input = input[end:]
			switch {
			case value == "*":
				selector.kind = '*'
			case strings.Contains(value, ":"):
				bounds, ok := parseAPIJSONArraySlice(value)
				if !ok {
					return nil, "", errAPIJSONPath
				}
				selector = apiJSONSelector{kind: 's', arraySlice: bounds}
			default:
				index, ok := parseAPIJSONIndex(value)
				if !ok {
					return nil, "", errAPIJSONPath
				}
				selector = apiJSONSelector{kind: 'i', index: index}
			}
		}
		selectors = append(selectors, selector)
		input = strings.TrimLeft(input, " \t\r\n")
		if tail, ok := strings.CutPrefix(input, "]"); ok {
			return selectors, tail, nil
		}
		tail, ok := strings.CutPrefix(input, ",")
		if !ok {
			return nil, "", errAPIJSONPath
		}
		input = tail
	}
}

func parseAPIJSONIndex(value string) (int64, bool) {
	index, err := strconv.ParseInt(value, 10, 64)
	const maximumExactJSONInteger = 1<<53 - 1
	return index, err == nil && index >= -maximumExactJSONInteger && index <= maximumExactJSONInteger &&
		strconv.FormatInt(index, 10) == value
}

func parseAPIJSONArraySlice(value string) (apiJSONArraySlice, bool) {
	parts := strings.SplitN(value, ":", 4)
	if len(parts) < 2 || len(parts) > 3 {
		return apiJSONArraySlice{}, false
	}
	start, startOK := parseAPIJSONSliceBound(parts[0])
	end, endOK := parseAPIJSONSliceBound(parts[1])
	if !startOK || !endOK {
		return apiJSONArraySlice{}, false
	}
	result := apiJSONArraySlice{start: start, end: end, step: 1}
	if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
		step, ok := parseAPIJSONIndex(strings.TrimSpace(parts[2]))
		if !ok {
			return apiJSONArraySlice{}, false
		}
		result.step = step
	}
	return result, true
}

func parseAPIJSONSliceBound(value string) (*int64, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, true
	}
	index, ok := parseAPIJSONIndex(trimmed)
	return &index, ok
}

func apiJSONQuotedName(input string) (string, string, error) {
	quote := input[0]
	var encoded strings.Builder
	encoded.WriteByte('"')
	for i := 1; i < len(input); i++ {
		c := input[i]
		if c == quote {
			encoded.WriteByte('"')
			var name string
			if err := json.Unmarshal([]byte(encoded.String()), &name); err != nil {
				return "", "", errAPIJSONPath
			}
			return name, input[i+1:], nil
		}
		if c == '\\' {
			i++
			if i == len(input) {
				return "", "", errAPIJSONPath
			}
			if quote != '\'' || input[i] != '\'' {
				encoded.WriteByte('\\')
			}
			encoded.WriteByte(input[i])
			continue
		}
		if c == '"' {
			encoded.WriteByte('\\')
		}
		encoded.WriteByte(c)
	}
	return "", "", errAPIJSONPath
}

func selectAPIJSON(ctx context.Context, value any, segments []apiJSONSegment, limit int) ([]any, error) {
	input := []any{value}
	charge := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if limit <= 0 {
			return errAPIJSONWork
		}
		limit--
		return nil
	}
	for _, segment := range segments {
		var output []any
		collect := func(node any) error {
			if err := charge(); err != nil {
				return err
			}
			output = append(output, node)
			return nil
		}
		visit := func(node any) error {
			if err := charge(); err != nil {
				return err
			}
			for _, selector := range segment.selectors {
				if err := selector.apply(node, collect); err != nil {
					return err
				}
			}
			return nil
		}
		for _, node := range input {
			if segment.descend {
				if err := walkAPIJSON(node, visit); err != nil {
					return nil, err
				}
			} else if err := visit(node); err != nil {
				return nil, err
			}
		}
		input = output
	}
	return input, nil
}

func (s apiJSONSelector) apply(node any, collect func(any) error) error {
	switch s.kind {
	case 'n':
		if object, ok := node.(map[string]any); ok {
			if value, found := object[s.name]; found {
				return collect(value)
			}
		}
	case 'i':
		if array, ok := node.([]any); ok {
			index, size := s.index, int64(len(array))
			if index < 0 {
				index += size
			}
			if index >= 0 && index < size {
				return collect(array[index])
			}
		}
	case '*':
		return apiJSONChildren(node, collect)
	case 's':
		if array, ok := node.([]any); ok {
			return s.arraySlice.selectFrom(array, collect)
		}
	}
	return nil
}

// selectFrom follows JSONPath's half-open bounds, negative index normalization
// and reverse traversal. A zero step selects no values.
func (s apiJSONArraySlice) selectFrom(array []any, collect func(any) error) error {
	if s.step == 0 || len(array) == 0 {
		return nil
	}
	size := int64(len(array))
	bound := func(input *int64, fallback, minBound, maxBound int64) int64 {
		if input == nil {
			return fallback
		}
		index := *input
		if index < 0 {
			index += size
		}
		return max(minBound, min(maxBound, index))
	}
	if s.step > 0 {
		start := bound(s.start, 0, 0, size)
		end := bound(s.end, size, 0, size)
		for i := start; i < end; i += s.step {
			if err := collect(array[i]); err != nil {
				return err
			}
		}
		return nil
	}
	start := bound(s.start, size-1, -1, size-1)
	end := bound(s.end, -1, -1, size-1)
	for i := start; i > end; i += s.step {
		if err := collect(array[i]); err != nil {
			return err
		}
	}
	return nil
}

func walkAPIJSON(node any, visit func(any) error) error {
	if err := visit(node); err != nil {
		return err
	}
	return apiJSONChildren(node, func(child any) error { return walkAPIJSON(child, visit) })
}

func apiJSONChildren(node any, visit func(any) error) error {
	switch value := node.(type) {
	case []any:
		for _, child := range value {
			if err := visit(child); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(value)) {
			if err := visit(value[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

func equalAPIJSON(ctx context.Context, left, right any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	switch value := left.(type) {
	case nil:
		return right == nil, nil
	case bool:
		other, ok := right.(bool)
		return ok && value == other, nil
	case string:
		other, ok := right.(string)
		return ok && value == other, nil
	case json.Number:
		other, ok := right.(json.Number)
		return ok && normalizedAPIDecimal(value) == normalizedAPIDecimal(other), nil
	case []any:
		other, ok := right.([]any)
		if !ok || len(value) != len(other) {
			return false, nil
		}
		for i, entry := range value {
			match, err := equalAPIJSON(ctx, entry, other[i])
			if err != nil || !match {
				return match, err
			}
		}
		return true, nil
	case map[string]any:
		other, ok := right.(map[string]any)
		if !ok || len(value) != len(other) {
			return false, nil
		}
		for key, entry := range value {
			candidate, found := other[key]
			if !found {
				return false, nil
			}
			match, err := equalAPIJSON(ctx, entry, candidate)
			if err != nil || !match {
				return match, err
			}
		}
		return true, nil
	default:
		return false, errAPIJSONDocument
	}
}

type apiDecimal struct {
	negative bool
	digits   string
	exponent string
}

// Normalize the representation instead of expanding 10^exponent or converting
// through a float. Large integers remain exact and a huge exponent only costs
// work proportional to its encoded length.
func normalizedAPIDecimal(number json.Number) apiDecimal {
	raw, negative := strings.CutPrefix(number.String(), "-")
	exponent := "0"
	if delimiter := strings.IndexAny(raw, "eE"); delimiter >= 0 {
		raw, exponent = raw[:delimiter], raw[delimiter+1:]
	}
	whole, fraction, _ := strings.Cut(raw, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return apiDecimal{}
	}
	significand := strings.TrimRight(digits, "0")
	adjustment := len(digits) - len(significand) - len(fraction)
	return apiDecimal{negative: negative, digits: significand, exponent: adjustedAPIExponent(exponent, adjustment)}
}

func adjustedAPIExponent(raw string, adjustment int) string {
	negative := strings.HasPrefix(raw, "-")
	digits := strings.TrimLeft(strings.TrimLeft(raw, "+-"), "0")
	if len(digits) <= 19 {
		// The small case can cross zero. Parse only the bounded significant
		// exponent, so a long leading-zero run never enters big.Int.
		var exponent big.Int
		if digits != "" {
			exponent.SetString(digits, 10)
		}
		if negative {
			exponent.Neg(&exponent)
		}
		return exponent.Add(&exponent, big.NewInt(int64(adjustment))).String()
	}
	// Here the magnitude exceeds every possible adjustment, so the sign is
	// stable. Carry through decimal digits without parsing an enormous integer.
	if negative {
		adjustment = -adjustment
	}
	if adjustment != 0 {
		out := []byte(digits)
		for i := len(out) - 1; i >= 0 && adjustment != 0; i-- {
			digit := int(out[i]-'0') + adjustment%10
			adjustment /= 10
			if digit < 0 {
				digit += 10
				adjustment--
			} else if digit >= 10 {
				digit -= 10
				adjustment++
			}
			out[i] = "0123456789"[digit]
		}
		digits = strings.TrimLeft(string(out), "0")
		if adjustment > 0 {
			digits = strconv.Itoa(adjustment) + string(out)
		}
	}
	if negative {
		return "-" + digits
	}
	return digits
}
