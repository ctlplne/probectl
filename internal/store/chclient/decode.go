// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// Decode parses a ClickHouse JSONEachRow response body into row maps.
func Decode(body []byte) ([]map[string]any, error) {
	var rows []map[string]any
	for _, line := range bytes.Split(body, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row map[string]any
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&row); err != nil {
			return nil, fmt.Errorf("chclient: decode row: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Float coerces a JSONEachRow cell (number or numeric string) to float64.
func Float(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(n, 64)
		return f
	}
	return 0
}

// Uint64 coerces an integer JSONEachRow cell to uint64 without passing exact
// counters through float64. ClickHouse may emit UInt64 values as JSON numbers
// or strings; both forms are parsed as decimal integers first.
func Uint64(v any) uint64 {
	switch n := v.(type) {
	case json.Number:
		u, err := strconv.ParseUint(n.String(), 10, 64)
		if err == nil {
			return u
		}
		f, _ := n.Float64()
		return uint64(f)
	case string:
		u, err := strconv.ParseUint(n, 10, 64)
		if err == nil {
			return u
		}
		f, _ := strconv.ParseFloat(n, 64)
		return uint64(f)
	case float64:
		return uint64(n)
	case uint64:
		return n
	case uint32:
		return uint64(n)
	case int:
		if n > 0 {
			return uint64(n)
		}
	case int64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

// String coerces a cell to string ("" when not a string).
func String(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Int coerces a cell to int (via Float).
func Int(v any) int { return int(Float(v)) }

// UintSlice coerces a ClickHouse array cell to []uint32.
func UintSlice(v any) []uint32 {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]uint32, 0, len(arr))
	for _, e := range arr {
		out = append(out, uint32(Uint64(e)))
	}
	return out
}

// Count extracts a single count() result keyed "n".
func Count(rows []map[string]any) int {
	if len(rows) == 0 {
		return 0
	}
	return Int(rows[0]["n"])
}
