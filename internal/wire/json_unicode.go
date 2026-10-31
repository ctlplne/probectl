// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package wire

import (
	"context"
	"strconv"
	"unicode/utf8"
)

// ExactJSONUnicode refuses malformed UTF-8 and unpaired UTF-16 escapes without
// replacing literal values. Callers must independently validate JSON syntax,
// shape and resource bounds; this function does not parse JSON authority.
func ExactJSONUnicode(ctx context.Context, raw string) bool {
	if ctx.Err() != nil || !utf8.ValidString(raw) {
		return false
	}
	inside := false
	for index := 0; index < len(raw); index++ {
		if index%4096 == 0 && ctx.Err() != nil {
			return false
		}
		if raw[index] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[index] != '\\' {
			continue
		}
		index++
		if index >= len(raw) {
			return false
		}
		if raw[index] != 'u' {
			continue
		}
		if index+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(raw[index+1:index+5], 16, 16)
		if err != nil || (value >= 0xDC00 && value <= 0xDFFF) {
			return false
		}
		index += 4
		if value < 0xD800 || value > 0xDBFF {
			continue
		}
		if index+6 >= len(raw) || raw[index+1:index+3] != `\u` {
			return false
		}
		low, err := strconv.ParseUint(raw[index+3:index+7], 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		index += 6
	}
	return !inside && ctx.Err() == nil
}
