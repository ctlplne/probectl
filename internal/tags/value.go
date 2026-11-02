// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"unicode"
	"unicode/utf8"
)

const (
	// MaxValueCharacters matches the published resource-property UI reach.
	// Values are Unicode code points; UTF-8 bytes are bounded separately.
	MaxValueCharacters = 24000
	MaxValueBytes      = 4 * MaxValueCharacters
	// MaxValueInputBytes admits JSON-escaped supplementary code points and
	// the bounded target/provenance fields without raising global HTTP limits.
	MaxValueInputBytes = 384 << 10
)

// ValidateValue is shared by manual/rule writes, snapshots and source import.
// Large accepted values still consume the caller's existing query budget.
func ValidateValue(value string) error {
	if !validText(value, MaxValueBytes) || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > MaxValueCharacters {
		return ErrInvalid
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ErrInvalid
		}
	}
	return nil
}
