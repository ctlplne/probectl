// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// CSVText adds a quoted text prefix to formula-like display cells. A leading
// tab makes encoding/csv quote the complete field; its original text follows
// unchanged. Validated numeric columns use their separate typed path. JSON
// and stored source values never use this presentation encoder.
func CSVText(value string) string {
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\ufeff' })
	first, _ := utf8.DecodeRuneInString(trimmed)
	if strings.HasPrefix(value, "\t") || strings.HasPrefix(value, "\r") || strings.HasPrefix(value, "\n") || strings.ContainsRune("=+-@＝＋－＠", first) {
		return "\t" + value
	}
	return value
}
