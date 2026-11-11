// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/govern"
)

// Network identities are complete tokens. Other directory aliases retain
// their existing literal metadata policy after identifier admission.
func literalSubjectPattern(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !isSafeContainsIdentifier(value) {
		return "", false
	}
	if pattern, ok := govern.SubjectNetworkPattern(value); ok {
		return pattern, true
	}
	return "(?i)" + regexp.QuoteMeta(value), true
}

func (a subjectAliasSet) exactSubjectValues() (plain, network []string) {
	for _, value := range a.values() {
		if pattern, ok := govern.SubjectNetworkExactPattern(value); ok {
			network = append(network, pattern)
		} else {
			plain = append(plain, strings.ToLower(value))
		}
	}
	return plain, network
}

func subjectExactPredicate(column string) string {
	return `(COALESCE(lower(COALESCE(` + column + `::text,''))=ANY($2::text[]),FALSE)
 OR EXISTS (SELECT 1 FROM unnest($4::text[]) AS subject_exact(value)
 WHERE COALESCE(` + column + `::text,'') ~ subject_exact.value))`
}
