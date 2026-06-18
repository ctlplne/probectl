// SPDX-License-Identifier: LicenseRef-probectl-TBD

package migrate

import "strings"

const noTxDirective = "-- probectl:no-tx:"

// hasNoTxDirective recognizes a reviewed, file-level no-transaction migration
// directive. It must be in the leading comment block and carry a reason, so the
// unusual execution mode is visible during review.
func hasNoTxDirective(sql string) bool {
	for _, line := range strings.Split(sql, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "--") {
			return false
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, noTxDirective) {
			return strings.TrimSpace(line[len(noTxDirective):]) != ""
		}
	}
	return false
}
