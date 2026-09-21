// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import "sort"

// CompletenessCommandCatalog returns the API-backed command candidates used by
// the capability completeness gate. Generated surface commands come from the
// dispatcher's own data. The gate additionally intersects special test/agent
// candidates with the actual switch cases in commands.go, so deleting a real
// shipping branch removes that command from the validated inventory.
func CompletenessCommandCatalog() []string {
	coverage := cliImplementedCoverage()
	commands := make([]string, 0, len(coverage))
	seen := make(map[string]bool, len(coverage))
	for _, item := range coverage {
		if item.Command == "" || item.Command == "none-by-design" || seen[item.Command] {
			continue
		}
		seen[item.Command] = true
		commands = append(commands, item.Command)
	}
	sort.Strings(commands)
	return commands
}
