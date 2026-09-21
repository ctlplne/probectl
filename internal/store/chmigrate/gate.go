// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chmigrate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ClickHouse migration-gate (SCHEMA-001).
//
// The Postgres expand/contract gate (internal/store/migrate) never covered the
// Go-embedded ClickHouse DDL, so a destructive DROP/RENAME on a telemetry store
// (flow/eBPF/OTLP/path) could merge with a green build. This gate closes that
// hole: it lints every store's chMigrations() and FAILS on a destructive
// statement unless the migration is explicitly annotated Destructive with a
// Justification (the typed pre-GA exception the SCHEMA findings require —
// enforced, not prose).
//
// ClickHouse has no transactional DDL, so the rules differ from Postgres: a
// RENAME TABLE here is the ATOMIC swap used to rebuild a table (the data is
// preserved under the _pre_dedup name first), and DROP TABLE discards data.
// Both are flagged; both need the annotation to ship.

// CHViolation is one destructive ClickHouse-DDL statement that lacks an
// annotated exception.
type CHViolation struct {
	Component string
	Version   int
	Name      string
	Rule      string
	Statement string
}

func (v CHViolation) String() string {
	return fmt.Sprintf("%s %04d_%s: %s — %s", v.Component, v.Version, v.Name, v.Rule, v.Statement)
}

var (
	chDropTable   = regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)
	chRenameTable = regexp.MustCompile(`(?i)\bRENAME\s+TABLE\b`)
	chWSRun       = regexp.MustCompile(`\s+`)
)

// CheckMigrations returns the destructive-DDL violations in one component's
// migration list. A DROP TABLE / RENAME TABLE statement is a violation UNLESS
// the migration sets Destructive:true with a non-empty Justification.
func CheckMigrations(component string, ms []Migration) []CHViolation {
	var out []CHViolation
	for _, m := range ms {
		// An annotated-destructive migration MUST carry a justification.
		if m.Destructive && strings.TrimSpace(m.Justification) == "" {
			out = append(out, CHViolation{
				Component: component, Version: m.Version, Name: m.Name,
				Rule:      "Destructive migration without a Justification",
				Statement: "(set chmigrate.Migration.Justification)",
			})
			continue
		}
		for _, stmt := range m.Statements {
			norm := strings.TrimSpace(chWSRun.ReplaceAllString(stmt, " "))
			var rule string
			switch {
			case chDropTable.MatchString(norm):
				rule = "DROP TABLE on a telemetry store (data loss — set Destructive:true + a Justification, or make it data-preserving)"
			case chRenameTable.MatchString(norm):
				rule = "RENAME TABLE on a telemetry store (table rewrite — set Destructive:true + a Justification)"
			default:
				continue
			}
			if m.Destructive {
				continue // annotated + justified exception
			}
			out = append(out, CHViolation{
				Component: component, Version: m.Version, Name: m.Name,
				Rule: rule, Statement: trimCH(norm),
			})
		}
	}
	return out
}

// CheckAll runs CheckMigrations over a set of components and returns the
// violations sorted by component+version. The gate test passes the live
// chMigrations() of every store (flow/eBPF/OTLP/path) so a destructive change
// to any of them reddens the build.
func CheckAll(sets map[string][]Migration) []CHViolation {
	var out []CHViolation
	for component, ms := range sets {
		out = append(out, CheckMigrations(component, ms)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func trimCH(s string) string {
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}
