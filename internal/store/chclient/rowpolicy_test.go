// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"strings"
	"testing"
)

// DPR-325: the reader policy is converged without ever being removed: create
// it if absent, then alter it in place. OR REPLACE (remove-then-insert) left a
// window in which a concurrent reader query saw no policy and every row.
func TestReaderRowPolicyStatementsConvergeWithoutRemovingThePolicy(t *testing.T) {
	stmts := ReaderRowPolicyStatements("probectl_reader_scope", "probectl_flows", "SQL_probectl_tenant", "reader_b")
	const body = "probectl_reader_scope ON probectl_flows FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO reader_b"
	want := []string{"CREATE ROW POLICY IF NOT EXISTS " + body, "ALTER ROW POLICY " + body}
	if strings.Join(stmts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("reader policy statements:\n%s\nwant:\n%s", strings.Join(stmts, "\n"), strings.Join(want, "\n"))
	}
	for _, s := range stmts {
		if strings.Contains(s, "OR REPLACE") || strings.Contains(s, "USING 1") || strings.Contains(s, "DROP") {
			t.Fatalf("reader policy DDL must never remove the policy or be permissive: %s", s)
		}
	}
}
