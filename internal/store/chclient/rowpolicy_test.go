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

func TestReaderRowPolicyDDLReplacesTheCurrentUserBinding(t *testing.T) {
	ddl := ReaderRowPolicyDDL(
		"probectl_reader_scope",
		"probectl_flows",
		"SQL_probectl_tenant",
		"reader_b",
	)
	for _, want := range []string{
		"CREATE ROW POLICY OR REPLACE probectl_reader_scope ON probectl_flows",
		"FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant')",
		"TO reader_b",
	} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("reader policy DDL missing %q: %s", want, ddl)
		}
	}
	if strings.Contains(ddl, "IF NOT EXISTS") || strings.Contains(ddl, "USING 1") {
		t.Fatalf("reader policy must replace stale bindings and never be permissive: %s", ddl)
	}
}
