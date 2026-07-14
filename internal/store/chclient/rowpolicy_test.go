// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
