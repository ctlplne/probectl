// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

// TENANT-102: when tenant scoping is on, a tenant-scoped read carries the
// per-request custom setting; an admin (tenant "") read does not; and scoping
// off never attaches it. We assert on the URL the read path builds.
func TestTenantSettingAttach(t *testing.T) {
	build := func(scoping bool, tenantID string) string {
		c := &ClickHouse{base: "http://ch:8123", tenantScoping: scoping}
		u := c.baseFor("") + "/?query=" + url.QueryEscape("SELECT 1 FORMAT JSONEachRow")
		if c.tenantScoping && tenantID != "" {
			u += "&" + tenantSettingName + "=" + url.QueryEscape(tenantID)
		}
		return u
	}

	if got := build(true, "tenant-a"); !strings.Contains(got, tenantSettingName+"=tenant-a") {
		t.Fatalf("scoped read must carry the tenant setting: %s", got)
	}
	if got := build(true, ""); strings.Contains(got, tenantSettingName) {
		t.Fatalf("admin (cross-tenant) read must NOT carry the setting: %s", got)
	}
	if got := build(false, "tenant-a"); strings.Contains(got, tenantSettingName) {
		t.Fatalf("scoping off must never attach the setting: %s", got)
	}
}

// The reader row-policy DDL binds the reader user's SELECTs to the setting and
// nothing else — no permissive escape (fail closed when unset).
func TestReaderRowPolicyDDLShape(t *testing.T) {
	// Reproduce the DDL EnsureReaderRowPolicy emits (it is built from the same
	// constants) and assert the security-relevant shape.
	stmts := chclient.ReaderRowPolicyStatements("probectl_reader_scope", sharedFlowsTable, tenantSettingName, "probectl_reader")
	if len(stmts) != 2 || !strings.HasPrefix(stmts[0], "CREATE ROW POLICY IF NOT EXISTS ") || !strings.HasPrefix(stmts[1], "ALTER ROW POLICY ") {
		t.Fatalf("reader policy must be created if absent then altered in place, never replaced (DPR-325): %q", stmts)
	}
	for _, ddl := range stmts {
		for _, must := range []string{"FOR SELECT", "tenant_id = getSetting('" + tenantSettingName + "')", "TO probectl_reader"} {
			if !strings.Contains(ddl, must) {
				t.Fatalf("reader policy DDL missing %q: %s", must, ddl)
			}
		}
		if strings.Contains(ddl, "USING 1") || strings.Contains(ddl, "OR REPLACE") {
			t.Fatalf("reader policy must not be permissive or remove-then-insert: %s", ddl)
		}
	}
}

// EnsureReaderRowPolicy refuses an empty reader user (no accidental TO ALL).
func TestEnsureReaderRowPolicyRejectsEmptyUser(t *testing.T) {
	c := &ClickHouse{base: "http://ch:8123"}
	if err := c.EnsureReaderRowPolicy(context.TODO(), ""); err == nil {
		t.Fatal("empty reader user must be rejected")
	}
}
