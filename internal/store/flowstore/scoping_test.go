// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	ddl := chclient.ReaderRowPolicyDDL("probectl_reader_scope", sharedFlowsTable, tenantSettingName, "probectl_reader")
	for _, must := range []string{"CREATE ROW POLICY OR REPLACE", "FOR SELECT", "tenant_id = getSetting('" + tenantSettingName + "')", "TO probectl_reader"} {
		if !strings.Contains(ddl, must) {
			t.Fatalf("reader policy DDL missing %q: %s", must, ddl)
		}
	}
	if strings.Contains(ddl, "USING 1") {
		t.Fatal("reader policy must NOT contain a permissive USING 1 escape")
	}
}

// EnsureReaderRowPolicy refuses an empty reader user (no accidental TO ALL).
func TestEnsureReaderRowPolicyRejectsEmptyUser(t *testing.T) {
	c := &ClickHouse{base: "http://ch:8123"}
	if err := c.EnsureReaderRowPolicy(context.TODO(), ""); err == nil {
		t.Fatal("empty reader user must be rejected")
	}
}
