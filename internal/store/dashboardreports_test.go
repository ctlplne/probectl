// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store_test

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/migrations"
)

// TestDashboardTenantSchemaIsolation keeps a fast, database-free guard in the
// default suite. The integration sibling proves behavior against real RLS.
func TestDashboardTenantSchemaIsolation(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0061_dashboard_reporting.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, table := range []string{"dashboard_views", "dashboard_report_schedules", "dashboard_report_artifacts"} {
		for _, want := range []string{
			"CREATE TABLE IF NOT EXISTS " + table,
			"ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY",
			"ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY",
			"CREATE POLICY tenant_isolation ON " + table,
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("migration missing %q", want)
			}
		}
	}
	if strings.Count(sql, "tenant_id") < 20 || !strings.Contains(sql, "PRIMARY KEY (tenant_id, id)") {
		t.Fatal("dashboard reporting relationships are not tenant-composite from their first migration")
	}
}

func TestDashboardTenantIdentityFunctionFailsClosedAtStorageLayer(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0062_current_tenant_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, want := range []string{
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, public",
		"public.tenants",
		"pg_catalog.current_setting('probectl.tenant_id', true)",
		"REVOKE ALL ON FUNCTION public.probectl_current_tenant_identity() FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION public.probectl_current_tenant_identity() TO probectl_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("tenant identity function missing %q", want)
		}
	}
	if strings.Contains(sql, "GRANT SELECT ON tenants TO probectl_app") {
		t.Fatal("tenant identity migration grants provider registry enumeration to the app role")
	}
}
