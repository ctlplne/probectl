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

func TestDiagnosticsTopologyFunctionFailsClosedAtStorageLayer(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0069_tenant_diagnostics_topology.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, want := range []string{
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, public",
		"public.tenants",
		"pg_catalog.current_setting('probectl.tenant_id', true)",
		"REVOKE ALL ON FUNCTION public.probectl_current_tenant_topology() FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION public.probectl_current_tenant_topology() TO probectl_app",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("tenant diagnostics topology function missing %q", want)
		}
	}
	if strings.Contains(sql, "GRANT SELECT ON tenants TO probectl_app") {
		t.Fatal("tenant diagnostics migration grants provider registry enumeration to the app role")
	}
}
