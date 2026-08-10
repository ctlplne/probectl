// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantlife

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/migrations"
)

func TestCorrelationOverrideMigrationAttachesTenantWriteFence(t *testing.T) {
	body, err := migrations.FS.ReadFile("0091_incident_correlation_overrides.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, required := range []string{
		"CREATE TRIGGER tenant_write_fence",
		"BEFORE INSERT OR UPDATE ON public.incident_correlation_overrides",
		"EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()",
		"ENABLE ALWAYS TRIGGER tenant_write_fence",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 0091 is missing durable write-fence clause %q", required)
		}
	}
}
