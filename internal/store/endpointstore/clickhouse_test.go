// SPDX-License-Identifier: LicenseRef-probectl-TBD

package endpointstore

import (
	"strings"
	"testing"
)

func TestEndpointDurableMigrationTenantLedAndIdempotent(t *testing.T) {
	migrations := CHMigrations()
	if len(migrations) != 1 || len(migrations[0].Statements) != 1 {
		t.Fatalf("endpoint migration registry = %+v", migrations)
	}
	ddl := migrations[0].Statements[0]
	for _, required := range []string{
		"CREATE TABLE IF NOT EXISTS probectl_endpoint_events",
		"tenant_id String",
		"PARTITION BY (tenant_id, toYYYYMMDD(observed_at))",
		"ORDER BY (tenant_id, observed_at",
		"ReplacingMergeTree",
	} {
		if !strings.Contains(ddl, required) {
			t.Fatalf("endpoint v1 migration missing %q:\n%s", required, ddl)
		}
	}
}
