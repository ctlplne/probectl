// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpointstore

import (
	"context"
	"errors"
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

func TestEndpointTargetRouterReceivesOperationContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	c := (&ClickHouse{}).WithRouter(func(got context.Context, tenantID string) (Target, error) {
		called = true
		if tenantID != "tenant-a" {
			t.Fatalf("router tenant = %q, want tenant-a", tenantID)
		}
		return Target{}, got.Err()
	})
	_, err := c.Latest(ctx, "tenant-a")
	if !called || !errors.Is(err, context.Canceled) {
		t.Fatalf("operation context did not reach endpoint router: called=%v err=%v", called, err)
	}
}
