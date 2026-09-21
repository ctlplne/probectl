// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/migrations"
)

func TestSessionDetailCleanupMigrationIsTenantIndexed(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0076_session_detail_retention.sql")
	if err != nil {
		t.Fatalf("read session-detail retention migration: %v", err)
	}
	sql := string(raw)
	for _, required := range []string{
		"ON sessions (tenant_id, expires_at)",
		"ON sessions (tenant_id, replaced_at)",
		"WHERE replaced_at IS NOT NULL",
		"information_schema.schemata",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("session cleanup migration missing %q", required)
		}
	}
}
