// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/migrations"
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
