// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chmigrate

import "testing"

// TestCheckMigrationsFlagsDestructive is the SCHEMA-001 core: a DROP/RENAME
// TABLE in a ClickHouse migration is a violation unless the migration is
// annotated Destructive with a Justification.
func TestCheckMigrationsFlagsDestructive(t *testing.T) {
	cases := map[string]Migration{
		"drop table": {Version: 1, Name: "x", Statements: []string{
			"DROP TABLE IF EXISTS probectl_flows",
		}},
		"rename table": {Version: 1, Name: "x", Statements: []string{
			"RENAME TABLE probectl_flows TO probectl_flows_old",
		}},
	}
	for name, m := range cases {
		if v := CheckMigrations("teststore", []Migration{m}); len(v) == 0 {
			t.Fatalf("%s: expected a destructive violation, got none", name)
		}
	}
}

// TestCheckMigrationsAllowsAnnotated: an annotated + justified destructive
// migration passes; a Destructive migration WITHOUT a justification fails.
func TestCheckMigrationsAllowsAnnotated(t *testing.T) {
	ok := Migration{Version: 2, Name: "repartition", Statements: []string{
		"DROP TABLE IF EXISTS probectl_path_hops",
	}, Destructive: true, Justification: "re-discoverable cache, re-probed over time"}
	if v := CheckMigrations("pathstore", []Migration{ok}); len(v) != 0 {
		t.Fatalf("annotated+justified destructive migration should pass, got %v", v)
	}

	noJustify := Migration{Version: 2, Name: "bad", Statements: []string{
		"DROP TABLE probectl_flows",
	}, Destructive: true}
	if v := CheckMigrations("flowstore", []Migration{noJustify}); len(v) == 0 {
		t.Fatal("Destructive without a Justification must fail the gate")
	}
}

// TestCheckMigrationsAllowsAdditive: a plain additive migration passes clean.
func TestCheckMigrationsAllowsAdditive(t *testing.T) {
	m := Migration{Version: 1, Name: "create", Statements: []string{
		"CREATE TABLE IF NOT EXISTS probectl_flows (tenant_id String) ENGINE = MergeTree ORDER BY tenant_id",
		"ALTER TABLE probectl_flows ADD COLUMN IF NOT EXISTS x UInt64",
	}}
	if v := CheckMigrations("flowstore", []Migration{m}); len(v) != 0 {
		t.Fatalf("additive migration should pass, got %v", v)
	}
}
