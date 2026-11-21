// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package migrate

import (
	"strings"
	"testing"
)

func TestCheckSQLAddedColumnSeparatesProceduralChecksAndDefaults(t *testing.T) {
	for _, test := range []struct {
		name, sql string
		unsafe    bool
	}{
		{"nullable installer", `CREATE FUNCTION install() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'ALTER TABLE owned ADD COLUMN IF NOT EXISTS payload jsonb'; IF definition IS NOT NULL THEN RETURN; END IF; END $$;`, false},
		{"unsafe dynamic column", `DO $$ BEGIN EXECUTE 'ALTER TABLE owned ADD COLUMN payload jsonb NOT NULL'; END $$;`, true},
		{"other column default", `ALTER TABLE owned ADD COLUMN unsafe text NOT NULL, ADD COLUMN safe int NOT NULL DEFAULT 0;`, true},
		{"nullable json path check", `ALTER TABLE owned ADD COLUMN current_path jsonb CHECK (current_path IS NULL OR (current_path IS NOT NULL AND jsonb_typeof(current_path) = 'array'));`, false},
		{"column constraint after check", `ALTER TABLE owned ADD COLUMN current_path jsonb CHECK (jsonb_typeof(current_path) = 'array') NOT NULL;`, true},
		{"unsafe column after nullable check", `ALTER TABLE owned ADD COLUMN previous_path jsonb CHECK (previous_path IS NULL OR (previous_path IS NOT NULL AND jsonb_typeof(previous_path) = 'array')), ADD COLUMN current_path jsonb NOT NULL;`, true},
		{"default in literal", `ALTER TABLE owned ADD COLUMN payload text CHECK(payload <> 'DEFAULT') NOT NULL;`, true},
		{"default in identifier", `ALTER TABLE owned ADD COLUMN "DEFAULT" text NOT NULL;`, true},
		{"default in dollar literal", `ALTER TABLE owned ADD COLUMN payload text CHECK(payload <> $literal$DEFAULT$literal$) NOT NULL;`, true},
		{"actual default", `ALTER TABLE owned ADD COLUMN payload text DEFAULT 'kept' NOT NULL;`, false},
		{"parenthesized type", `ALTER TABLE owned ADD COLUMN payload numeric(20,2) NOT NULL;`, true},
		{"parenthesized default", `ALTER TABLE owned ADD COLUMN payload numeric(20,2) DEFAULT (round(3.14, 1)) NOT NULL;`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			found := false
			for _, violation := range CheckSQL("fixture.sql", test.sql) {
				found = found || strings.HasPrefix(violation.Rule, "add column NOT NULL")
			}
			if found != test.unsafe {
				t.Fatal("column declaration guard confused procedural/other-column tokens", found, test.unsafe)
			}
		})
	}
}
