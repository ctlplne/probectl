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
		{"default in literal", `ALTER TABLE owned ADD COLUMN payload text CHECK(payload <> 'DEFAULT') NOT NULL;`, true},
		{"default in identifier", `ALTER TABLE owned ADD COLUMN "DEFAULT" text NOT NULL;`, true},
		{"default in dollar literal", `ALTER TABLE owned ADD COLUMN payload text CHECK(payload <> $literal$DEFAULT$literal$) NOT NULL;`, true},
		{"actual default", `ALTER TABLE owned ADD COLUMN payload text DEFAULT 'kept' NOT NULL;`, false},
		{"parenthesized type", `ALTER TABLE owned ADD COLUMN payload numeric(20,2) NOT NULL;`, true},
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
