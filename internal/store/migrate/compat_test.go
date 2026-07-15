// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package migrate

import (
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/migrations"
)

func TestCheckSQLAllowsAdditive(t *testing.T) {
	// A realistic additive migration (mirrors the repo's style) must pass clean.
	additive := `
-- a comment mentioning DROP TABLE that must be ignored
CREATE TABLE IF NOT EXISTS widgets (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    name      text NOT NULL DEFAULT ''
);
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS color text NOT NULL DEFAULT 'blue';
CREATE INDEX IF NOT EXISTS widgets_tenant_idx ON widgets (tenant_id);
DO $$
BEGIN
    EXECUTE 'ALTER TABLE widgets ENABLE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON widgets';
    EXECUTE $pol$
        CREATE POLICY tenant_isolation ON widgets USING (true)
    $pol$;
END $$;
GRANT SELECT ON widgets TO probectl_app;
`
	if v := CheckSQL("0099_add.sql", additive); len(v) != 0 {
		t.Fatalf("additive migration should pass, got violations: %v", v)
	}
}

func TestCheckSQLRejectsDestructive(t *testing.T) {
	cases := map[string]string{
		"drop table":        `DROP TABLE widgets;`,
		"drop column":       `ALTER TABLE widgets DROP COLUMN color;`,
		"alter type":        `ALTER TABLE widgets ALTER COLUMN name TYPE varchar(50);`,
		"rename column":     `ALTER TABLE widgets RENAME COLUMN name TO label;`,
		"set not null":      `ALTER TABLE widgets ALTER COLUMN color SET NOT NULL;`,
		"truncate":          `TRUNCATE widgets;`,
		"add notnull nodef": `ALTER TABLE widgets ADD COLUMN size int NOT NULL;`,
	}
	for name, sql := range cases {
		if v := CheckSQL("bad.sql", sql); len(v) == 0 {
			t.Fatalf("%s: expected a violation for %q", name, sql)
		}
	}
}

// TestCheckSQLRejectsLockingDDL is the SCHEMA-003 acceptance test: the gate is
// an online/non-locking gate, not merely a destructive one. A bare CREATE INDEX
// on an existing table, and a validating ADD CONSTRAINT without NOT VALID, both
// lock under live ingestion and must be flagged.
func TestCheckSQLRejectsLockingDDL(t *testing.T) {
	cases := map[string]string{
		"bare create index":        `CREATE INDEX foo ON existing_table (col);`,
		"bare create unique index": `CREATE UNIQUE INDEX foo ON existing_table (col);`,
		"add check no notvalid":    `ALTER TABLE tenants ADD CONSTRAINT c CHECK (x IN ('a','b'));`,
		"add fk no notvalid":       `ALTER TABLE t ADD CONSTRAINT c FOREIGN KEY (a) REFERENCES u(id);`,
	}
	for name, sql := range cases {
		if v := CheckSQL("bad.sql", sql); len(v) == 0 {
			t.Fatalf("%s: expected a locking violation for %q", name, sql)
		}
	}
}

// TestCheckSQLAllowsOnlineDDL: the online (non-locking) forms and inline
// CREATE TABLE constraints must pass clean.
func TestCheckSQLAllowsOnlineDDL(t *testing.T) {
	ok := []string{
		`-- probectl:no-tx: CREATE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS foo ON t (col);`,
		`-- probectl:no-tx: CREATE UNIQUE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
CREATE UNIQUE INDEX CONCURRENTLY foo ON t (col);`,
		`ALTER TABLE t ADD CONSTRAINT c CHECK (x > 0) NOT VALID;`,
		`ALTER TABLE t VALIDATE CONSTRAINT c;`,
		`CREATE TABLE IF NOT EXISTS t (id int, status text CHECK (status IN ('a','b')));`,
	}
	for _, sql := range ok {
		if v := CheckSQL("ok.sql", sql); len(v) != 0 {
			t.Fatalf("online DDL should pass, got %v for %q", v, sql)
		}
	}
}

func TestCheckSQLRequiresNoTxForConcurrentIndex(t *testing.T) {
	sql := `CREATE INDEX CONCURRENTLY IF NOT EXISTS foo ON existing_table (col);`
	v := CheckSQL("needs_no_tx.sql", sql)
	if len(v) != 1 || !strings.Contains(v[0].Rule, "probectl:no-tx") {
		t.Fatalf("concurrent index without no-tx directive violations = %v, want no-tx violation", v)
	}

	bare := `-- probectl:no-tx
CREATE INDEX CONCURRENTLY IF NOT EXISTS foo ON existing_table (col);`
	v = CheckSQL("bare_no_tx.sql", bare)
	if len(v) != 1 || !strings.Contains(v[0].Rule, "probectl:no-tx") {
		t.Fatalf("reason-less no-tx directive violations = %v, want no-tx violation", v)
	}
}

// TestCheckSQLLockOKAnnotation: a reviewed `-- lock-ok: <reason>` waives a
// locking statement (a confirmed-tiny/new table); a bare `-- lock-ok` without a
// reason does NOT waive it.
func TestCheckSQLLockOKAnnotation(t *testing.T) {
	waived := `-- lock-ok: tiny config table
CREATE INDEX foo ON config (col);`
	if v := CheckSQL("ann.sql", waived); len(v) != 0 {
		t.Fatalf("annotated lock-ok should be waived, got %v", v)
	}
	bare := `-- lock-ok
CREATE INDEX foo ON config (col);`
	if v := CheckSQL("bare.sql", bare); len(v) == 0 {
		t.Fatal("a reason-less -- lock-ok must NOT waive a locking statement")
	}
}

func TestCheckSQLDollarQuoteNotSplit(t *testing.T) {
	// A ';' inside a dollar-quoted body must not cause a false split that hides or
	// invents a violation. This block is additive and must pass.
	sql := `DO $$
BEGIN
    EXECUTE 'CREATE INDEX IF NOT EXISTS i ON t (a)';
    EXECUTE 'GRANT SELECT ON t TO probectl_app';
END $$;`
	if v := CheckSQL("x.sql", sql); len(v) != 0 {
		t.Fatalf("dollar-quoted block should pass, got: %v", v)
	}
}

func TestCheckSQLRejectsUnguardedCreatePolicy(t *testing.T) {
	cases := map[string]string{
		"bare": `CREATE POLICY tenant_isolation ON widgets USING (true);`,
		"do block without catalog branch": `DO $$
BEGIN
    CREATE POLICY tenant_isolation ON widgets USING (true);
END $$;`,
		"guard for another table": `DROP POLICY IF EXISTS tenant_isolation ON other;
CREATE POLICY tenant_isolation ON widgets USING (true);`,
		"catalog guard without schema": `DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE tablename = 'widgets' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON widgets USING (true);
    END IF;
END $$;`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			violations := CheckSQL("bad_policy.sql", sql)
			if len(violations) == 0 || !strings.Contains(violations[0].Rule, "idempotency guard") {
				t.Fatalf("unguarded CREATE POLICY violations = %v", violations)
			}
		})
	}
}

func TestCheckSQLAllowsGuardedCreatePolicy(t *testing.T) {
	cases := map[string]string{
		"drop then create": `DROP POLICY IF EXISTS tenant_isolation ON widgets;
CREATE POLICY tenant_isolation ON widgets USING (true);`,
		"catalog create or alter": `DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = current_schema()
           AND tablename = 'widgets' AND policyname = 'tenant_isolation'
    ) THEN
        ALTER POLICY tenant_isolation ON widgets USING (true);
    ELSE
        CREATE POLICY tenant_isolation ON widgets USING (true);
    END IF;
END $$;`,
		"catalog create when absent": `DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = current_schema()
           AND tablename = 'widgets' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON widgets USING (true);
    END IF;
END $$;`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			if violations := CheckSQL("guarded_policy.sql", sql); len(violations) != 0 {
				t.Fatalf("guarded CREATE POLICY violations = %v", violations)
			}
		})
	}
}

// The migration-gate: every shipped migration must be backward-compatible
// (expand/contract). This walks the real embedded migrations FS, so adding a
// destructive migration fails CI here.
func TestMigrationsExpandContractCompat(t *testing.T) {
	violations, err := CheckFS(migrations.FS)
	if err != nil {
		t.Fatalf("walk migrations: %v", err)
	}
	if len(violations) > 0 {
		var b strings.Builder
		for _, v := range violations {
			b.WriteString("\n  " + v.String())
		}
		t.Fatalf("shipped migrations break the expand/contract policy:%s", b.String())
	}
}
