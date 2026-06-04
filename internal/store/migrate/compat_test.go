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
