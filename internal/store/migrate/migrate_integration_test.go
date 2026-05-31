//go:build integration

package migrate_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/migrations"
)

func dsn() string {
	if v := os.Getenv("NETCTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://netctl:netctl@localhost:5432/netctl?sslmode=disable"
}

// TestApplyIsIdempotent proves the S1 Done-when: a no-op (already-applied)
// migration run on a second boot applies nothing.
func TestApplyIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("no database available: %v", err)
	}

	// Deterministic clean slate for the test.
	if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS schema_migrations, netctl_meta"); err != nil {
		t.Fatalf("reset: %v", err)
	}

	runner := migrate.New(migrations.FS, nil)

	applied1, err := runner.Apply(ctx, pool)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if len(applied1) == 0 {
		t.Fatal("first apply should run the baseline migration")
	}

	applied2, err := runner.Apply(ctx, pool)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(applied2) != 0 {
		t.Fatalf("second apply must be a no-op, but applied %v", applied2)
	}

	var value string
	if err := pool.QueryRow(ctx, "SELECT value FROM netctl_meta WHERE key = 'schema_baseline'").Scan(&value); err != nil {
		t.Fatalf("baseline marker row: %v", err)
	}
	if value != "s1" {
		t.Errorf("schema_baseline = %q, want s1", value)
	}
}
