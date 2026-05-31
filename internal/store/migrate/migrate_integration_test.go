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

	runner := migrate.New(migrations.FS, nil)

	// Apply serializes on a Postgres advisory lock, so this is safe to run
	// concurrently with other packages migrating the same shared database. We do
	// NOT drop the schema (that would race other appliers); instead we assert the
	// invariant that matters: after a first apply, a second apply changes nothing.
	if _, err := runner.Apply(ctx, pool); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	applied, err := runner.Apply(ctx, pool)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second apply must be a no-op, but applied %v", applied)
	}

	var value string
	if err := pool.QueryRow(ctx, "SELECT value FROM netctl_meta WHERE key = 'schema_baseline'").Scan(&value); err != nil {
		t.Fatalf("baseline marker row: %v", err)
	}
	if value != "s1" {
		t.Errorf("schema_baseline = %q, want s1", value)
	}
}
