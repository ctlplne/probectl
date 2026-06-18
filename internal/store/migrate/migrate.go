// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package migrate applies the sequential, idempotent SQL migrations embedded in
// the migrations package. Applied versions are recorded in a schema_migrations
// ledger, so a second run is a no-op — re-running is always safe (CLAUDE.md §6).
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationAdvisoryLock serializes concurrent migration runners (multiple
// control-plane replicas booting at once, or parallel test packages) against a
// single database, so they cannot race on CREATE TABLE / type creation.
const migrationAdvisoryLock int64 = 5434142191

// DB is the subset of *pgxpool.Pool the runner needs.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Migration is a single parsed migration file.
type Migration struct {
	Version int64
	Name    string
	SQL     string
	NoTx    bool
}

// Runner loads migrations from an fs.FS and applies the pending ones.
type Runner struct {
	fsys fs.FS
	log  *slog.Logger
}

// New returns a Runner over fsys (typically migrations.FS).
func New(fsys fs.FS, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{fsys: fsys, log: log}
}

const ledgerDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    bigint PRIMARY KEY,
	name       text NOT NULL,
	applied_at timestamptz NOT NULL DEFAULT now()
)`

// Apply runs every migration not yet recorded in schema_migrations, in version
// order. Most migrations run in their own transaction; migrations marked with
// the reviewed no-tx directive run outside a transaction for PostgreSQL DDL
// forms such as CREATE INDEX CONCURRENTLY, which PostgreSQL refuses inside a
// transaction block. It returns the versions applied during this call — empty
// when the database is already up to date.
func (r *Runner) Apply(ctx context.Context, pool *pgxpool.Pool) ([]int64, error) {
	migrations, err := r.load()
	if err != nil {
		return nil, err
	}

	// Hold the work on a single connection so the advisory lock (session-scoped)
	// stays held for the whole run.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	// Serialize concurrent appliers: one runs the migrations; the rest block here
	// and then find the schema already up to date. The lock MUST be released
	// before the connection returns to the pool.
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLock); err != nil {
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationAdvisoryLock)
	}()

	db := DB(conn)
	if _, err := db.Exec(ctx, ledgerDDL); err != nil {
		return nil, fmt.Errorf("ensure schema_migrations: %w", err)
	}
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return nil, err
	}

	var done []int64
	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return done, fmt.Errorf("apply migration %04d_%s: %w", m.Version, m.Name, err)
		}
		r.log.Info("applied migration", "version", m.Version, "name", m.Name)
		done = append(done, m.Version)
	}
	return done, nil
}

func applyOne(ctx context.Context, conn *pgxpool.Conn, m Migration) (err error) {
	if m.NoTx {
		return applyOneNoTx(ctx, conn, m)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	// Migration bodies may contain multiple statements, so execute them with the
	// simple query protocol on the transaction's own connection.
	if e := tx.Conn().PgConn().Exec(ctx, m.SQL).Close(); e != nil {
		return fmt.Errorf("exec body: %w", e)
	}
	if _, e := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); e != nil {
		return fmt.Errorf("record ledger: %w", e)
	}
	if e := tx.Commit(ctx); e != nil {
		return fmt.Errorf("commit: %w", e)
	}
	return nil
}

func applyOneNoTx(ctx context.Context, conn *pgxpool.Conn, m Migration) error {
	for i, stmt := range splitStatements(m.SQL) {
		if strings.TrimSpace(stripComments(stmt)) == "" {
			continue
		}
		if e := conn.Conn().PgConn().Exec(ctx, stmt).Close(); e != nil {
			return fmt.Errorf("exec no-tx statement %d: %w", i+1, e)
		}
	}
	if _, e := conn.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); e != nil {
		return fmt.Errorf("record no-tx ledger: %w", e)
	}
	return nil
}

func appliedVersions(ctx context.Context, db DB) (map[int64]bool, error) {
	rows, err := db.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()
	set := make(map[int64]bool)
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		set[v] = true
	}
	return set, rows.Err()
}

// load parses and orders the embedded *.sql files.
func (r *Runner) load() ([]Migration, error) {
	entries, err := fs.Glob(r.fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	migrations := make([]Migration, 0, len(entries))
	seen := make(map[int64]string)
	for _, name := range entries {
		version, label, err := parseName(name)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("duplicate migration version %d: %s and %s", version, prev, name)
		}
		seen[version] = name
		body, err := fs.ReadFile(r.fsys, name)
		if err != nil {
			return nil, err
		}
		sql := string(body)
		migrations = append(migrations, Migration{Version: version, Name: label, SQL: sql, NoTx: hasNoTxDirective(sql)})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// parseName extracts the version and label from "NNNN_label.sql".
func parseName(filename string) (int64, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, "", fmt.Errorf("migration %q must be named NNNN_description.sql", filename)
	}
	version, err := strconv.ParseInt(base[:idx], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("migration %q: invalid version prefix: %w", filename, err)
	}
	return version, base[idx+1:], nil
}
