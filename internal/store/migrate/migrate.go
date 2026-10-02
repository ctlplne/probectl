// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package migrate applies the sequential, idempotent SQL migrations embedded in
// the migrations package. Applied versions are recorded in a schema_migrations
// ledger, so a second run is a no-op — re-running is always safe (CONTRIBUTING.md).
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationAdvisoryLock serializes concurrent migration runners (multiple
// control-plane replicas booting at once, or parallel test packages) against a
// single database, so they cannot race on CREATE TABLE / type creation.
const migrationAdvisoryLock int64 = 5434142191

// lockPollInterval/lockPollMax bound the non-blocking advisory-lock poll
// (PLAT-03): a waiter sleeps between pg_try_advisory_lock attempts rather than
// blocking inside pg_advisory_lock, so it never holds an open snapshot that a
// peer's CREATE INDEX CONCURRENTLY would deadlock against.
const (
	lockPollInterval = 50 * time.Millisecond
	lockPollMax      = 1 * time.Second
)

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

	// Serialize concurrent appliers: one runs the migrations; the rest wait here
	// and then find the schema already up to date. The lock MUST be released
	// before the connection returns to the pool. PLAT-03: acquire it with
	// pg_try_advisory_lock + backoff rather than a blocking pg_advisory_lock —
	// a blocking lock keeps the waiting statement, and its snapshot, alive, and
	// the holder's CREATE INDEX CONCURRENTLY then waits on that snapshot,
	// deadlocking the two and leaving an INVALID index recorded as applied.
	if err := acquireMigrationLock(ctx, conn); err != nil {
		return nil, err
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

	// PLAT-03: repair any index a previously-crashed CIC left INVALID before
	// applying new work. CREATE INDEX CONCURRENTLY IF NOT EXISTS SKIPS a leftover
	// invalid index, so without this the schema stays broken while the ledger
	// says the migration is applied (e.g. 0098 => every incident-signal insert
	// fails forever). Safe under the exclusive lock: no peer is building indexes.
	if err := r.repairInvalidIndexesLocked(ctx, conn, migrations); err != nil {
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
	if err := execNoTxBody(ctx, conn, m); err != nil {
		return err
	}
	// PLAT-03: a no-tx migration that leaves an INVALID index must NOT be
	// recorded as applied — otherwise CREATE INDEX CONCURRENTLY IF NOT EXISTS
	// skips the leftover on every later run and the schema is wedged forever
	// while the ledger claims success. Under the exclusive advisory lock a CIC
	// no longer deadlocks, so this should not trigger; if it does (e.g. a genuine
	// data conflict), fail loudly and leave the migration pending to retry.
	if invalid, err := invalidIndexNames(ctx, conn); err != nil {
		return err
	} else if len(invalid) > 0 {
		return fmt.Errorf("left invalid index(es) %v; not recording as applied", invalid)
	}
	if _, e := conn.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); e != nil {
		return fmt.Errorf("record no-tx ledger: %w", e)
	}
	return nil
}

// execNoTxBody runs a no-tx migration's statements outside a transaction,
// without touching the ledger. Shared by applyOneNoTx and the invalid-index
// repair so a recreate re-runs the exact migration body.
func execNoTxBody(ctx context.Context, conn *pgxpool.Conn, m Migration) error {
	for i, stmt := range splitStatements(m.SQL) {
		if strings.TrimSpace(stripComments(stmt)) == "" {
			continue
		}
		if e := conn.Conn().PgConn().Exec(ctx, stmt).Close(); e != nil {
			return fmt.Errorf("exec no-tx statement %d: %w", i+1, e)
		}
	}
	return nil
}

// acquireMigrationLock takes the session advisory lock without blocking inside
// the database (PLAT-03). It polls pg_try_advisory_lock with a capped backoff;
// between attempts the connection holds no open snapshot, so a waiting runner
// can never deadlock a holder's CREATE INDEX CONCURRENTLY.
func acquireMigrationLock(ctx context.Context, conn *pgxpool.Conn) error {
	backoff := lockPollInterval
	for {
		var got bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", migrationAdvisoryLock).Scan(&got); err != nil {
			return fmt.Errorf("acquire migration lock: %w", err)
		}
		if got {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("acquire migration lock: %w", ctx.Err())
		case <-time.After(backoff):
		}
		if backoff < lockPollMax {
			backoff *= 2
		}
	}
}

var createIndexNameRE = regexp.MustCompile(`(?i)\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?"?([a-zA-Z0-9_$]+)"?`)

// invalidIndexNames returns the names of indexes PostgreSQL marks invalid
// (indisvalid = false), excluding the catalog schemas. A CIC interrupted by a
// crash or deadlock leaves exactly such an index.
func invalidIndexNames(ctx context.Context, conn *pgxpool.Conn) ([]string, error) {
	rows, err := conn.Query(ctx, `SELECT c.relname
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE NOT i.indisvalid AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		return nil, fmt.Errorf("scan invalid indexes: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// repairInvalidIndexesLocked drops every INVALID index and recreates it by
// re-running the migration body that creates it (PLAT-03). Called under the
// exclusive advisory lock, where any invalid index is a leftover from a prior
// crashed/deadlocked run (no peer is concurrently building one), so dropping and
// rebuilding is safe. An invalid index with no matching migration is dropped and
// left to a pending migration to recreate.
func (r *Runner) repairInvalidIndexesLocked(ctx context.Context, conn *pgxpool.Conn, migrations []Migration) error {
	invalid, err := invalidIndexNames(ctx, conn)
	if err != nil {
		return err
	}
	for _, name := range invalid {
		if _, err := conn.Exec(ctx, fmt.Sprintf("DROP INDEX CONCURRENTLY IF EXISTS %s", pgx.Identifier{name}.Sanitize())); err != nil {
			return fmt.Errorf("drop invalid index %q: %w", name, err)
		}
		m, ok := migrationCreatingIndex(migrations, name)
		if !ok {
			r.log.Warn("dropped invalid index with no matching migration; a pending migration must recreate it", "index", name)
			continue
		}
		if err := execNoTxBody(ctx, conn, m); err != nil {
			return fmt.Errorf("recreate invalid index %q via %04d_%s: %w", name, m.Version, m.Name, err)
		}
		r.log.Info("repaired invalid index left by an interrupted CREATE INDEX CONCURRENTLY", "index", name, "migration", m.Version)
	}
	return nil
}

// migrationCreatingIndex finds the migration whose body creates the named index.
func migrationCreatingIndex(migrations []Migration, index string) (Migration, bool) {
	for _, m := range migrations {
		for _, g := range createIndexNameRE.FindAllStringSubmatch(m.SQL, -1) {
			if strings.EqualFold(g[1], index) {
				return m, true
			}
		}
	}
	return Migration{}, false
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
