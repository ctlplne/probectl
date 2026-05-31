package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pinger reports whether a backing datastore is reachable. The readiness probe
// depends on this interface rather than the concrete pool, so health checks are
// trivially fakeable in unit tests.
type Pinger interface {
	Ping(ctx context.Context) error
}

// DB wraps a pgx connection pool. Tenant-scoped repositories build on it in S2.
type DB struct {
	pool *pgxpool.Pool
}

// Open parses dsn, applies pool sizing, and creates the PostgreSQL pool. The
// pool connects lazily, so Open does not fail when the database is temporarily
// unreachable — the readiness probe reports that instead. TLS-in-transit is
// honored when the DSN requests it via sslmode (CLAUDE.md §7 guardrail 12).
func Open(ctx context.Context, dsn string, maxConns, minConns int32, connectTimeout time.Duration) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if minConns >= 0 {
		cfg.MinConns = minConns
	}
	if connectTimeout > 0 {
		cfg.ConnConfig.ConnectTimeout = connectTimeout
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Ping verifies connectivity; used by the readiness probe.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Pool returns the underlying pgx pool for repositories and the migration runner.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// Close releases all pooled connections.
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
}
