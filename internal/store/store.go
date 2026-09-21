// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pinger reports whether a backing datastore is reachable. The readiness probe
// depends on this interface rather than the concrete pool, so health checks are
// trivially fakeable in unit tests.
type Pinger interface {
	Ping(ctx context.Context) error
}

// DB wraps a pgx connection pool. Tenant-scoped repositories build on it in S2.
//
// Multi-region (S-EE2): an optional read pool points at a local read replica.
// readPool defaults to the writer pool, so every existing call site keeps
// working unchanged; read-heavy paths can opt into ReadPool() for locality.
// Writes always go through Pool() (the writer endpoint), guarded by the
// cluster split-brain fence at the API layer and — while the endpoint resolves
// to a stale ex-primary — by FenceWrites at the connection level (DPR-089), so
// the control plane's own background writers fail closed as well.
type DB struct {
	pool     *pgxpool.Pool
	readPool *pgxpool.Pool

	// writeFence mirrors the cluster fence on the writer pool: while set,
	// every session the pool opens starts read-only.
	writeFence atomic.Bool
}

// Open parses dsn, applies pool sizing, and creates the PostgreSQL pool. The
// pool connects lazily, so Open does not fail when the database is temporarily
// unreachable — the readiness probe reports that instead. TLS-in-transit is
// honored when the DSN requests it via sslmode (docs/guardrails.md G7-12).
func Open(ctx context.Context, dsn string, maxConns, minConns int32, connectTimeout time.Duration) (*DB, error) {
	db := &DB{}
	pool, err := openPool(ctx, dsn, maxConns, minConns, connectTimeout, db.afterConnect)
	if err != nil {
		return nil, err
	}
	db.pool, db.readPool = pool, pool
	return db, nil
}

func openPool(ctx context.Context, dsn string, maxConns, minConns int32, connectTimeout time.Duration, afterConnect func(context.Context, *pgx.Conn) error) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx's parse error redacts URL userinfo, but it retains arbitrary
		// query values such as password and sslpassword. Do not wrap it into
		// startup/log output: the raw connection string is still available to
		// the configuration owner, while this boundary returns only bounded,
		// credential-free guidance.
		return nil, errors.New("parse database url: invalid PostgreSQL connection parameters")
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
	cfg.AfterConnect = afterConnect
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	return pool, nil
}

// WithReadReplica opens a second pool against readDSN (a local read replica,
// S-EE2) and routes ReadPool() to it. An empty readDSN is a no-op (reads stay
// on the writer). The reader pool is closed alongside the writer.
func (db *DB) WithReadReplica(ctx context.Context, readDSN string, maxConns, minConns int32, connectTimeout time.Duration) error {
	if readDSN == "" {
		return nil
	}
	pool, err := openPool(ctx, readDSN, maxConns, minConns, connectTimeout, nil)
	if err != nil {
		return fmt.Errorf("open read replica: %w", err)
	}
	db.readPool = pool
	return nil
}

// FenceWrites (DPR-089) switches the writer pool between normal and read-only
// sessions. The cluster manager sets it while the writer endpoint resolves to
// a stale ex-primary (a node a promotion elsewhere has fenced off): every
// pooled connection is recycled so no session keeps writing, and every new
// session starts with default_transaction_read_only = on, so any write from
// any path — heartbeats, incident signals, alert state, audit — fails closed
// with SQLSTATE 25006 exactly as it would on a standby, while reads keep
// serving. Idempotent; reports whether the state changed.
func (db *DB) FenceWrites(on bool) bool {
	if db == nil || db.pool == nil {
		return false
	}
	if db.writeFence.Swap(on) == on {
		return false
	}
	db.pool.Reset()
	return true
}

// WritesFenced reports whether the writer pool is currently fenced read-only.
func (db *DB) WritesFenced() bool { return db.writeFence.Load() }

// afterConnect applies the fence to every session the writer pool opens.
func (db *DB) afterConnect(ctx context.Context, conn *pgx.Conn) error {
	if !db.writeFence.Load() {
		return nil
	}
	_, err := conn.Exec(ctx, "SET default_transaction_read_only = on")
	return err
}

// Ping verifies connectivity; used by the readiness probe.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Pool returns the writer pool for repositories and the migration runner.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }

// ReadPool returns the read pool — the read replica when configured, else the
// writer pool. Read-heavy, latency-sensitive paths use this for locality;
// anything that writes uses Pool().
func (db *DB) ReadPool() *pgxpool.Pool {
	if db.readPool != nil {
		return db.readPool
	}
	return db.pool
}

// Close releases all pooled connections (writer + read replica).
func (db *DB) Close() {
	if db.readPool != nil && db.readPool != db.pool {
		db.readPool.Close()
	}
	if db.pool != nil {
		db.pool.Close()
	}
}
