// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//
// Multi-region (S-EE2): an optional read pool points at a local read replica.
// readPool defaults to the writer pool, so every existing call site keeps
// working unchanged; read-heavy paths can opt into ReadPool() for locality.
// Writes always go through Pool() (the writer endpoint), guarded by the
// cluster split-brain fence at the API layer.
type DB struct {
	pool     *pgxpool.Pool
	readPool *pgxpool.Pool
}

// Open parses dsn, applies pool sizing, and creates the PostgreSQL pool. The
// pool connects lazily, so Open does not fail when the database is temporarily
// unreachable — the readiness probe reports that instead. TLS-in-transit is
// honored when the DSN requests it via sslmode (CLAUDE.md §7 guardrail 12).
func Open(ctx context.Context, dsn string, maxConns, minConns int32, connectTimeout time.Duration) (*DB, error) {
	pool, err := openPool(ctx, dsn, maxConns, minConns, connectTimeout)
	if err != nil {
		return nil, err
	}
	return &DB{pool: pool, readPool: pool}, nil
}

func openPool(ctx context.Context, dsn string, maxConns, minConns int32, connectTimeout time.Duration) (*pgxpool.Pool, error) {
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
	return pool, nil
}

// WithReadReplica opens a second pool against readDSN (a local read replica,
// S-EE2) and routes ReadPool() to it. An empty readDSN is a no-op (reads stay
// on the writer). The reader pool is closed alongside the writer.
func (db *DB) WithReadReplica(ctx context.Context, readDSN string, maxConns, minConns int32, connectTimeout time.Duration) error {
	if readDSN == "" {
		return nil
	}
	pool, err := openPool(ctx, readDSN, maxConns, minConns, connectTimeout)
	if err != nil {
		return fmt.Errorf("open read replica: %w", err)
	}
	db.readPool = pool
	return nil
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
