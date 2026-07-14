// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package pglease provides a session-scoped PostgreSQL advisory-lock lease
// with a persistent fencing epoch.
package pglease

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const lockPrefix = "probectl:singleton:"

var (
	// ErrFenced means the caller's epoch is no longer the current epoch.
	ErrFenced = errors.New("cluster: singleton lease epoch fenced")
	// ErrAlreadyHeld means Acquire was called twice on one lease handle.
	ErrAlreadyHeld = errors.New("cluster: singleton lease handle already holds a connection")
)

// Token fences one leadership term. Epoch increases on every successful
// database acquisition; HolderID distinguishes processes in logs and the
// database ledger.
type Token struct {
	Name     string
	HolderID string
	Epoch    int64
}

// Lease holds a session advisory lock on a dedicated pool connection. It never
// returns a still-locked connection to pgxpool: if unlock fails, the connection
// is hijacked and closed so a future borrower cannot inherit the lock.
type Lease struct {
	pool     *pgxpool.Pool
	name     string
	holderID string

	mu      sync.Mutex
	conn    *pgxpool.Conn
	current Token
}

// New builds the PostgreSQL singleton lease. Empty holderID generates a
// hostname+random process identity through internal/crypto.
func New(pool *pgxpool.Pool, name, holderID string) (*Lease, error) {
	if pool == nil {
		return nil, errors.New("cluster: singleton lease requires a writer pool")
	}
	if name == "" {
		return nil, errors.New("cluster: singleton lease name is required")
	}
	if holderID == "" {
		var err error
		holderID, err = newHolderID()
		if err != nil {
			return nil, err
		}
	}
	return &Lease{pool: pool, name: name, holderID: holderID}, nil
}

func newHolderID() (string, error) {
	random, err := crypto.Random(12)
	if err != nil {
		return "", fmt.Errorf("cluster: generate singleton holder id: %w", err)
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "probectl-control"
	}
	return host + ":" + hex.EncodeToString(random), nil
}

// Acquire tries the named advisory lock without blocking. A winner increments
// the persistent fencing epoch before it may start work; a loser releases its
// borrowed connection immediately and remains a hot standby.
func (l *Lease) Acquire(ctx context.Context) (Token, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		return Token{}, false, ErrAlreadyHeld
	}
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return Token{}, false, fmt.Errorf("cluster: acquire lease connection: %w", err)
	}
	var won bool
	if err := conn.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, lockPrefix+l.name,
	).Scan(&won); err != nil {
		conn.Release()
		return Token{}, false, fmt.Errorf("cluster: try singleton advisory lock: %w", err)
	}
	if !won {
		conn.Release()
		return Token{}, false, nil
	}

	var epoch int64
	err = conn.QueryRow(ctx, `
INSERT INTO cluster_singleton_leases AS leases
    (lease_name, epoch, holder_id, acquired_at, renewed_at, released_at)
VALUES ($1, 1, $2, clock_timestamp(), clock_timestamp(), NULL)
ON CONFLICT (lease_name) DO UPDATE SET
    epoch = leases.epoch + 1,
    holder_id = EXCLUDED.holder_id,
    acquired_at = clock_timestamp(),
    renewed_at = clock_timestamp(),
    released_at = NULL
RETURNING epoch`, l.name, l.holderID).Scan(&epoch)
	if err != nil {
		l.discardLockedConn(conn)
		return Token{}, false, fmt.Errorf("cluster: advance singleton lease epoch: %w", err)
	}
	token := Token{Name: l.name, HolderID: l.holderID, Epoch: epoch}
	l.conn = conn
	l.current = token
	return token, true, nil
}

// Renew proves the dedicated connection is still usable and atomically
// refreshes only the caller's current epoch. Zero updated rows fences the
// caller even if its process still has runnable goroutines.
func (l *Lease) Renew(ctx context.Context, token Token) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil || token != l.current {
		return ErrFenced
	}
	tag, err := l.conn.Exec(ctx, `
UPDATE cluster_singleton_leases
SET renewed_at = clock_timestamp()
WHERE lease_name = $1 AND epoch = $2 AND holder_id = $3 AND released_at IS NULL`,
		token.Name, token.Epoch, token.HolderID)
	if err != nil {
		return fmt.Errorf("cluster: renew singleton lease: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrFenced
	}
	return nil
}

// Release marks the fenced epoch released, unlocks the session, and returns a
// clean connection to the pool. A failed unlock destroys the connection.
func (l *Lease) Release(ctx context.Context, token Token) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil || token != l.current {
		return ErrFenced
	}
	conn := l.conn
	l.conn = nil
	l.current = Token{}

	var result error
	tag, err := conn.Exec(ctx, `
UPDATE cluster_singleton_leases
SET renewed_at = clock_timestamp(), released_at = clock_timestamp()
WHERE lease_name = $1 AND epoch = $2 AND holder_id = $3 AND released_at IS NULL`,
		token.Name, token.Epoch, token.HolderID)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("cluster: mark singleton lease released: %w", err))
	} else if tag.RowsAffected() != 1 {
		result = errors.Join(result, ErrFenced)
	}

	var unlocked bool
	unlockErr := conn.QueryRow(ctx,
		`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockPrefix+l.name,
	).Scan(&unlocked)
	if unlockErr != nil || !unlocked {
		if unlockErr != nil {
			result = errors.Join(result, fmt.Errorf("cluster: unlock singleton advisory lock: %w", unlockErr))
		} else {
			result = errors.Join(result, errors.New("cluster: singleton advisory lock was not held by its connection"))
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.Hijack().Close(closeCtx); err != nil {
			result = errors.Join(result, fmt.Errorf("cluster: close tainted lease connection: %w", err))
		}
		return result
	}
	conn.Release()
	return result
}

func (l *Lease) discardLockedConn(conn *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var unlocked bool
	err := conn.QueryRow(ctx,
		`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockPrefix+l.name,
	).Scan(&unlocked)
	if err == nil && unlocked {
		conn.Release()
		return
	}
	_ = conn.Hijack().Close(ctx)
}
