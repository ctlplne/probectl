// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pglease

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewValidatesAndBuildsLease(t *testing.T) {
	if _, err := New(nil, "scheduler", "holder-1"); err == nil || !strings.Contains(err.Error(), "writer pool") {
		t.Fatalf("New(nil) error = %v, want writer-pool refusal", err)
	}

	pool := newLazyPool(t)
	if _, err := New(pool, "", "holder-1"); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("New(empty name) error = %v, want name refusal", err)
	}
	lease, err := New(pool, "scheduler", "holder-1")
	if err != nil {
		t.Fatal(err)
	}
	if lease.name != "scheduler" || lease.holderID != "holder-1" || lease.pool == nil {
		t.Fatalf("lease = %+v, want explicit constructor fields", lease)
	}

	auto, err := New(pool, "retention", "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(auto.holderID, ":")
	if len(parts) < 2 {
		t.Fatalf("generated holder id %q has no host/random separator", auto.holderID)
	}
	randomHex := parts[len(parts)-1]
	decoded, err := hex.DecodeString(randomHex)
	if err != nil || len(decoded) != 12 {
		t.Fatalf("generated holder random suffix %q: bytes=%d err=%v", randomHex, len(decoded), err)
	}
}

func TestLeaseAcquireRenewReleaseHappyPath(t *testing.T) {
	conn := &fakeLeaseConn{
		rows: []pgx.Row{
			fakeLeaseRow{values: []any{true}},
			fakeLeaseRow{values: []any{int64(7)}},
			fakeLeaseRow{values: []any{true}},
		},
		execs: []fakeLeaseExec{
			{tag: pgconn.NewCommandTag("UPDATE 1")},
			{tag: pgconn.NewCommandTag("UPDATE 1")},
		},
	}
	lease := &Lease{pool: fakeLeasePool{conn: conn}, name: "scheduler", holderID: "holder-1"}
	token, won, err := lease.Acquire(context.Background())
	if err != nil || !won {
		t.Fatalf("Acquire = token=%+v won=%v err=%v", token, won, err)
	}
	want := Token{Name: "scheduler", HolderID: "holder-1", Epoch: 7}
	if token != want {
		t.Fatalf("token = %+v, want %+v", token, want)
	}
	if _, _, err := lease.Acquire(context.Background()); !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("second Acquire error = %v, want ErrAlreadyHeld", err)
	}
	if err := lease.Renew(context.Background(), Token{Name: "scheduler", HolderID: "other", Epoch: 7}); !errors.Is(err, ErrFenced) {
		t.Fatalf("Renew wrong holder error = %v, want ErrFenced", err)
	}
	if err := lease.Renew(context.Background(), token); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if err := lease.Release(context.Background(), token); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if !conn.released || conn.closed {
		t.Fatalf("clean release state = released=%v closed=%v", conn.released, conn.closed)
	}
	if err := lease.Release(context.Background(), token); !errors.Is(err, ErrFenced) {
		t.Fatalf("second Release error = %v, want ErrFenced", err)
	}
}

func TestUnacquiredLeaseFailsClosed(t *testing.T) {
	pool := newLazyPool(t)
	lease, err := New(pool, "scheduler", "holder-1")
	if err != nil {
		t.Fatal(err)
	}
	token := Token{Name: "scheduler", HolderID: "holder-1", Epoch: 1}
	if err := lease.Renew(context.Background(), token); !errors.Is(err, ErrFenced) {
		t.Fatalf("Renew before Acquire error = %v, want ErrFenced", err)
	}
	if err := lease.Release(context.Background(), token); !errors.Is(err, ErrFenced) {
		t.Fatalf("Release before Acquire error = %v, want ErrFenced", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, won, err := lease.Acquire(ctx)
	if !errors.Is(err, context.Canceled) || won || got != (Token{}) {
		t.Fatalf("Acquire(canceled) = token=%+v won=%v err=%v, want zero/false/context canceled", got, won, err)
	}
}

func newLazyPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://probectl:probectl@127.0.0.1:1/probectl?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

type fakeLeasePool struct {
	conn leaseConn
	err  error
}

func (p fakeLeasePool) Acquire(context.Context) (leaseConn, error) { return p.conn, p.err }

type fakeLeaseExec struct {
	tag pgconn.CommandTag
	err error
}

type fakeLeaseConn struct {
	rows     []pgx.Row
	execs    []fakeLeaseExec
	released bool
	closed   bool
}

func (c *fakeLeaseConn) QueryRow(context.Context, string, ...any) pgx.Row {
	row := c.rows[0]
	c.rows = c.rows[1:]
	return row
}

func (c *fakeLeaseConn) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	result := c.execs[0]
	c.execs = c.execs[1:]
	return result.tag, result.err
}

func (c *fakeLeaseConn) Release() { c.released = true }

func (c *fakeLeaseConn) CloseTainted(context.Context) error {
	c.closed = true
	return nil
}

type fakeLeaseRow struct {
	values []any
	err    error
}

func (r fakeLeaseRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, value := range r.values {
		switch pointer := dest[i].(type) {
		case *bool:
			*pointer = value.(bool)
		case *int64:
			*pointer = value.(int64)
		default:
			return errors.New("unsupported fake lease scan destination")
		}
	}
	return nil
}
