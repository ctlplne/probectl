// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/l7redact"
)

// EffectiveL7CaptureFloor turns a tenant's stored statement into the floor
// agents and the ingest strip apply (D-43): no or unknown statement is the
// metadata default, and the regulated profile never allows looser than metadata.
func TestEffectiveL7CaptureFloor(t *testing.T) {
	for _, tc := range []struct {
		stmt      string
		regulated bool
		want      string
	}{
		{"", false, l7redact.ModeMetadata},
		{"bogus", false, l7redact.ModeMetadata},
		{l7redact.ModeHeaders, false, l7redact.ModeHeaders},
		{l7redact.ModeFull, false, l7redact.ModeFull},
		{l7redact.ModeLength, false, l7redact.ModeLength},
		{l7redact.ModeHeaders, true, l7redact.ModeMetadata},
		{l7redact.ModeFull, true, l7redact.ModeMetadata},
		{l7redact.ModeLength, true, l7redact.ModeLength},
		{"", true, l7redact.ModeMetadata},
	} {
		if got := EffectiveL7CaptureFloor(tc.stmt, tc.regulated); got != tc.want {
			t.Errorf("EffectiveL7CaptureFloor(%q, regulated=%t) = %q, want %q", tc.stmt, tc.regulated, got, tc.want)
		}
	}
}

type l7ErrSource struct{ err error }

func (e l7ErrSource) PolicyFor(context.Context, string) (Policy, bool, error) {
	return Policy{}, false, e.err
}

// PolicyForStrict fails closed on a store error (AUTHZ-29) but treats a
// missing row as the zero policy, like PolicyFor.
func TestPolicyForStrict(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(Reset)

	Reset()
	if p, err := PolicyForStrict(ctx, "t1"); err != nil || p.RedactExport {
		t.Fatalf("no source: %+v, %v; want the zero policy and no error", p, err)
	}
	boom := errors.New("governance store down")
	SetSource(l7ErrSource{err: boom})
	if _, err := PolicyForStrict(ctx, "t1"); !errors.Is(err, boom) {
		t.Fatalf("store error: got %v, want it surfaced", err)
	}
	SetSource(&fakeSource{ok: false})
	if p, err := PolicyForStrict(ctx, "t1"); err != nil || p.RedactExport {
		t.Fatalf("missing row: %+v, %v; want the zero policy and no error", p, err)
	}
	SetSource(&fakeSource{pol: Policy{RedactExport: true}, ok: true})
	if p, err := PolicyForStrict(ctx, "t1"); err != nil || !p.RedactExport {
		t.Fatalf("stored policy: %+v, %v; want it returned", p, err)
	}
}

// The ingest floor keeps built-in PII redacted and restricted values dropped
// even when a tenant override weakens the category.
func TestTelemetryStrategyForKeepsTheBuiltInFloor(t *testing.T) {
	weakened := Policy{Overrides: map[Category]Class{CatEmail: ClassPublic, CatCredential: ClassPublic}}
	if got := telemetryStrategyFor(weakened, CatEmail); got != StrategyPartial {
		t.Errorf("weakened email: %v, want %v", got, StrategyPartial)
	}
	if got := telemetryStrategyFor(weakened, CatCredential); got != StrategyDrop {
		t.Errorf("weakened credential: %v, want %v", got, StrategyDrop)
	}
	if got := telemetryStrategyFor(Policy{}, CatASN); got != StrategyNone {
		t.Errorf("public asn: %v, want %v", got, StrategyNone)
	}
	if got := telemetryStrategyFor(Policy{}, CatEmail); got != StrategyPartial {
		t.Errorf("default email: %v, want %v", got, StrategyPartial)
	}
	if got := telemetryStrategyFor(Policy{}, Category("unknown_category")); got != StrategyNone {
		t.Errorf("unknown category: %v, want %v", got, StrategyNone)
	}
}

// l7Querier records statements and answers QueryRow with a scripted row.
type l7Querier struct {
	execs   []string
	execErr error
	rowVal  string
	rowErr  error
	queries []string
	args    [][]any
}

func (f *l7Querier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, sql)
	f.args = append(f.args, args)
	return pgconn.CommandTag{}, f.execErr
}

func (f *l7Querier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not used")
}

func (f *l7Querier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	f.queries = append(f.queries, sql)
	return l7Row{val: f.rowVal, err: f.rowErr}
}

type l7Row struct {
	val string
	err error
}

func (r l7Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.val
	return nil
}

func TestL7CaptureRedactionTx(t *testing.T) {
	ctx := context.Background()
	if got, err := L7CaptureRedactionTx(ctx, &l7Querier{rowErr: pgx.ErrNoRows}, "t1"); err != nil || got != "" {
		t.Fatalf("no row: %q, %v; want \"\" and no error (the caller applies the metadata default)", got, err)
	}
	if got, err := L7CaptureRedactionTx(ctx, &l7Querier{rowVal: l7redact.ModeHeaders}, "t1"); err != nil || got != l7redact.ModeHeaders {
		t.Fatalf("stored headers: %q, %v", got, err)
	}
	boom := errors.New("db down")
	if _, err := L7CaptureRedactionTx(ctx, &l7Querier{rowErr: boom}, "t1"); !errors.Is(err, boom) {
		t.Fatalf("read error: %v, want it surfaced", err)
	}
}

// The writer lock serializes a tenant's L7 policy writes even with no row yet
// (advisory lock) and reads the replaced value under FOR UPDATE (RN3).
func TestLockL7CaptureRedactionTx(t *testing.T) {
	ctx := context.Background()
	q := &l7Querier{rowVal: l7redact.ModeLength}
	got, err := lockL7CaptureRedactionTx(ctx, q, "t1")
	if err != nil || got != l7redact.ModeLength {
		t.Fatalf("locked read: %q, %v", got, err)
	}
	if len(q.execs) != 1 || !strings.Contains(q.execs[0], "pg_advisory_xact_lock") {
		t.Fatalf("lock statement = %q, want a transaction-scoped advisory lock", q.execs)
	}
	if len(q.queries) != 1 || !strings.Contains(q.queries[0], "FOR UPDATE") {
		t.Fatalf("read = %q, want it under FOR UPDATE", q.queries)
	}
	if got, err := lockL7CaptureRedactionTx(ctx, &l7Querier{rowErr: pgx.ErrNoRows}, "t1"); err != nil || got != "" {
		t.Fatalf("no row yet: %q, %v; want \"\"", got, err)
	}
	if _, err := lockL7CaptureRedactionTx(ctx, &l7Querier{execErr: errors.New("lock refused")}, "t1"); err == nil {
		t.Fatal("a refused lock must fail the write")
	}
}

// The upsert writes only the L7 column (D-64: its single writer).
func TestUpsertL7CaptureRedactionTxWritesOnlyTheL7Column(t *testing.T) {
	q := &l7Querier{}
	if err := upsertL7CaptureRedactionTx(context.Background(), q, "t1", l7redact.ModeHeaders, "admin@t1"); err != nil {
		t.Fatal(err)
	}
	sql := q.execs[0]
	if !strings.Contains(sql, "ON CONFLICT (tenant_id) DO UPDATE") || !strings.Contains(sql, "l7_capture_redaction = excluded.l7_capture_redaction") {
		t.Fatalf("upsert = %q", sql)
	}
	for _, other := range []string{"classes", "redact_export", "ai_remote_egress"} {
		if strings.Contains(sql, other) {
			t.Fatalf("the L7 upsert must not write %s: %q", other, sql)
		}
	}
	if q.args[0][0] != "t1" || q.args[0][1] != l7redact.ModeHeaders || q.args[0][3] != "admin@t1" {
		t.Fatalf("args = %v", q.args[0])
	}
	if err := upsertL7CaptureRedactionTx(context.Background(), &l7Querier{execErr: errors.New("write refused")}, "t1", "headers", "x"); err == nil {
		t.Fatal("a refused write must surface")
	}
}
