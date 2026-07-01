// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// genesis is the prev_hash of the first record in a chain.
const genesis = ""

// providerStream is the chain key bound into provider-stream hashes.
const providerStream = "provider"

// Event is one audit record.
type Event struct {
	Seq       int64          `json:"seq"`
	Actor     string         `json:"actor"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Data      map[string]any `json:"data"`
	PrevHash  string         `json:"prev_hash"`
	Hash      string         `json:"hash"`
	CreatedAt time.Time      `json:"created_at"`
}

// computeHash returns the hex SHA-256 over an event's canonical, chained fields.
// streamKey binds the record to its chain (the tenant id, or "provider"), so a
// record cannot be moved between chains without breaking verification. The data
// map is canonicalized via encoding/json (Go sorts map keys), so append and
// verify produce identical bytes.
func computeHash(streamKey string, seq int64, actor, action, target string, data map[string]any, prevHash string) (string, error) {
	if data == nil {
		data = map[string]any{}
	}
	canonicalData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("canonicalize audit data: %w", err)
	}
	header := fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%s\n", streamKey, seq, actor, action, target, prevHash)
	sum := crypto.Hash(append([]byte(header), canonicalData...))
	return hex.EncodeToString(sum), nil
}

// TenantAppend appends an event to the calling tenant's audit chain. It is
// written inside the scope's transaction so it commits or rolls back atomically
// with the action being audited, and RLS confines it to the tenant.
//
// Appends are serialized per tenant with a transaction-scoped advisory lock:
// the chain is a read-head→insert sequence, so two concurrent audited writes
// for the same tenant would otherwise both read seq N and both insert N+1 —
// and UNIQUE (tenant_id, seq) turns the loser into a 23505/500. The lock is
// released with the surrounding commit/rollback, so the append stays atomic
// with the action being audited; different tenants never contend.
func TenantAppend(ctx context.Context, s tenancy.Scope, actor, action, target string, data map[string]any) (Event, error) {
	if _, err := s.Q.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('audit:'||$1::text, 0))`,
		s.Tenant.String()); err != nil {
		return Event{}, fmt.Errorf("lock audit chain: %w", err)
	}
	var lastSeq int64
	prevHash := genesis
	err := s.Q.QueryRow(ctx,
		`SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Event{}, fmt.Errorf("read audit head: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		lastSeq, prevHash = 0, genesis
	}

	ev := Event{Seq: lastSeq + 1, Actor: actor, Action: action, Target: target, Data: data, PrevHash: prevHash}
	ev.Hash, err = computeHash(s.Tenant.String(), ev.Seq, actor, action, target, data, prevHash)
	if err != nil {
		return Event{}, err
	}
	dataJSON, err := json.Marshal(orEmpty(data))
	if err != nil {
		return Event{}, err
	}
	if err := s.Q.QueryRow(ctx,
		`INSERT INTO audit_events (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8) RETURNING created_at`,
		s.Tenant.String(), ev.Seq, actor, action, target, string(dataJSON), prevHash, ev.Hash,
	).Scan(&ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert audit event: %w", err)
	}
	return ev, nil
}

// TenantVerify recomputes the tenant's chain and returns an error describing the
// first record that fails (tampering, reordering, or deletion).
func TenantVerify(ctx context.Context, s tenancy.Scope) error {
	rows, err := s.Q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash FROM audit_events ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	return verify(rows, s.Tenant.String(), genesis)
}

// TenantVerifyFrom recomputes the tenant chain AFTER afterSeq, anchoring on that
// record's stored hash. It is the scoped verifier used after retention pruning:
// the pruned prefix is proven by WORM/SIEM export, while the kept suffix must
// still be internally unbroken.
func TenantVerifyFrom(ctx context.Context, s tenancy.Scope, afterSeq int64) error {
	prev := genesis
	if afterSeq > 0 {
		if err := s.Q.QueryRow(ctx,
			`SELECT hash FROM audit_events WHERE seq = $1`, afterSeq).Scan(&prev); err != nil {
			return fmt.Errorf("read tenant audit anchor seq %d: %w", afterSeq, err)
		}
	}
	rows, err := s.Q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash FROM audit_events
		  WHERE seq > $1 ORDER BY seq`, afterSeq)
	if err != nil {
		return err
	}
	defer rows.Close()
	return verify(rows, s.Tenant.String(), prev)
}

// ProviderAppend appends an event to the global provider/break-glass chain.
// It opens its own transaction so the same advisory-lock serialization that
// protects the per-tenant chains protects the global one (see TenantAppend) —
// a transaction-scoped lock on a bare pool statement would release
// immediately and protect nothing.
func ProviderAppend(ctx context.Context, pool *pgxpool.Pool, actor, action, target string, data map[string]any) (Event, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Event{}, fmt.Errorf("begin provider audit append: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('audit:provider', 0))`); err != nil {
		return Event{}, fmt.Errorf("lock provider audit chain: %w", err)
	}

	var lastSeq int64
	prevHash := genesis
	err = tx.QueryRow(ctx,
		`SELECT seq, hash FROM provider_audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Event{}, fmt.Errorf("read provider audit head: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		lastSeq, prevHash = 0, genesis
	}

	ev := Event{Seq: lastSeq + 1, Actor: actor, Action: action, Target: target, Data: data, PrevHash: prevHash}
	ev.Hash, err = computeHash(providerStream, ev.Seq, actor, action, target, data, prevHash)
	if err != nil {
		return Event{}, err
	}
	dataJSON, err := json.Marshal(orEmpty(data))
	if err != nil {
		return Event{}, err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO provider_audit_events (seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7) RETURNING created_at`,
		ev.Seq, actor, action, target, string(dataJSON), prevHash, ev.Hash,
	).Scan(&ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert provider audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Event{}, fmt.Errorf("commit provider audit event: %w", err)
	}
	return ev, nil
}

// ProviderVerify recomputes the global provider chain.
func ProviderVerify(ctx context.Context, pool *pgxpool.Pool) error {
	return ProviderVerifyFrom(ctx, pool, 0)
}

// ProviderHeadSeq returns the provider chain's current head sequence (0 when
// empty) — capture it before an operation to verify just that operation's
// suffix with ProviderVerifyFrom.
func ProviderHeadSeq(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var seq int64
	err := pool.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM provider_audit_events`).Scan(&seq)
	return seq, err
}

// ProviderVerifyFrom recomputes the provider chain AFTER afterSeq, anchoring
// on that record's stored hash (genesis when afterSeq is 0). It proves the
// suffix's integrity without asserting anything about earlier history — the
// scoped check a caller needs when it shares the global stream with other
// writers (or, in CI, with the tamper-detection suite itself).
func ProviderVerifyFrom(ctx context.Context, pool *pgxpool.Pool, afterSeq int64) error {
	prev := genesis
	if afterSeq > 0 {
		if err := pool.QueryRow(ctx,
			`SELECT hash FROM provider_audit_events WHERE seq = $1`, afterSeq).Scan(&prev); err != nil {
			return fmt.Errorf("read anchor seq %d: %w", afterSeq, err)
		}
	}
	rows, err := pool.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash FROM provider_audit_events
		  WHERE seq > $1 ORDER BY seq`, afterSeq)
	if err != nil {
		return err
	}
	defer rows.Close()
	return verify(rows, providerStream, prev)
}

// verify walks an ordered set of records, recomputing each hash and checking the
// chain linkage.
func verify(rows pgx.Rows, streamKey string, startPrev string) error {
	prev := startPrev
	for rows.Next() {
		var (
			seq                    int64
			actor, action, target  string
			dataBytes              []byte
			storedPrev, storedHash string
		)
		if err := rows.Scan(&seq, &actor, &action, &target, &dataBytes, &storedPrev, &storedHash); err != nil {
			return err
		}
		var data map[string]any
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return fmt.Errorf("seq %d: decode data: %w", seq, err)
		}
		if storedPrev != prev {
			return fmt.Errorf("audit chain broken at seq %d: prev_hash mismatch (record inserted, deleted, or reordered)", seq)
		}
		want, err := computeHash(streamKey, seq, actor, action, target, data, storedPrev)
		if err != nil {
			return err
		}
		if want != storedHash {
			return fmt.Errorf("audit chain broken at seq %d: hash mismatch (record tampered)", seq)
		}
		prev = storedHash
	}
	return rows.Err()
}

func orEmpty(data map[string]any) map[string]any {
	if data == nil {
		return map[string]any{}
	}
	return data
}
