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
func TenantAppend(ctx context.Context, s tenancy.Scope, actor, action, target string, data map[string]any) (Event, error) {
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
	return verify(rows, s.Tenant.String())
}

// ProviderAppend appends an event to the global provider/break-glass chain.
func ProviderAppend(ctx context.Context, pool *pgxpool.Pool, actor, action, target string, data map[string]any) (Event, error) {
	var lastSeq int64
	prevHash := genesis
	err := pool.QueryRow(ctx,
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
	if err := pool.QueryRow(ctx,
		`INSERT INTO provider_audit_events (seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7) RETURNING created_at`,
		ev.Seq, actor, action, target, string(dataJSON), prevHash, ev.Hash,
	).Scan(&ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert provider audit event: %w", err)
	}
	return ev, nil
}

// ProviderVerify recomputes the global provider chain.
func ProviderVerify(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash FROM provider_audit_events ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	return verify(rows, providerStream)
}

// verify walks an ordered set of records, recomputing each hash and checking the
// chain linkage.
func verify(rows pgx.Rows, streamKey string) error {
	prev := genesis
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
