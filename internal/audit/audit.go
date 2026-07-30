// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// streamHead is the small, non-prunable database anchor for one audit chain.
// HeadSeq/HeadHash is the last sequence ever appended, even when retention has
// removed every event row. PrunedSeq/PrunedHash is the exact predecessor of the
// first retained row, so verification can start after an intentional prune
// without treating that prune as tampering.
type streamHead struct {
	HeadSeq    int64
	HeadHash   string
	PrunedSeq  int64
	PrunedHash string
}

func (h streamHead) validate(label string) error {
	if h.HeadSeq < 0 || h.PrunedSeq < 0 || h.PrunedSeq > h.HeadSeq {
		return fmt.Errorf("%s audit stream head has invalid sequence bounds", label)
	}
	if (h.HeadSeq == 0) != (h.HeadHash == "") {
		return fmt.Errorf("%s audit stream head has an invalid head hash", label)
	}
	if (h.PrunedSeq == 0) != (h.PrunedHash == "") {
		return fmt.Errorf("%s audit stream head has an invalid prune anchor hash", label)
	}
	return nil
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
	if err := lockTenantStream(ctx, s.Q, s.Tenant.String()); err != nil {
		return Event{}, fmt.Errorf("lock audit chain: %w", err)
	}
	return tenantAppendLocked(ctx, s, actor, action, target, data)
}

func tenantAppendLocked(ctx context.Context, s tenancy.Scope, actor, action, target string, data map[string]any) (Event, error) {
	head, err := ensureTenantStreamHead(ctx, s.Q, s.Tenant.String())
	if err != nil {
		return Event{}, fmt.Errorf("read audit head: %w", err)
	}
	ev := Event{
		Seq:      head.HeadSeq + 1,
		Actor:    actor,
		Action:   action,
		Target:   target,
		Data:     data,
		PrevHash: head.HeadHash,
	}
	ev.Hash, err = computeHash(s.Tenant.String(), ev.Seq, actor, action, target, data, ev.PrevHash)
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
		s.Tenant.String(), ev.Seq, actor, action, target, string(dataJSON), ev.PrevHash, ev.Hash,
	).Scan(&ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert audit event: %w", err)
	}
	if err := advanceTenantStreamHead(ctx, s.Q, s.Tenant.String(), head, ev); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// TenantVerify recomputes the retained tenant suffix from its durable prune
// anchor and checks that it reaches the durable head. Intentional retention is
// therefore valid, while deletion/tampering anywhere in the retained suffix
// (including its tail) is still detected.
func TenantVerify(ctx context.Context, s tenancy.Scope) error {
	if err := lockTenantStream(ctx, s.Q, s.Tenant.String()); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}
	head, err := ensureTenantStreamHead(ctx, s.Q, s.Tenant.String())
	if err != nil {
		return err
	}
	return tenantVerifyFromLocked(ctx, s, head, 0)
}

// TenantVerifyFrom recomputes the tenant chain AFTER afterSeq. If afterSeq is
// the durable prune sequence, its stored prune hash is used even though the
// event row is intentionally gone. Asking to start inside an already-pruned
// prefix fails closed because that older anchor is no longer locally provable.
func TenantVerifyFrom(ctx context.Context, s tenancy.Scope, afterSeq int64) error {
	if afterSeq < 0 {
		return fmt.Errorf("tenant audit anchor sequence must be non-negative")
	}
	if err := lockTenantStream(ctx, s.Q, s.Tenant.String()); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}
	head, err := ensureTenantStreamHead(ctx, s.Q, s.Tenant.String())
	if err != nil {
		return err
	}
	return tenantVerifyFromLocked(ctx, s, head, afterSeq)
}

// ProviderAppend appends an event to the global provider/break-glass chain in
// its own provider-scoped transaction. Mutations that must commit atomically
// with their audit event use ProviderAppendTx inside their existing
// tenancy.InProvider transaction instead.
func ProviderAppend(ctx context.Context, pool *pgxpool.Pool, actor, action, target string, data map[string]any) (Event, error) {
	var ev Event
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		ev, err = ProviderAppendTx(ctx, q, actor, action, target, data)
		return err
	})
	return ev, err
}

// ProviderAppendTx appends an event using the caller's provider transaction.
// The caller owns commit/rollback. Keeping the action and this append in the
// same tenancy.InProvider callback makes an audit failure fail closed without
// leaving an unaudited provider mutation.
func ProviderAppendTx(ctx context.Context, q tenancy.Querier, actor, action, target string, data map[string]any) (Event, error) {
	if err := lockProviderStream(ctx, q); err != nil {
		return Event{}, fmt.Errorf("lock provider audit chain: %w", err)
	}
	return providerAppendLocked(ctx, q, actor, action, target, data)
}

func providerAppendLocked(ctx context.Context, q tenancy.Querier, actor, action, target string, data map[string]any) (Event, error) {
	head, err := ensureProviderStreamHead(ctx, q)
	if err != nil {
		return Event{}, fmt.Errorf("read provider audit head: %w", err)
	}
	ev := Event{
		Seq:      head.HeadSeq + 1,
		Actor:    actor,
		Action:   action,
		Target:   target,
		Data:     data,
		PrevHash: head.HeadHash,
	}
	ev.Hash, err = computeHash(providerStream, ev.Seq, actor, action, target, data, ev.PrevHash)
	if err != nil {
		return Event{}, err
	}
	dataJSON, err := json.Marshal(orEmpty(data))
	if err != nil {
		return Event{}, err
	}
	if err := q.QueryRow(ctx,
		`INSERT INTO provider_audit_events (seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7) RETURNING created_at`,
		ev.Seq, actor, action, target, string(dataJSON), ev.PrevHash, ev.Hash,
	).Scan(&ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("insert provider audit event: %w", err)
	}
	if err := advanceProviderStreamHead(ctx, q, head, ev); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// ProviderVerify recomputes the retained provider suffix from its durable
// prune anchor and proves that it reaches the durable head.
func ProviderVerify(ctx context.Context, pool *pgxpool.Pool) error {
	return ProviderVerifyFrom(ctx, pool, 0)
}

// ProviderHeadSeq returns the durable provider head sequence (0 when empty).
// Unlike MAX(provider_audit_events.seq), it cannot move backward after
// retention removes every currently stored event row.
func ProviderHeadSeq(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin provider head read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockProviderStream(ctx, tx); err != nil {
		return 0, fmt.Errorf("lock provider audit chain: %w", err)
	}
	head, err := ensureProviderStreamHead(ctx, tx)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit provider head read: %w", err)
	}
	return head.HeadSeq, nil
}

// ProviderVerifyFrom recomputes the provider chain AFTER afterSeq, anchoring
// on that record's stored hash (genesis when afterSeq is 0). It proves the
// suffix's integrity without asserting anything about earlier history — the
// scoped check a caller needs when it shares the global stream with other
// writers (or, in CI, with the tamper-detection suite itself).
func ProviderVerifyFrom(ctx context.Context, pool *pgxpool.Pool, afterSeq int64) error {
	if afterSeq < 0 {
		return fmt.Errorf("provider audit anchor sequence must be non-negative")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin provider audit verify: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockProviderStream(ctx, tx); err != nil {
		return fmt.Errorf("lock provider audit chain: %w", err)
	}
	head, err := ensureProviderStreamHead(ctx, tx)
	if err != nil {
		return err
	}
	if err := providerVerifyFromLocked(ctx, tx, head, afterSeq); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit provider audit verify: %w", err)
	}
	return nil
}

func lockTenantStream(ctx context.Context, q tenancy.Querier, tenantID string) error {
	_, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('audit:'||$1::text, 0))`,
		tenantID,
	)
	return err
}

func lockProviderStream(ctx context.Context, q tenancy.Querier) error {
	_, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('audit:provider', 0))`,
	)
	return err
}

func readTenantStreamHead(ctx context.Context, q tenancy.Querier, tenantID string) (streamHead, bool, error) {
	var head streamHead
	err := q.QueryRow(
		ctx,
		`SELECT head_seq, head_hash, pruned_seq, pruned_hash
		   FROM public.audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&head.HeadSeq, &head.HeadHash, &head.PrunedSeq, &head.PrunedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamHead{}, false, nil
	}
	if err != nil {
		return streamHead{}, false, fmt.Errorf("read tenant audit stream head: %w", err)
	}
	if err := head.validate("tenant"); err != nil {
		return streamHead{}, false, err
	}
	return head, true, nil
}

func readProviderStreamHead(ctx context.Context, q tenancy.Querier) (streamHead, bool, error) {
	var head streamHead
	err := q.QueryRow(
		ctx,
		`SELECT head_seq, head_hash, pruned_seq, pruned_hash
		   FROM provider_audit_stream_head
		  WHERE singleton`,
	).Scan(&head.HeadSeq, &head.HeadHash, &head.PrunedSeq, &head.PrunedHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamHead{}, false, nil
	}
	if err != nil {
		return streamHead{}, false, fmt.Errorf("read provider audit stream head: %w", err)
	}
	if err := head.validate("provider"); err != nil {
		return streamHead{}, false, err
	}
	return head, true, nil
}

type streamBounds struct {
	FirstSeq      int64
	FirstPrevHash string
	LastSeq       int64
	LastHash      string
}

func readTenantStreamBounds(ctx context.Context, q tenancy.Querier, tenantID string) (streamBounds, bool, error) {
	var bounds streamBounds
	err := q.QueryRow(
		ctx,
		`SELECT first_row.seq, first_row.prev_hash, last_row.seq, last_row.hash
		   FROM LATERAL (
		       SELECT seq, prev_hash
		         FROM audit_events
		        WHERE tenant_id = $1::uuid
		        ORDER BY seq
		        LIMIT 1
		   ) AS first_row
		  CROSS JOIN LATERAL (
		       SELECT seq, hash
		         FROM audit_events
		        WHERE tenant_id = $1::uuid
		        ORDER BY seq DESC
		        LIMIT 1
		   ) AS last_row`,
		tenantID,
	).Scan(&bounds.FirstSeq, &bounds.FirstPrevHash, &bounds.LastSeq, &bounds.LastHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamBounds{}, false, nil
	}
	if err != nil {
		return streamBounds{}, false, fmt.Errorf("read tenant audit event bounds: %w", err)
	}
	return bounds, true, nil
}

func readProviderStreamBounds(ctx context.Context, q tenancy.Querier) (streamBounds, bool, error) {
	var bounds streamBounds
	err := q.QueryRow(
		ctx,
		`SELECT first_row.seq, first_row.prev_hash, last_row.seq, last_row.hash
		   FROM LATERAL (
		       SELECT seq, prev_hash
		         FROM provider_audit_events
		        ORDER BY seq
		        LIMIT 1
		   ) AS first_row
		  CROSS JOIN LATERAL (
		       SELECT seq, hash
		         FROM provider_audit_events
		        ORDER BY seq DESC
		        LIMIT 1
		   ) AS last_row`,
	).Scan(&bounds.FirstSeq, &bounds.FirstPrevHash, &bounds.LastSeq, &bounds.LastHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamBounds{}, false, nil
	}
	if err != nil {
		return streamBounds{}, false, fmt.Errorf("read provider audit event bounds: %w", err)
	}
	return bounds, true, nil
}

// ensureTenantStreamHead reconciles the durable head with retained rows. The
// reconciliation is needed during a rolling upgrade: an older binary can still
// append a correctly chained row without advancing the new metadata table.
// It never accepts a rewind or a missing unpruned tail.
func ensureTenantStreamHead(ctx context.Context, q tenancy.Querier, tenantID string) (streamHead, error) {
	exportCursor, err := readTenantAuditExportCursor(ctx, q, tenantID)
	if err != nil {
		return streamHead{}, err
	}
	return ensureTenantStreamHeadAtCursor(ctx, q, tenantID, exportCursor)
}

// ensureTenantStreamHeadAtCursor performs the same reconciliation using an
// already-proven exporter watermark. The provider-role retention transaction
// uses this form so it never gains read access to tenant SIEM delivery state.
func ensureTenantStreamHeadAtCursor(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	exportCursor int64,
) (streamHead, error) {
	head, haveHead, err := readTenantStreamHead(ctx, q, tenantID)
	if err != nil {
		return streamHead{}, err
	}
	bounds, haveEvents, err := readTenantStreamBounds(ctx, q, tenantID)
	if err != nil {
		return streamHead{}, err
	}
	if !haveEvents {
		if !haveHead {
			if exportCursor > 0 {
				return streamHead{}, fmt.Errorf(
					"tenant audit stream head is unrecoverable: SIEM cursor %d exists but no retained event or durable head remains; restore the pre-retention anchor before appending",
					exportCursor,
				)
			}
			return streamHead{}, nil
		}
		if err := validateTenantCursorAgainstHead(exportCursor, head); err != nil {
			return streamHead{}, err
		}
		if head.HeadSeq != head.PrunedSeq || head.HeadHash != head.PrunedHash {
			return streamHead{}, fmt.Errorf(
				"tenant audit stream tail missing after seq %d (durable head is %d)",
				head.PrunedSeq,
				head.HeadSeq,
			)
		}
		return head, nil
	}
	if !haveHead {
		head = inferredStreamHead(bounds)
		if err := validateTenantCursorAgainstHead(exportCursor, head); err != nil {
			return streamHead{}, fmt.Errorf(
				"tenant audit stream head cannot be reconstructed safely: %w",
				err,
			)
		}
		tag, err := q.Exec(
			ctx,
			`INSERT INTO public.audit_stream_heads
			    (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, now())
			 ON CONFLICT (tenant_id) DO NOTHING`,
			tenantID,
			head.HeadSeq,
			head.HeadHash,
			head.PrunedSeq,
			head.PrunedHash,
		)
		if err != nil {
			return streamHead{}, fmt.Errorf("initialize tenant audit stream head: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return streamHead{}, fmt.Errorf("initialize tenant audit stream head: concurrent state change")
		}
		return head, nil
	}
	if bounds.FirstSeq != head.PrunedSeq+1 || bounds.FirstPrevHash != head.PrunedHash {
		return streamHead{}, fmt.Errorf(
			"tenant audit retention boundary broken: first retained seq %d does not follow prune anchor %d",
			bounds.FirstSeq,
			head.PrunedSeq,
		)
	}
	if bounds.LastSeq < head.HeadSeq {
		return streamHead{}, fmt.Errorf(
			"tenant audit stream tail deleted: retained head %d is behind durable head %d",
			bounds.LastSeq,
			head.HeadSeq,
		)
	}
	if bounds.LastSeq == head.HeadSeq {
		if bounds.LastHash != head.HeadHash {
			return streamHead{}, fmt.Errorf("tenant audit durable head hash mismatch at seq %d", head.HeadSeq)
		}
		if err := validateTenantCursorAgainstHead(exportCursor, head); err != nil {
			return streamHead{}, err
		}
		return head, nil
	}
	if err := verifyTenantExtension(ctx, q, tenantID, head, bounds); err != nil {
		return streamHead{}, err
	}
	if err := updateTenantHead(ctx, q, tenantID, head, bounds.LastSeq, bounds.LastHash); err != nil {
		return streamHead{}, err
	}
	head.HeadSeq, head.HeadHash = bounds.LastSeq, bounds.LastHash
	if err := validateTenantCursorAgainstHead(exportCursor, head); err != nil {
		return streamHead{}, err
	}
	return head, nil
}

func readTenantAuditExportCursor(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
) (int64, error) {
	var cursor int64
	err := q.QueryRow(
		ctx,
		`SELECT last_seq FROM siem_delivery WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read tenant audit SIEM cursor: %w", err)
	}
	if cursor < 0 {
		return 0, fmt.Errorf("tenant audit SIEM cursor is negative")
	}
	return cursor, nil
}

func validateTenantCursorAgainstHead(cursor int64, head streamHead) error {
	if cursor > head.HeadSeq {
		return fmt.Errorf(
			"tenant audit SIEM cursor %d is above durable head %d; refusing to append behind an existing exporter cursor",
			cursor,
			head.HeadSeq,
		)
	}
	if cursor < head.PrunedSeq {
		return fmt.Errorf(
			"tenant audit SIEM cursor %d is behind prune anchor %d",
			cursor,
			head.PrunedSeq,
		)
	}
	return nil
}

func ensureProviderStreamHead(ctx context.Context, q tenancy.Querier) (streamHead, error) {
	head, haveHead, err := readProviderStreamHead(ctx, q)
	if err != nil {
		return streamHead{}, err
	}
	bounds, haveEvents, err := readProviderStreamBounds(ctx, q)
	if err != nil {
		return streamHead{}, err
	}
	if !haveEvents {
		if !haveHead {
			return streamHead{}, nil
		}
		if head.HeadSeq != head.PrunedSeq || head.HeadHash != head.PrunedHash {
			return streamHead{}, fmt.Errorf(
				"provider audit stream tail missing after seq %d (durable head is %d)",
				head.PrunedSeq,
				head.HeadSeq,
			)
		}
		return head, nil
	}
	if !haveHead {
		head = inferredStreamHead(bounds)
		tag, err := q.Exec(
			ctx,
			`INSERT INTO provider_audit_stream_head
			    (singleton, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
			 VALUES (true, $1, $2, $3, $4, now())
			 ON CONFLICT (singleton) DO NOTHING`,
			head.HeadSeq,
			head.HeadHash,
			head.PrunedSeq,
			head.PrunedHash,
		)
		if err != nil {
			return streamHead{}, fmt.Errorf("initialize provider audit stream head: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return streamHead{}, fmt.Errorf("initialize provider audit stream head: concurrent state change")
		}
		return head, nil
	}
	if bounds.FirstSeq != head.PrunedSeq+1 || bounds.FirstPrevHash != head.PrunedHash {
		return streamHead{}, fmt.Errorf(
			"provider audit retention boundary broken: first retained seq %d does not follow prune anchor %d",
			bounds.FirstSeq,
			head.PrunedSeq,
		)
	}
	if bounds.LastSeq < head.HeadSeq {
		return streamHead{}, fmt.Errorf(
			"provider audit stream tail deleted: retained head %d is behind durable head %d",
			bounds.LastSeq,
			head.HeadSeq,
		)
	}
	if bounds.LastSeq == head.HeadSeq {
		if bounds.LastHash != head.HeadHash {
			return streamHead{}, fmt.Errorf("provider audit durable head hash mismatch at seq %d", head.HeadSeq)
		}
		return head, nil
	}
	if err := verifyProviderExtension(ctx, q, head, bounds); err != nil {
		return streamHead{}, err
	}
	if err := updateProviderHead(ctx, q, head, bounds.LastSeq, bounds.LastHash); err != nil {
		return streamHead{}, err
	}
	head.HeadSeq, head.HeadHash = bounds.LastSeq, bounds.LastHash
	return head, nil
}

func inferredStreamHead(bounds streamBounds) streamHead {
	head := streamHead{HeadSeq: bounds.LastSeq, HeadHash: bounds.LastHash}
	if bounds.FirstSeq > 1 {
		head.PrunedSeq = bounds.FirstSeq - 1
		head.PrunedHash = bounds.FirstPrevHash
	}
	return head
}

func verifyTenantExtension(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	head streamHead,
	bounds streamBounds,
) error {
	rows, err := q.Query(
		ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash
		   FROM audit_events
		  WHERE tenant_id = $1::uuid AND seq > $2
		  ORDER BY seq`,
		tenantID,
		head.HeadSeq,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	lastSeq, lastHash, err := verify(rows, tenantID, head.HeadSeq+1, head.HeadHash)
	if err != nil {
		return fmt.Errorf("verify tenant audit rolling-upgrade extension: %w", err)
	}
	if lastSeq != bounds.LastSeq || lastHash != bounds.LastHash {
		return fmt.Errorf("tenant audit rolling-upgrade extension did not reach retained head")
	}
	return nil
}

func verifyProviderExtension(
	ctx context.Context,
	q tenancy.Querier,
	head streamHead,
	bounds streamBounds,
) error {
	rows, err := q.Query(
		ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash
		   FROM provider_audit_events
		  WHERE seq > $1
		  ORDER BY seq`,
		head.HeadSeq,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	lastSeq, lastHash, err := verify(rows, providerStream, head.HeadSeq+1, head.HeadHash)
	if err != nil {
		return fmt.Errorf("verify provider audit rolling-upgrade extension: %w", err)
	}
	if lastSeq != bounds.LastSeq || lastHash != bounds.LastHash {
		return fmt.Errorf("provider audit rolling-upgrade extension did not reach retained head")
	}
	return nil
}

func advanceTenantStreamHead(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	head streamHead,
	ev Event,
) error {
	if err := updateTenantHead(ctx, q, tenantID, head, ev.Seq, ev.Hash); err != nil {
		return fmt.Errorf("advance tenant audit stream head: %w", err)
	}
	return nil
}

func updateTenantHead(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	old streamHead,
	newSeq int64,
	newHash string,
) error {
	tag, err := q.Exec(
		ctx,
		`INSERT INTO public.audit_stream_heads AS heads
		    (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
		 VALUES ($1::uuid, $2, $3, $4, $5, now())
		 ON CONFLICT (tenant_id) DO UPDATE
		       SET head_seq = EXCLUDED.head_seq,
		           head_hash = EXCLUDED.head_hash,
		           updated_at = now()
		     WHERE heads.head_seq = $6
		       AND heads.head_hash = $7`,
		tenantID,
		newSeq,
		newHash,
		old.PrunedSeq,
		old.PrunedHash,
		old.HeadSeq,
		old.HeadHash,
	)
	if err != nil {
		return fmt.Errorf("update tenant audit stream head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update tenant audit stream head: non-monotonic state transition")
	}
	return nil
}

func advanceProviderStreamHead(ctx context.Context, q tenancy.Querier, head streamHead, ev Event) error {
	if err := updateProviderHead(ctx, q, head, ev.Seq, ev.Hash); err != nil {
		return fmt.Errorf("advance provider audit stream head: %w", err)
	}
	return nil
}

func updateProviderHead(
	ctx context.Context,
	q tenancy.Querier,
	old streamHead,
	newSeq int64,
	newHash string,
) error {
	tag, err := q.Exec(
		ctx,
		`INSERT INTO provider_audit_stream_head AS heads
		    (singleton, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
		 VALUES (true, $1, $2, $3, $4, now())
		 ON CONFLICT (singleton) DO UPDATE
		       SET head_seq = EXCLUDED.head_seq,
		           head_hash = EXCLUDED.head_hash,
		           updated_at = now()
		     WHERE heads.head_seq = $5
		       AND heads.head_hash = $6`,
		newSeq,
		newHash,
		old.PrunedSeq,
		old.PrunedHash,
		old.HeadSeq,
		old.HeadHash,
	)
	if err != nil {
		return fmt.Errorf("update provider audit stream head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("update provider audit stream head: non-monotonic state transition")
	}
	return nil
}

func tenantVerifyFromLocked(ctx context.Context, s tenancy.Scope, head streamHead, afterSeq int64) error {
	startSeq, prevHash, err := tenantVerificationAnchor(ctx, s, head, afterSeq)
	if err != nil {
		return err
	}
	rows, err := s.Q.Query(
		ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash
		   FROM audit_events
		  WHERE tenant_id = $1::uuid AND seq > $2
		  ORDER BY seq`,
		s.Tenant.String(),
		startSeq,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	lastSeq, lastHash, err := verify(rows, s.Tenant.String(), startSeq+1, prevHash)
	if err != nil {
		return err
	}
	return verifyReachedHead("tenant", head, lastSeq, lastHash)
}

func tenantVerificationAnchor(
	ctx context.Context,
	s tenancy.Scope,
	head streamHead,
	afterSeq int64,
) (int64, string, error) {
	if afterSeq == 0 {
		return head.PrunedSeq, head.PrunedHash, nil
	}
	if afterSeq < head.PrunedSeq {
		return 0, "", fmt.Errorf(
			"tenant audit anchor seq %d was pruned through seq %d",
			afterSeq,
			head.PrunedSeq,
		)
	}
	if afterSeq > head.HeadSeq {
		return 0, "", fmt.Errorf(
			"tenant audit anchor seq %d is above durable head %d",
			afterSeq,
			head.HeadSeq,
		)
	}
	if afterSeq == head.PrunedSeq {
		return afterSeq, head.PrunedHash, nil
	}
	var hash string
	if err := s.Q.QueryRow(
		ctx,
		`SELECT hash FROM audit_events WHERE tenant_id = $1::uuid AND seq = $2`,
		s.Tenant.String(),
		afterSeq,
	).Scan(&hash); err != nil {
		return 0, "", fmt.Errorf("read tenant audit anchor seq %d: %w", afterSeq, err)
	}
	return afterSeq, hash, nil
}

func providerVerifyFromLocked(
	ctx context.Context,
	q tenancy.Querier,
	head streamHead,
	afterSeq int64,
) error {
	startSeq, prevHash, err := providerVerificationAnchor(ctx, q, head, afterSeq)
	if err != nil {
		return err
	}
	rows, err := q.Query(
		ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash
		   FROM provider_audit_events
		  WHERE seq > $1
		  ORDER BY seq`,
		startSeq,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	lastSeq, lastHash, err := verify(rows, providerStream, startSeq+1, prevHash)
	if err != nil {
		return err
	}
	return verifyReachedHead("provider", head, lastSeq, lastHash)
}

func providerVerificationAnchor(
	ctx context.Context,
	q tenancy.Querier,
	head streamHead,
	afterSeq int64,
) (int64, string, error) {
	if afterSeq == 0 {
		return head.PrunedSeq, head.PrunedHash, nil
	}
	if afterSeq < head.PrunedSeq {
		return 0, "", fmt.Errorf(
			"provider audit anchor seq %d was pruned through seq %d",
			afterSeq,
			head.PrunedSeq,
		)
	}
	if afterSeq > head.HeadSeq {
		return 0, "", fmt.Errorf(
			"provider audit anchor seq %d is above durable head %d",
			afterSeq,
			head.HeadSeq,
		)
	}
	if afterSeq == head.PrunedSeq {
		return afterSeq, head.PrunedHash, nil
	}
	var hash string
	if err := q.QueryRow(
		ctx,
		`SELECT hash FROM provider_audit_events WHERE seq = $1`,
		afterSeq,
	).Scan(&hash); err != nil {
		return 0, "", fmt.Errorf("read provider audit anchor seq %d: %w", afterSeq, err)
	}
	return afterSeq, hash, nil
}

func verifyReachedHead(label string, head streamHead, lastSeq int64, lastHash string) error {
	if lastSeq != head.HeadSeq {
		return fmt.Errorf(
			"%s audit chain ended at seq %d before durable head %d (tail deleted)",
			label,
			lastSeq,
			head.HeadSeq,
		)
	}
	if lastHash != head.HeadHash {
		return fmt.Errorf("%s audit chain durable head hash mismatch at seq %d", label, head.HeadSeq)
	}
	return nil
}

// verify walks an ordered set of records, recomputing each hash and checking
// sequence continuity plus chain linkage. It returns the verified tail.
func verify(rows pgx.Rows, streamKey string, wantSeq int64, startPrev string) (int64, string, error) {
	prev := startPrev
	lastSeq := wantSeq - 1
	for rows.Next() {
		var (
			seq                    int64
			actor, action, target  string
			dataBytes              []byte
			storedPrev, storedHash string
		)
		if err := rows.Scan(&seq, &actor, &action, &target, &dataBytes, &storedPrev, &storedHash); err != nil {
			return 0, "", err
		}
		var data map[string]any
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return 0, "", fmt.Errorf("seq %d: decode data: %w", seq, err)
		}
		if seq != wantSeq {
			return 0, "", fmt.Errorf(
				"audit chain broken at seq %d: sequence gap (want %d)",
				seq,
				wantSeq,
			)
		}
		if storedPrev != prev {
			return 0, "", fmt.Errorf("audit chain broken at seq %d: prev_hash mismatch (record inserted, deleted, or reordered)", seq)
		}
		want, err := computeHash(streamKey, seq, actor, action, target, data, storedPrev)
		if err != nil {
			return 0, "", err
		}
		if want != storedHash {
			return 0, "", fmt.Errorf("audit chain broken at seq %d: hash mismatch (record tampered)", seq)
		}
		prev = storedHash
		lastSeq = seq
		wantSeq++
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	return lastSeq, prev, nil
}

func orEmpty(data map[string]any) map[string]any {
	if data == nil {
		return map[string]any{}
	}
	return data
}
