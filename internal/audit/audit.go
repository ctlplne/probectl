// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// genesis is the prev_hash of the first record in a chain.
const genesis = ""

// auditNow stamps an event's created_at. It is a package variable only so that
// integration tests which exercise time-based retention can create events at a
// chosen time WITHOUT mutating created_at after the fact (which, since AUD-02,
// is covered by the hash chain and would read as tampering). Production code
// never overrides it. Microsecond truncation matches Postgres timestamptz.
var auditNow = func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

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

	// canonicalData is the EXACT JSON byte sequence the hash chain covers for
	// this event (docs/guardrails.md G7-N; AUD-03). It is read verbatim from the
	// durable data_canonical column so verification hashes the same bytes the
	// append side hashed — never a re-marshal of the jsonb-decoded map, which
	// loses >2^53 integer precision and reorders keys. Unexported, so it is never
	// serialized into API responses or WORM segments; nil for rows written before
	// the column existed (verification then falls back to the legacy recompute).
	canonicalData []byte
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

	// HeadSig is the Ed25519 signature over the canonical head
	// (tenant_id, head_seq, head_hash) produced by the control plane's offline
	// WORM key (AUD-01; docs/guardrails.md G7-7). It anchors the chain OUTSIDE
	// the database's trust domain: a DB writer cannot forge it. Empty for a
	// legacy head written before the head_sig column, or when head anchoring is
	// not configured. Only populated for the tenant stream; the provider stream
	// is anchored separately by the signed WORM export (worm.go).
	HeadSig []byte
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

// escapeHeaderField makes the newline-delimited hash header an unambiguous
// encoding (docs/guardrails.md G7-N; AUD-03). The header joins string fields
// with '\n'; without escaping, a field value that itself contains a newline can
// shift a delimiter, so two DISTINCT field tuples — e.g. (actor "a\nb",
// action "c") and (actor "a", action "b\nc") — serialize to the same bytes and
// collide to the same hash. Escaping '\' then '\n' (to the two-byte sequences
// `\\` and `\n`) makes every boundary recoverable. It is the IDENTITY for any
// value containing neither byte, so every hash written before AUD-03 — tenant
// ids, hex prev-hashes and ordinary dotted actions/actors/targets never contain
// '\' or newlines — stays byte-identical.
func escapeHeaderField(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// auditHeader builds the chained, canonical header hashed ahead of the data
// bytes. streamKey binds the record to its chain (the tenant id, or "provider"),
// so a record cannot be moved between chains without breaking verification.
// AUD-02: created_at (as Unix microseconds, matching Postgres timestamptz
// precision) is part of the header, so back- or forward-dating a stored event
// with an UPDATE breaks verification at that sequence. Micros are instant-based,
// so the hash is stable regardless of the read-back session time zone.
func auditHeader(streamKey string, seq int64, actor, action, target string, createdAtMicros int64, prevHash string) string {
	return fmt.Sprintf(
		"%s\n%d\n%s\n%s\n%s\n%d\n%s\n",
		escapeHeaderField(streamKey),
		seq,
		escapeHeaderField(actor),
		escapeHeaderField(action),
		escapeHeaderField(target),
		createdAtMicros,
		escapeHeaderField(prevHash),
	)
}

// chainEventHash returns the hex SHA-256 over an event's header plus the EXACT
// canonical data bytes. AUD-03: the caller passes the precise byte sequence that
// was (or will be) stored, so append and verify hash identical bytes. It never
// re-marshals a decoded map, which would corrupt >2^53 integers and reorder keys.
func chainEventHash(streamKey string, seq int64, actor, action, target string, createdAtMicros int64, canonicalData []byte, prevHash string) string {
	header := auditHeader(streamKey, seq, actor, action, target, createdAtMicros, prevHash)
	sum := crypto.Hash(append([]byte(header), canonicalData...))
	return hex.EncodeToString(sum)
}

// canonicalAuditData is the single canonicalization door for audit payloads: the
// bytes produced here are BOTH stored (data_canonical) AND hashed on append, so
// verification need only hash the stored bytes back. Go's encoding/json sorts
// map keys, so the output is deterministic for a given map.
func canonicalAuditData(data map[string]any) ([]byte, error) {
	canonical, err := json.Marshal(orEmpty(data))
	if err != nil {
		return nil, fmt.Errorf("canonicalize audit data: %w", err)
	}
	return canonical, nil
}

// computeHash hashes an event whose data is still an in-memory map. It is the
// append-time and legacy/in-memory path (rows written before data_canonical
// existed, and synthetic test events). Readers with durable canonical bytes use
// chainEventHash directly so they never reconstruct the bytes from the jsonb.
func computeHash(streamKey string, seq int64, actor, action, target string, createdAtMicros int64, data map[string]any, prevHash string) (string, error) {
	canonical, err := canonicalAuditData(data)
	if err != nil {
		return "", err
	}
	return chainEventHash(streamKey, seq, actor, action, target, createdAtMicros, canonical, prevHash), nil
}

// eventHash recomputes a read-back event's hash over the bytes it is bound to:
// the durable canonical bytes when present, else (legacy/pre-AUD-03 or synthetic
// in-memory events) the re-canonicalized map. Both branches are byte-identical
// for honest data, so mixed-vintage chains link seamlessly.
func eventHash(streamKey string, ev Event) (string, error) {
	if len(ev.canonicalData) > 0 {
		return chainEventHash(streamKey, ev.Seq, ev.Actor, ev.Action, ev.Target, ev.CreatedAt.UnixMicro(), ev.canonicalData, ev.PrevHash), nil
	}
	return computeHash(streamKey, ev.Seq, ev.Actor, ev.Action, ev.Target, ev.CreatedAt.UnixMicro(), ev.Data, ev.PrevHash)
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
		// AUD-02: the application stamps created_at so it can be covered by the
		// hash chain (micros to match Postgres timestamptz precision).
		CreatedAt: auditNow(),
	}
	// AUD-03: marshal the canonical bytes ONCE, then store AND hash the identical
	// sequence. data_canonical holds those exact bytes so verification hashes them
	// verbatim; the jsonb data column is the queryable mirror, kept in lock-step
	// with the hashed bytes by a CHECK constraint (migration 0108).
	canonical, err := canonicalAuditData(data)
	if err != nil {
		return Event{}, err
	}
	ev.canonicalData = canonical
	ev.Hash = chainEventHash(s.Tenant.String(), ev.Seq, actor, action, target, ev.CreatedAt.UnixMicro(), canonical, ev.PrevHash)
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO audit_events (tenant_id, seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)`,
		s.Tenant.String(), ev.Seq, actor, action, target, string(canonical), ev.PrevHash, ev.Hash, ev.CreatedAt, string(canonical),
	); err != nil {
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

// tenantVerifyFrom recomputes the tenant chain AFTER afterSeq. If afterSeq is
// the durable prune sequence, its stored prune hash is used even though the
// event row is intentionally gone. Asking to start inside an already-pruned
// prefix fails closed because that older anchor is no longer locally provable.
func tenantVerifyFrom(ctx context.Context, s tenancy.Scope, afterSeq int64) error {
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
	if isProtectedBreakGlassAction(action) {
		return Event{}, fmt.Errorf(
			"audit: protected break-glass action %q requires encrypted IR attribution",
			action,
		)
	}
	if err := lockProviderStream(ctx, q); err != nil {
		return Event{}, fmt.Errorf("lock provider audit chain: %w", err)
	}
	return providerAppendLocked(ctx, q, actor, action, target, data)
}

func providerAppendLocked(ctx context.Context, q tenancy.Querier, actor, action, target string, data map[string]any) (Event, error) {
	return providerAppendLockedWith(ctx, q, actor, action, target, data, nil)
}

// ProviderAppendBreakGlass appends one protected provider event and its
// encrypted attribution in one provider transaction.
func ProviderAppendBreakGlass(
	ctx context.Context,
	pool *pgxpool.Pool,
	sidecar IRStageAppender,
	actor, action, target string,
	data map[string]any,
	attribution IRAttribution,
) (Event, error) {
	var event Event
	err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		event, err = ProviderAppendBreakGlassTx(
			ctx,
			q,
			sidecar,
			actor,
			action,
			target,
			data,
			attribution,
		)
		return err
	})
	return event, err
}

// ProviderAppendBreakGlassTx is the only append seam for provider.breakglass_*
// actions. The caller owns the transaction, so a sidecar seal/insert failure
// rolls back the protected mutation and provider event together.
func ProviderAppendBreakGlassTx(
	ctx context.Context,
	q tenancy.Querier,
	sidecar IRStageAppender,
	actor, action, target string,
	data map[string]any,
	attribution IRAttribution,
) (Event, error) {
	if sidecar == nil {
		return Event{}, errors.New("audit: encrypted IR attribution sidecar is unavailable")
	}
	if err := validateIRAttribution(actor, action, target, data, attribution); err != nil {
		return Event{}, err
	}
	if err := lockProviderStream(ctx, q); err != nil {
		return Event{}, fmt.Errorf("lock provider audit chain: %w", err)
	}
	return providerAppendLockedWith(
		ctx,
		q,
		actor,
		action,
		target,
		data,
		func(event Event) error {
			bound := attribution
			bound.EventRef = event.Hash
			bound.TS = event.CreatedAt
			if err := sidecar.AppendIRStageTx(ctx, q, event, bound); err != nil {
				return fmt.Errorf("append encrypted IR attribution: %w", err)
			}
			return nil
		},
	)
}

func providerAppendLockedWith(
	ctx context.Context,
	q tenancy.Querier,
	actor, action, target string,
	data map[string]any,
	afterInsert func(Event) error,
) (Event, error) {
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
		// AUD-02: application-stamped so created_at is covered by the hash chain.
		CreatedAt: auditNow(),
	}
	// AUD-03: see tenantAppendLocked — hash the exact bytes stored in
	// data_canonical, with the jsonb data column as the CHECK-bound mirror.
	canonical, err := canonicalAuditData(data)
	if err != nil {
		return Event{}, err
	}
	ev.canonicalData = canonical
	ev.Hash = chainEventHash(providerStream, ev.Seq, actor, action, target, ev.CreatedAt.UnixMicro(), canonical, ev.PrevHash)
	if _, err := q.Exec(ctx,
		`INSERT INTO provider_audit_events (seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)`,
		ev.Seq, actor, action, target, string(canonical), ev.PrevHash, ev.Hash, ev.CreatedAt, string(canonical),
	); err != nil {
		return Event{}, fmt.Errorf("insert provider audit event: %w", err)
	}
	if afterInsert != nil {
		if err := afterInsert(ev); err != nil {
			return Event{}, err
		}
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

// LockTenantStream acquires the canonical transaction-scoped tenant audit
// lock. Mutations that must lock tenant rows before appending their audit event
// use this seam first so every caller keeps the same audit-lock → row-lock
// order.
func LockTenantStream(ctx context.Context, q tenancy.Querier, tenantID string) error {
	return lockTenantStream(ctx, q, tenantID)
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
		`SELECT head_seq, head_hash, pruned_seq, pruned_hash, head_sig
		   FROM public.audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&head.HeadSeq, &head.HeadHash, &head.PrunedSeq, &head.PrunedHash, &head.HeadSig)
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
		// AUD-01: this is the anchor's genesis for a tenant whose rows an older
		// binary appended before the head metadata existed — sign the inferred
		// head so a later verify under a configured anchor accepts it. The app
		// role keeps INSERT (not UPDATE) on audit_stream_heads, so this first-time
		// insert carries the signature directly.
		sig, serr := signTenantHead(tenantID, head.HeadSeq, head.HeadHash)
		if serr != nil {
			return streamHead{}, serr
		}
		tag, err := q.Exec(
			ctx,
			`INSERT INTO public.audit_stream_heads
			    (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash, head_sig, updated_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6, now())
			 ON CONFLICT (tenant_id) DO NOTHING`,
			tenantID,
			head.HeadSeq,
			head.HeadHash,
			head.PrunedSeq,
			head.PrunedHash,
			sig,
		)
		if err != nil {
			return streamHead{}, fmt.Errorf("initialize tenant audit stream head: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return streamHead{}, fmt.Errorf("initialize tenant audit stream head: concurrent state change")
		}
		head.HeadSig = sig
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
	sig, err := updateTenantHead(ctx, q, tenantID, head, bounds.LastSeq, bounds.LastHash)
	if err != nil {
		return streamHead{}, err
	}
	head.HeadSeq, head.HeadHash, head.HeadSig = bounds.LastSeq, bounds.LastHash, sig
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
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical
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
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical
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
	if _, err := updateTenantHead(ctx, q, tenantID, head, ev.Seq, ev.Hash); err != nil {
		return fmt.Errorf("advance tenant audit stream head: %w", err)
	}
	return nil
}

// updateTenantHead advances the durable head through the AUD-04 SECURITY DEFINER
// function and returns the Ed25519 signature it stored over the new head (nil
// when head anchoring is not configured). AUD-01: the signature is computed HERE,
// in the control plane, over (tenant_id, head_seq, head_hash); only the resulting
// bytes are passed into the definer, so the signing key never reaches the
// database or the SQL function (docs/guardrails.md G7-7). The definer still
// enforces monotonic, forward-only, caller-GUC-free head advancement (AUD-04).
func updateTenantHead(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	old streamHead,
	newSeq int64,
	newHash string,
) ([]byte, error) {
	sig, err := signTenantHead(tenantID, newSeq, newHash)
	if err != nil {
		return nil, err
	}
	var rows int64
	if err := q.QueryRow(
		ctx,
		`SELECT public.probectl_advance_tenant_audit_head(
		     $1::uuid, $2, $3, $4, $5, $6, $7, $8)`,
		tenantID,
		newSeq,
		newHash,
		old.PrunedSeq,
		old.PrunedHash,
		old.HeadSeq,
		old.HeadHash,
		sig,
	).Scan(&rows); err != nil {
		return nil, fmt.Errorf("update tenant audit stream head: %w", err)
	}
	if rows != 1 {
		return nil, fmt.Errorf("update tenant audit stream head: non-monotonic state transition")
	}
	return sig, nil
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
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical
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
	if err := verifyReachedHead("tenant", head, lastSeq, lastHash); err != nil {
		return err
	}
	// AUD-01: the hash-chain check above is self-contained in the database, so a
	// writer that rewrites a row, recomputes the chain, and updates
	// audit_stream_heads passes it. The out-of-trust-domain Ed25519 signature
	// over the durable head is the check that same writer cannot forge.
	return verifyTenantHeadAnchor(s.Tenant.String(), head)
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
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at, data_canonical
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
			createdAt              time.Time
			canonical              []byte
		)
		if err := rows.Scan(&seq, &actor, &action, &target, &dataBytes, &storedPrev, &storedHash, &createdAt, &canonical); err != nil {
			return 0, "", err
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
		// AUD-03: hash the EXACT canonical bytes the append side stored, so a
		// payload with an integer above 2^53 verifies cleanly (a jsonb-decode +
		// re-marshal would round-trip it through float64 and corrupt it). Rows
		// written before the data_canonical column fall back to the pre-AUD-03
		// recompute so their honest chains stay byte-identical.
		var want string
		if len(canonical) > 0 {
			want = chainEventHash(streamKey, seq, actor, action, target, createdAt.UnixMicro(), canonical, storedPrev)
		} else {
			var data map[string]any
			if err := json.Unmarshal(dataBytes, &data); err != nil {
				return 0, "", fmt.Errorf("seq %d: decode data: %w", seq, err)
			}
			var err error
			want, err = computeHash(streamKey, seq, actor, action, target, createdAt.UnixMicro(), data, storedPrev)
			if err != nil {
				return 0, "", err
			}
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
