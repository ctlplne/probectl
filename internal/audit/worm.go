// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	selfmetrics "github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// WORM export (U-041). The audit chains are tamper-EVIDENT in Postgres (RLS
// without UPDATE/DELETE policies + hash chaining) but a database owner can
// still purge rows. This exporter closes that hole: the provider stream —
// the chain that records break-glass and survives tenant erasure — is
// periodically exported as Ed25519-SIGNED, append-only segments into object
// storage. Pointing the store at a bucket with OBJECT LOCK (S3/MinIO
// compliance mode; documented in docs/hardening.md) makes the copies WORM:
// the DB owner can purge Postgres, but the signed history already left.
//
// VerifyWORMChain is the companion job: it re-verifies every segment
// signature, the hash chain ACROSS segments, and seq continuity — a purge or
// gap surfaces as a loud error (the alert hook).

const (
	// wormPrefix is the object-key namespace for provider-stream segments.
	wormPrefix = "worm/audit/provider/"

	// Stored WORM objects are durable but still untrusted input during restart,
	// retention, and explicit verification. These ceilings are enforced while
	// reading, before signature verification or JSON decoding can allocate from
	// an attacker-controlled object size.
	maxWORMPublicKeyBytes int64 = 4 << 10
	maxWORMSegmentBytes   int64 = 4 << 20
	maxWORMSignatureBytes int64 = crypto.Ed25519SignatureSize

	// One complete segment consumes two artifacts (.json + .sig). This ceiling
	// therefore retains up to 100,000 signed segments / 100 million events while
	// preventing a hostile or accidentally shared object directory from forcing
	// unbounded key allocation. Exceeding it fails verification and retention
	// closed; operators can archive/rotate the WORM destination deliberately.
	maxWORMSegmentArtifacts = 200_000

	// A cycle may catch up more than one page, but it must remain bounded so a
	// continuously growing provider stream cannot monopolize the singleton.
	// Eight full pages move 8,000 events per interval; a read-only ninth probe
	// distinguishes exact-boundary completion from remaining lag.
	maxWORMExportPagesPerCycle = 8
)

// WormSegment is one exported, signed slice of the provider audit chain.
type WormSegment struct {
	FormatVersion int       `json:"format_version"`
	Stream        string    `json:"stream"` // "provider"
	FromSeq       int64     `json:"from_seq"`
	ToSeq         int64     `json:"to_seq"`
	ExportedAt    time.Time `json:"exported_at"`
	Events        []Event   `json:"events"`
}

// WormSource pages provider-stream events after a seq (the export cursor).
type WormSource func(ctx context.Context, afterSeq int64, limit int) ([]Event, error)

// wormExportCursor is the last complete, signed WORM chain position verified
// at the start of a catch-up cycle or advanced by a successfully written page.
// It is deliberately cycle-local: every public ExportOnce call and every new
// run cycle still derives its initial cursor from the durable signed objects.
type wormExportCursor struct {
	lastSeq          int64
	anchorHash       string
	publicKeyEnsured bool
}

// WormExporter writes signed segments and verifies the exported chain.
type WormExporter struct {
	source  WormSource
	objects objectstore.Store
	privPEM []byte
	pubPEM  []byte
	log     *slog.Logger

	gaps            atomic.Uint64 // chain-verification failures observed (never silent)
	lastSuccessUnix atomic.Int64
	lagging         atomic.Int64
	metrics         wormExporterMetrics
}

type wormExporterMetrics struct {
	exportFailures    *selfmetrics.Counter
	chainFailures     *selfmetrics.Counter
	signatureFailures *selfmetrics.Counter
	exportedEvents    *selfmetrics.Counter
	laggedCycles      *selfmetrics.Counter
}

// NewWormExporter wires the exporter with an EXPLICIT, persisted signing key.
// KEYS-004: the per-boot ephemeral-key fallback is gone from this constructor —
// a missing key is an error, so production can never silently mint a key that
// breaks cross-restart chain verification. Tests that genuinely want a throwaway
// key use NewWormExporterEphemeralForTest.
func NewWormExporter(source WormSource, objects objectstore.Store, privPEM, pubPEM []byte, log *slog.Logger) (*WormExporter, error) {
	if source == nil || objects == nil {
		return nil, fmt.Errorf("audit: worm export requires a source and an object store")
	}
	if len(privPEM) == 0 || len(pubPEM) == 0 {
		return nil, fmt.Errorf("audit: worm export requires a persisted Ed25519 signing key " +
			"(resolve it via ResolveWormSigningKey; refusing to mint an ephemeral per-boot key — KEYS-004)")
	}
	if int64(len(pubPEM)) > maxWORMPublicKeyBytes {
		return nil, fmt.Errorf("audit: WORM signing public key exceeds %d-byte limit", maxWORMPublicKeyBytes)
	}
	if log == nil {
		log = slog.Default()
	}
	return &WormExporter{source: source, objects: objects, privPEM: privPEM, pubPEM: pubPEM, log: log}, nil
}

// NewWormExporterEphemeralForTest mints a throwaway signing key — TEST/DEV ONLY.
// Never wire this into a production path: an ephemeral per-boot key breaks
// cross-restart verification of the tamper-evident chain (KEYS-004).
func NewWormExporterEphemeralForTest(source WormSource, objects objectstore.Store, log *slog.Logger) (*WormExporter, error) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		return nil, fmt.Errorf("audit: worm signing key: %w", err)
	}
	return NewWormExporter(source, objects, priv, pub, log)
}

// NewWormExporterPG is the production wiring over the provider audit table.
// The signing key (privPEM/pubPEM) is resolved by the caller via
// ResolveWormSigningKey (KEYS-002 / D2) and MUST be persisted — empty PEMs are
// REFUSED (KEYS-004), never auto-minted.
func NewWormExporterPG(pool *pgxpool.Pool, objects objectstore.Store, privPEM, pubPEM []byte, log *slog.Logger) (*WormExporter, error) {
	return NewWormExporter(func(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
		return ListProvider(ctx, pool, afterSeq, limit)
	}, objects, privPEM, pubPEM, log)
}

// WithMetrics exposes aggregate WORM export health at /metrics. These series
// carry no tenant labels or audit payloads; they only say whether the provider
// chain exporter is completing its export+verify loop.
func (w *WormExporter) WithMetrics(reg *selfmetrics.Registry) *WormExporter {
	if reg == nil {
		return w
	}
	w.metrics.exportFailures = reg.Counter("probectl_audit_worm_export_failures_total",
		"Audit WORM export attempts that failed before a successful export+verify cycle.")
	w.metrics.chainFailures = reg.Counter("probectl_audit_worm_chain_failures_total",
		"Audit WORM verification failures across signed provider-chain segments.")
	w.metrics.signatureFailures = reg.Counter("probectl_audit_worm_signature_failures_total",
		"Audit WORM segment signature verification failures.")
	w.metrics.exportedEvents = reg.Counter("probectl_audit_worm_exported_events_total",
		"Provider audit events durably exported and chain-verified in WORM cycles.")
	w.metrics.laggedCycles = reg.Counter("probectl_audit_worm_lagged_cycles_total",
		"Audit WORM cycles that reached the bounded catch-up limit with source events still pending.")
	reg.Gauge("probectl_audit_worm_last_success_unix_seconds",
		"Unix timestamp of the last successful audit WORM export+verify cycle; 0 until the first success.",
		func() float64 { return float64(w.lastSuccessUnix.Load()) })
	reg.Gauge("probectl_audit_worm_lagging",
		"Whether the last verified audit WORM cycle left provider events pending after bounded catch-up (1=yes, 0=no).",
		func() float64 { return float64(w.lagging.Load()) })
	return w
}

// ResolveWormSigningKey resolves the Ed25519 key that signs WORM segments
// (KEYS-002 / decision D2). Precedence: an explicit base64-PEM env key wins
// (KMS / secret-manager injection); else a key FILE is loaded — generated +
// persisted on first boot like the envelope KEK, so it is STABLE across
// restarts; else, when WORM export is enabled but no key is configured, it
// FAILS CLOSED. A control-plane restart must NOT silently mint a new key:
// that would break cross-restart verification of the tamper-evident chain
// (the entire point of the signed export). regulated only enriches the error.
func ResolveWormSigningKey(envKeyB64, keyFile string, regulated bool) (privPEM, pubPEM []byte, generated bool, err error) {
	switch {
	case strings.TrimSpace(envKeyB64) != "":
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(envKeyB64))
		if derr != nil {
			return nil, nil, false, fmt.Errorf("audit: PROBECTL_WORM_SIGNING_KEY is not valid base64: %w", derr)
		}
		pub, perr := crypto.PublicPEMFromPrivate(raw)
		if perr != nil {
			return nil, nil, false, fmt.Errorf("audit: PROBECTL_WORM_SIGNING_KEY is not a valid Ed25519 private-key PEM: %w", perr)
		}
		return raw, pub, false, nil
	case keyFile != "":
		return crypto.LoadOrGenerateEd25519KeyFile(keyFile)
	default:
		reg := ""
		if regulated {
			reg = " (and at-rest encryption is required)"
		}
		return nil, nil, false, fmt.Errorf(
			"audit: WORM export is enabled but no signing key is configured%s — set PROBECTL_WORM_SIGNING_KEY_FILE "+
				"(generated + persisted on first boot) or PROBECTL_WORM_SIGNING_KEY; refusing to mint an ephemeral "+
				"per-boot key, which would break cross-restart chain verification (KEYS-002)", reg)
	}
}

// Run performs one bounded multi-page catch-up and full-chain verification on
// each interval, until ctx is canceled. A cycle with known remaining source lag
// is signaled immediately and is never recorded as successful.
func (w *WormExporter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		w.runCycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *WormExporter) runCycle(ctx context.Context) {
	exported, lagging, err := w.exportCatchUp(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.recordExportFailure()
			w.log.Error("audit worm export failed", "error", err.Error())
		}
		return
	}
	// Surface known lag before the potentially long full-history verification.
	// Verification still gates exported-event accounting and cycle success.
	if lagging {
		w.recordLag()
	}
	if err := w.VerifyWORMChain(ctx); err != nil {
		if ctx.Err() == nil {
			failures := w.recordVerifyFailure(err)
			w.log.Error("AUDIT WORM CHAIN VERIFICATION FAILED — possible purge or tampering",
				"error", err.Error(), "failures_total", failures)
		}
		return
	}
	if w.metrics.exportedEvents != nil && exported > 0 {
		w.metrics.exportedEvents.Add(uint64(exported))
	}
	if lagging {
		w.log.Error("AUDIT WORM EXPORT LAGGING — bounded catch-up left provider events pending",
			"exported_events", exported,
			"max_pages", maxWORMExportPagesPerCycle,
			"page_size", MaxExportPageSize)
		return
	}
	if ctx.Err() == nil {
		w.recordSuccess()
	}
}

// exportCatchUp writes at most maxWORMExportPagesPerCycle pages. When all data
// pages were full, a final read-only one-event probe reports whether lag remains
// without creating a ninth segment.
func (w *WormExporter) exportCatchUp(ctx context.Context) (exported int, lagging bool, err error) {
	last, anchorHash, repaired, err := w.lastExportedHead(ctx)
	if err != nil {
		return 0, false, err
	}
	exported = repaired
	cursor := wormExportCursor{lastSeq: last, anchorHash: anchorHash}
	for page := 0; page < maxWORMExportPagesPerCycle; page++ {
		var n int
		cursor, n, err = w.exportPage(ctx, cursor)
		exported += n
		if err != nil {
			return exported, false, err
		}
		if n == 0 {
			return exported, false, nil
		}
	}
	lagging, err = w.hasPendingSource(ctx, cursor)
	return exported, lagging, err
}

func (w *WormExporter) hasPendingSource(ctx context.Context, cursor wormExportCursor) (bool, error) {
	events, err := w.source(ctx, cursor.lastSeq, 1)
	if err != nil {
		return false, err
	}
	if len(events) > 1 {
		return false, fmt.Errorf("audit: WORM source returned %d events to one-event lag probe", len(events))
	}
	if err := validateProviderSource(events, cursor.lastSeq, cursor.anchorHash); err != nil {
		return false, err
	}
	return len(events) == 1, nil
}

func (w *WormExporter) recordSuccess() {
	w.lagging.Store(0)
	w.lastSuccessUnix.Store(time.Now().Unix())
}

func (w *WormExporter) recordLag() {
	w.lagging.Store(1)
	if w.metrics.laggedCycles != nil {
		w.metrics.laggedCycles.Inc()
	}
}

func (w *WormExporter) recordExportFailure() {
	if w.metrics.exportFailures != nil {
		w.metrics.exportFailures.Inc()
	}
}

func (w *WormExporter) recordVerifyFailure(err error) uint64 {
	total := w.gaps.Add(1)
	if w.metrics.chainFailures != nil {
		w.metrics.chainFailures.Inc()
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "signature") && w.metrics.signatureFailures != nil {
		w.metrics.signatureFailures.Inc()
	}
	return total
}

// ExportOnce exports every provider-stream event past the last exported seq
// as one signed segment (no-op when nothing is new). Returns the number of
// events exported.
func (w *WormExporter) ExportOnce(ctx context.Context) (int, error) {
	last, anchorHash, repaired, err := w.lastExportedHead(ctx)
	if err != nil {
		return 0, err
	}
	_, n, err := w.exportPage(ctx, wormExportCursor{lastSeq: last, anchorHash: anchorHash})
	return repaired + n, err
}

// exportPage validates and writes one page after a cursor that was derived from
// the signed chain or a page this same catch-up cycle just durably completed.
// The caller may carry the returned cursor to the next page without rescanning
// the complete object history. A write failure never advances the cursor.
func (w *WormExporter) exportPage(
	ctx context.Context,
	cursor wormExportCursor,
) (wormExportCursor, int, error) {
	events, err := w.source(ctx, cursor.lastSeq, MaxExportPageSize)
	if err != nil {
		return cursor, 0, err
	}
	if len(events) > MaxExportPageSize {
		return cursor, 0, fmt.Errorf(
			"audit: WORM source returned %d events, exceeds %d-event limit",
			len(events),
			MaxExportPageSize,
		)
	}
	// The source is still mutable PostgreSQL state. Prove its canonical hash
	// chain against the last SIGNED WORM event before projecting personal fields
	// away or writing any object. Otherwise a database owner could alter an
	// unexported action, retain its stale hash, and have that inconsistency signed
	// as durable evidence.
	if err := validateProviderSource(events, cursor.lastSeq, cursor.anchorHash); err != nil {
		return cursor, 0, err
	}
	// Make the verification key durable only after source validation. A
	// vulnerable older export may already have a valid segment + signature but
	// no key object; lastExportedHead verifies that segment with the configured
	// key, then this repairs only the missing companion object. Invalid source
	// data must not create even this companion object.
	if !cursor.publicKeyEnsured {
		if err := w.ensurePublicKey(ctx); err != nil {
			return cursor, 0, err
		}
		cursor.publicKeyEnsured = true
	}
	if len(events) == 0 {
		return cursor, 0, nil
	}
	seg := WormSegment{
		FormatVersion: 1, Stream: "provider",
		FromSeq: events[0].Seq, ToSeq: events[len(events)-1].Seq,
		ExportedAt: time.Now().UTC(), Events: minimizeEventsForWORM(events),
	}
	raw, err := json.Marshal(seg)
	if err != nil {
		return cursor, 0, err
	}
	if int64(len(raw)) > maxWORMSegmentBytes {
		return cursor, 0, fmt.Errorf("audit: WORM segment exceeds %d-byte limit", maxWORMSegmentBytes)
	}
	sig, err := crypto.SignEd25519(w.privPEM, raw)
	if err != nil {
		return cursor, 0, fmt.Errorf("audit: sign segment: %w", err)
	}
	key := fmt.Sprintf("%ssegment-%012d-%012d.json", wormPrefix, seg.FromSeq, seg.ToSeq)
	if err := w.objects.Put(ctx, key, "application/json", raw); err != nil {
		return cursor, 0, fmt.Errorf("audit: put segment: %w", err)
	}
	if err := w.objects.Put(ctx, key+".sig", "application/octet-stream", sig); err != nil {
		return cursor, 0, fmt.Errorf("audit: put signature: %w", err)
	}
	w.log.Info("audit worm segment exported", "from_seq", seg.FromSeq, "to_seq", seg.ToSeq, "events", len(events))
	cursor.lastSeq = events[len(events)-1].Seq
	cursor.anchorHash = events[len(events)-1].Hash
	return cursor, len(events), nil
}

func validateProviderSource(events []Event, lastSeq int64, anchorHash string) error {
	wantSeq := lastSeq + 1
	prevHash := anchorHash
	for i, ev := range events {
		if ev.Seq != wantSeq {
			return fmt.Errorf(
				"audit: WORM source sequence invalid at page index %d: want %d, got %d",
				i, wantSeq, ev.Seq,
			)
		}
		if ev.PrevHash != prevHash {
			return fmt.Errorf("audit: WORM source previous hash invalid at seq %d", ev.Seq)
		}
		wantHash, err := computeHash(
			providerStream,
			ev.Seq,
			ev.Actor,
			ev.Action,
			ev.Target,
			ev.Data,
			ev.PrevHash,
		)
		if err != nil {
			return fmt.Errorf("audit: canonicalize WORM source event %d: %w", ev.Seq, err)
		}
		if ev.Hash != wantHash {
			return fmt.Errorf("audit: WORM source canonical hash invalid at seq %d", ev.Seq)
		}
		prevHash = ev.Hash
		wantSeq++
	}
	return nil
}

func (w *WormExporter) ensurePublicKey(ctx context.Context) error {
	const key = wormPrefix + "signing.pub"
	pub, err := w.objects.GetLimited(ctx, key, maxWORMPublicKeyBytes)
	switch {
	case err == nil:
		if !bytes.Equal(pub.Data, w.pubPEM) {
			return errors.New("audit WORM signing public key does not match configured key")
		}
		return nil
	case !errors.Is(err, objectstore.ErrNotFound):
		return fmt.Errorf("audit WORM signing public key unreadable: %w", err)
	default:
		if err := w.objects.Put(ctx, key, "application/x-pem-file", w.pubPEM); err != nil {
			return fmt.Errorf("audit: put public key: %w", err)
		}
		return nil
	}
}

// ExportedWatermark returns the highest provider-audit seq already present in
// signed WORM segments. The retention runner uses this as a durable export
// receipt; if the object store cannot be read, pruning fails closed.
func (w *WormExporter) ExportedWatermark(ctx context.Context) (int64, error) {
	if w == nil {
		return 0, nil
	}
	last, _, err := w.scanWORMChain(ctx, false)
	return last, err
}

// ReconcileProviderHead verifies the complete signed WORM chain and reconciles
// its terminal sequence/hash with the durable SQL head before provider writes
// are admitted at startup. This closes the one legacy state SQL cannot infer:
// a pre-0075 full prune left no event row or head, while signed WORM still
// proves the true terminal chain position.
//
// Reconciliation only creates a fully-pruned anchor when SQL is completely
// empty. Any non-empty disagreement, WORM rewind behind a SQL prune anchor, or
// hash mismatch fails closed; it is never "repaired" by guessing.
func (w *WormExporter) ReconcileProviderHead(
	ctx context.Context,
	pool *pgxpool.Pool,
) error {
	if w == nil || pool == nil {
		return fmt.Errorf("audit: reconcile provider WORM head requires exporter and database")
	}
	// A legacy export can have every segment and signature durably written but
	// be missing only the signing.pub companion. Verify that complete chain
	// strictly with the configured key before repairing the public-key object.
	// In particular, allowMissingPublicKey does not make an unsigned tail
	// acceptable.
	if _, _, err := w.scanWORMChainWithOptions(ctx, false, true, nil); err != nil {
		return fmt.Errorf("verify provider WORM artifacts before public-key repair: %w", err)
	}
	if err := w.ensurePublicKey(ctx); err != nil {
		return fmt.Errorf("repair provider WORM public key for SQL reconciliation: %w", err)
	}
	wormSeq, wormHash, err := w.scanWORMChain(ctx, false)
	if err != nil {
		return fmt.Errorf("verify provider WORM head for SQL reconciliation: %w", err)
	}
	return tenancy.InProvider(
		ctx,
		pool,
		func(ctx context.Context, q tenancy.Querier) error {
			if err := lockProviderStream(ctx, q); err != nil {
				return fmt.Errorf("lock provider audit reconciliation: %w", err)
			}
			head, err := ensureProviderStreamHead(ctx, q)
			if err != nil {
				return fmt.Errorf("read provider audit reconciliation head: %w", err)
			}
			if head.HeadSeq > 0 {
				if err := providerVerifyFromLocked(ctx, q, head, 0); err != nil {
					return fmt.Errorf(
						"verify retained provider SQL before WORM reconciliation: %w",
						err,
					)
				}
			}
			if wormSeq == 0 {
				if head.PrunedSeq > 0 {
					return fmt.Errorf(
						"provider WORM chain is empty behind SQL prune anchor %d",
						head.PrunedSeq,
					)
				}
				return nil
			}
			if head.HeadSeq == 0 {
				tag, err := q.Exec(
					ctx,
					`INSERT INTO provider_audit_stream_head AS heads
					    (singleton, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
					 VALUES (true, $1, $2, $1, $2, now())
					 ON CONFLICT (singleton) DO UPDATE
					        SET head_seq = EXCLUDED.head_seq,
					            head_hash = EXCLUDED.head_hash,
					            pruned_seq = EXCLUDED.pruned_seq,
					            pruned_hash = EXCLUDED.pruned_hash,
					            updated_at = now()
					      WHERE heads.head_seq = 0
					        AND heads.head_hash = ''
					        AND heads.pruned_seq = 0
					        AND heads.pruned_hash = ''`,
					wormSeq,
					wormHash,
				)
				if err != nil {
					return fmt.Errorf("restore provider SQL head from verified WORM: %w", err)
				}
				if tag.RowsAffected() != 1 {
					return fmt.Errorf("restore provider SQL head from verified WORM: concurrent state change")
				}
				if _, err := providerAppendLocked(
					ctx,
					q,
					"system:audit-retention",
					RetentionAnchorRecoveredAction,
					"provider",
					map[string]any{
						"source":             "verified_worm",
						"recovered_head_seq": wormSeq,
					},
				); err != nil {
					return fmt.Errorf("append provider WORM anchor recovery receipt: %w", err)
				}
				return nil
			}
			if wormSeq < head.PrunedSeq {
				return fmt.Errorf(
					"provider WORM head %d is behind SQL prune anchor %d",
					wormSeq,
					head.PrunedSeq,
				)
			}
			if wormSeq > head.HeadSeq {
				return fmt.Errorf(
					"provider WORM head %d is above SQL durable head %d with retained SQL state",
					wormSeq,
					head.HeadSeq,
				)
			}

			sqlHash := head.PrunedHash
			if wormSeq != head.PrunedSeq {
				if err := q.QueryRow(
					ctx,
					`SELECT hash FROM provider_audit_events WHERE seq = $1`,
					wormSeq,
				).Scan(&sqlHash); err != nil {
					return fmt.Errorf(
						"read provider SQL hash at verified WORM seq %d: %w",
						wormSeq,
						err,
					)
				}
			}
			if sqlHash != wormHash {
				return fmt.Errorf(
					"provider WORM/SQL hash mismatch at seq %d",
					wormSeq,
				)
			}
			return nil
		},
	)
}

// lastExportedHead derives the export cursor and canonical hash anchor from the
// verified segment prefix. A final JSON whose signature write failed is
// repaired in place only after it matches the exact live canonical source
// prefix; its JSON is never rewritten. The returned count makes that completed
// export visible to callers and metrics. Any other verification failure
// remains fatal.
func (w *WormExporter) lastExportedHead(ctx context.Context) (int64, string, int, error) {
	var repaired int
	last, hash, err := w.scanWORMChainWithOptions(ctx, true, true, &repaired)
	return last, hash, repaired, err
}

// scanWORMChain verifies every segment from sequence one and returns the last
// sequence whose segment, signature, key, and hash-chain links are durable.
// allowIncompleteTail is used only by export entry points so a failed
// signature write can be validated against its live source prefix and repaired.
// Retention and explicit verification reject that same partial tail.
func (w *WormExporter) scanWORMChain(ctx context.Context, allowIncompleteTail bool) (int64, string, error) {
	return w.scanWORMChainWithOptions(ctx, allowIncompleteTail, allowIncompleteTail, nil)
}

// scanWORMChainWithOptions separates the two legacy recovery allowances:
// allowIncompleteTail permits only export entry points to repair a final
// segment whose signature companion was not written, while
// allowMissingPublicKey permits a caller to verify complete signed segments
// with the configured key before repairing a missing signing.pub companion.
func (w *WormExporter) scanWORMChainWithOptions(
	ctx context.Context,
	allowIncompleteTail bool,
	allowMissingPublicKey bool,
	repairedEvents *int,
) (int64, string, error) {
	if repairedEvents != nil {
		*repairedEvents = 0
	}
	keys, err := w.objects.ListLimited(ctx, wormPrefix+"segment-", maxWORMSegmentArtifacts)
	if err != nil {
		if errors.Is(err, objectstore.ErrTooMany) {
			return 0, "", fmt.Errorf(
				"audit WORM aggregate segment artifact limit %d exceeded: %w",
				maxWORMSegmentArtifacts,
				err,
			)
		}
		return 0, "", err
	}
	if len(keys) > maxWORMSegmentArtifacts {
		return 0, "", fmt.Errorf(
			"audit WORM aggregate segment artifact limit %d exceeded: %w",
			maxWORMSegmentArtifacts,
			objectstore.ErrTooMany,
		)
	}
	segKeys, incompleteTail, err := inventoryWORMSegmentArtifacts(keys, allowIncompleteTail)
	if err != nil {
		return 0, "", err
	}
	if len(segKeys) == 0 {
		return 0, genesis, nil
	}

	pub, err := w.objects.GetLimited(ctx, wormPrefix+"signing.pub", maxWORMPublicKeyBytes)
	if err != nil {
		if !allowMissingPublicKey || !errors.Is(err, objectstore.ErrNotFound) {
			return 0, "", fmt.Errorf("audit WORM signing public key unreadable: %w", err)
		}
		// Recovery may inspect a legacy state with no public-key object, but
		// every existing signature is still verified below with the configured
		// durable key before ensurePublicKey repairs that object.
	} else if !bytes.Equal(pub.Data, w.pubPEM) {
		return 0, "", fmt.Errorf("audit WORM signing public key does not match configured key")
	}

	wantSeq := int64(1)
	prevHash := genesis // the chain root (audit.go)
	var last int64
	for _, key := range segKeys {
		var keyFrom, keyTo int64
		base := strings.TrimSuffix(strings.TrimPrefix(key, wormPrefix), ".json")
		if n, err := fmt.Sscanf(base, "segment-%d-%d", &keyFrom, &keyTo); err != nil || n != 2 ||
			key != fmt.Sprintf("%ssegment-%012d-%012d.json", wormPrefix, keyFrom, keyTo) {
			return 0, "", fmt.Errorf("invalid audit WORM segment key %q", key)
		}
		if key == incompleteTail {
			if keyFrom != wantSeq {
				return 0, "", fmt.Errorf(
					"incomplete audit WORM tail %s starts at %d, want %d",
					key,
					keyFrom,
					wantSeq,
				)
			}
			repairedLast, repairedHash, repaired, err := w.repairIncompleteWORMTail(
				ctx,
				key,
				keyFrom,
				keyTo,
				last,
				prevHash,
			)
			if err != nil {
				return 0, "", err
			}
			if repairedEvents != nil {
				*repairedEvents = repaired
			}
			return repairedLast, repairedHash, nil
		}

		obj, err := w.objects.GetLimited(ctx, key, maxWORMSegmentBytes)
		if err != nil {
			return 0, "", fmt.Errorf("segment %s unreadable: %w", key, err)
		}
		sig, err := w.objects.GetLimited(ctx, key+".sig", maxWORMSignatureBytes)
		if err != nil {
			return 0, "", fmt.Errorf("segment %s signature missing: %w", key, err)
		}
		ok, err := crypto.VerifyEd25519(w.pubPEM, obj.Data, sig.Data)
		if err != nil || !ok {
			return 0, "", fmt.Errorf("segment %s signature INVALID (tampered?): %v", key, err)
		}

		var seg WormSegment
		if err := json.Unmarshal(obj.Data, &seg); err != nil {
			return 0, "", fmt.Errorf("segment %s undecodable: %w", key, err)
		}
		if seg.FormatVersion != 1 || seg.Stream != "provider" {
			return 0, "", fmt.Errorf("segment %s has invalid format or stream", key)
		}
		if len(seg.Events) > MaxExportPageSize {
			return 0, "", fmt.Errorf("segment %s exceeds %d-event limit", key, MaxExportPageSize)
		}
		if len(seg.Events) == 0 || seg.FromSeq != keyFrom || seg.ToSeq != keyTo ||
			seg.Events[0].Seq != seg.FromSeq || seg.Events[len(seg.Events)-1].Seq != seg.ToSeq {
			return 0, "", fmt.Errorf("segment %s sequence metadata INVALID", key)
		}
		for _, ev := range seg.Events {
			if ev.Seq != wantSeq {
				return 0, "", fmt.Errorf("seq GAP at %s: want %d, got %d (events purged?)", key, wantSeq, ev.Seq)
			}
			if ev.PrevHash != prevHash {
				return 0, "", fmt.Errorf("hash chain BROKEN at seq %d in %s", ev.Seq, key)
			}
			prevHash = ev.Hash
			last = ev.Seq
			wantSeq++
		}
	}
	return last, prevHash, nil
}

// repairIncompleteWORMTail completes the only recoverable half-write: the
// exporter durably wrote a final canonical JSON segment but its signature Put
// failed. The JSON object is never rewritten. Before signing its exact bytes,
// the method proves that its bounded, canonical event projection is precisely
// the next live provider-source slice anchored to the already-signed prefix.
// Source growth is harmless: only the stored prefix is compared and signed;
// later rows are exported by the normal page path.
func (w *WormExporter) repairIncompleteWORMTail(
	ctx context.Context,
	key string,
	keyFrom int64,
	keyTo int64,
	lastSeq int64,
	anchorHash string,
) (int64, string, int, error) {
	obj, err := w.objects.GetLimited(ctx, key, maxWORMSegmentBytes)
	if err != nil {
		return 0, "", 0, fmt.Errorf("incomplete segment %s unreadable: %w", key, err)
	}
	if obj.ContentType != "application/json" {
		return 0, "", 0, fmt.Errorf(
			"incomplete segment %s has invalid content type %q",
			key,
			obj.ContentType,
		)
	}

	var seg WormSegment
	if err := json.Unmarshal(obj.Data, &seg); err != nil {
		return 0, "", 0, fmt.Errorf("incomplete segment %s undecodable: %w", key, err)
	}
	canonical, err := json.Marshal(seg)
	if err != nil {
		return 0, "", 0, fmt.Errorf("canonicalize incomplete segment %s: %w", key, err)
	}
	if !bytes.Equal(obj.Data, canonical) {
		return 0, "", 0, fmt.Errorf("incomplete segment %s is not canonical JSON", key)
	}
	if seg.FormatVersion != 1 || seg.Stream != "provider" || seg.ExportedAt.IsZero() {
		return 0, "", 0, fmt.Errorf("incomplete segment %s has invalid format, stream, or timestamp", key)
	}
	if len(seg.Events) == 0 ||
		len(seg.Events) > MaxExportPageSize ||
		seg.FromSeq != keyFrom ||
		seg.ToSeq != keyTo ||
		seg.Events[0].Seq != keyFrom ||
		seg.Events[len(seg.Events)-1].Seq != keyTo ||
		keyTo-keyFrom+1 != int64(len(seg.Events)) {
		return 0, "", 0, fmt.Errorf("incomplete segment %s has invalid sequence metadata", key)
	}

	live, err := w.source(ctx, lastSeq, len(seg.Events))
	if err != nil {
		return 0, "", 0, fmt.Errorf("read live source for incomplete segment %s: %w", key, err)
	}
	if len(live) > len(seg.Events) {
		return 0, "", 0, fmt.Errorf(
			"audit: WORM source returned %d events for %d-event incomplete-tail comparison",
			len(live),
			len(seg.Events),
		)
	}
	if len(live) != len(seg.Events) {
		return 0, "", 0, fmt.Errorf(
			"incomplete segment %s diverges from live source: got %d events, want %d",
			key,
			len(live),
			len(seg.Events),
		)
	}
	if err := validateProviderSource(live, lastSeq, anchorHash); err != nil {
		return 0, "", 0, fmt.Errorf("validate live source for incomplete segment %s: %w", key, err)
	}
	expectedEvents, err := json.Marshal(minimizeEventsForWORM(live))
	if err != nil {
		return 0, "", 0, fmt.Errorf("canonicalize live source for incomplete segment %s: %w", key, err)
	}
	storedEvents, err := json.Marshal(seg.Events)
	if err != nil {
		return 0, "", 0, fmt.Errorf("canonicalize stored events for incomplete segment %s: %w", key, err)
	}
	if !bytes.Equal(storedEvents, expectedEvents) {
		return 0, "", 0, fmt.Errorf("incomplete segment %s diverges from live canonical source", key)
	}

	sig, err := crypto.SignEd25519(w.privPEM, obj.Data)
	if err != nil {
		return 0, "", 0, fmt.Errorf("audit: sign existing incomplete segment: %w", err)
	}
	if err := w.objects.Put(ctx, key+".sig", "application/octet-stream", sig); err != nil {
		return 0, "", 0, fmt.Errorf("audit: put existing incomplete segment signature: %w", err)
	}
	return keyTo, seg.Events[len(seg.Events)-1].Hash, len(seg.Events), nil
}

// inventoryWORMSegmentArtifacts parses the complete bounded segment listing
// before any chain position is trusted. Every canonical segment JSON must have
// exactly one canonical signature companion and vice versa. The sole
// exception is an export entry point's final JSON: if its signature Put failed,
// the exporter may validate and sign those exact existing bytes on retry.
// Strict verification and retention watermarks do not receive that allowance.
func inventoryWORMSegmentArtifacts(
	keys []string,
	allowIncompleteTail bool,
) (segmentKeys []string, incompleteTail string, err error) {
	type artifactPair struct {
		json bool
		sig  bool
	}

	pairs := make(map[string]artifactPair, len(keys)/2)
	for _, artifactKey := range keys {
		segmentKey, isSignature, err := canonicalWORMSegmentArtifactKey(artifactKey)
		if err != nil {
			return nil, "", err
		}
		pair := pairs[segmentKey]
		if isSignature {
			if pair.sig {
				return nil, "", fmt.Errorf(
					"duplicate signature for audit WORM segment %q",
					segmentKey,
				)
			}
			pair.sig = true
		} else {
			if pair.json {
				return nil, "", fmt.Errorf("duplicate audit WORM segment JSON %q", segmentKey)
			}
			pair.json = true
		}
		pairs[segmentKey] = pair
	}

	segmentKeys = make([]string, 0, len(pairs))
	for key := range pairs {
		segmentKeys = append(segmentKeys, key)
	}
	sort.Strings(segmentKeys) // zero-padded seqs sort chronologically

	for i, key := range segmentKeys {
		pair := pairs[key]
		if !pair.json {
			return nil, "", fmt.Errorf("orphan signature for audit WORM segment %q", key)
		}
		if pair.sig {
			continue
		}
		if !allowIncompleteTail || i != len(segmentKeys)-1 {
			return nil, "", fmt.Errorf("segment %s signature missing", key)
		}
		incompleteTail = key
	}
	return segmentKeys, incompleteTail, nil
}

func canonicalWORMSegmentArtifactKey(artifactKey string) (
	segmentKey string,
	isSignature bool,
	err error,
) {
	segmentKey = artifactKey
	if strings.HasSuffix(segmentKey, ".sig") {
		isSignature = true
		segmentKey = strings.TrimSuffix(segmentKey, ".sig")
	}

	var fromSeq, toSeq int64
	base := strings.TrimSuffix(strings.TrimPrefix(segmentKey, wormPrefix), ".json")
	if n, scanErr := fmt.Sscanf(base, "segment-%d-%d", &fromSeq, &toSeq); scanErr != nil ||
		n != 2 ||
		fromSeq <= 0 ||
		toSeq < fromSeq ||
		segmentKey != fmt.Sprintf("%ssegment-%012d-%012d.json", wormPrefix, fromSeq, toSeq) {
		return "", false, fmt.Errorf("invalid audit WORM segment artifact %q", artifactKey)
	}
	return segmentKey, isSignature, nil
}

// VerifyWORMChain re-verifies the exported history end to end: every
// segment's signature, seq continuity from 1 with no gaps or overlaps, and
// the hash chain across segment boundaries. Any failure is a loud error.
func (w *WormExporter) VerifyWORMChain(ctx context.Context) error {
	_, _, err := w.scanWORMChain(ctx, false)
	return err
}

// ListProvider returns provider-stream events with seq greater than afterSeq
// in ascending order (the WORM export cursor).
func ListProvider(ctx context.Context, pool *pgxpool.Pool, afterSeq int64, limit int) ([]Event, error) {
	if afterSeq < 0 {
		return nil, fmt.Errorf("list provider audit events: cursor must be non-negative")
	}
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin provider audit list: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockProviderStream(ctx, tx); err != nil {
		return nil, fmt.Errorf("lock provider audit list: %w", err)
	}
	head, err := ensureProviderStreamHead(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("read provider audit list head: %w", err)
	}
	if afterSeq < head.PrunedSeq {
		return nil, fmt.Errorf(
			"list provider audit events: WORM cursor %d is behind pruned anchor %d",
			afterSeq,
			head.PrunedSeq,
		)
	}
	if afterSeq > head.HeadSeq {
		return nil, fmt.Errorf(
			"list provider audit events: WORM cursor %d is above durable head %d",
			afterSeq,
			head.HeadSeq,
		)
	}
	rows, err := tx.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		   FROM provider_audit_events
		  WHERE seq > $1
		  ORDER BY seq
		  LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("list provider audit events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		ev, err := scanProviderEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if head.HeadSeq > afterSeq {
		if len(out) == 0 {
			return nil, fmt.Errorf(
				"list provider audit events: durable head %d has no row after WORM cursor %d",
				head.HeadSeq,
				afterSeq,
			)
		}
		if out[0].Seq != afterSeq+1 {
			return nil, fmt.Errorf(
				"list provider audit events: sequence gap after WORM cursor %d (next row is %d)",
				afterSeq,
				out[0].Seq,
			)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit provider audit list: %w", err)
	}
	return out, nil
}

func scanProviderEvent(row interface{ Scan(...any) error }) (Event, error) {
	var (
		ev        Event
		dataBytes []byte
	)
	if err := row.Scan(&ev.Seq, &ev.Actor, &ev.Action, &ev.Target, &dataBytes, &ev.PrevHash, &ev.Hash, &ev.CreatedAt); err != nil {
		return Event{}, err
	}
	if len(dataBytes) > 0 {
		if err := json.Unmarshal(dataBytes, &ev.Data); err != nil {
			return Event{}, fmt.Errorf("decode provider audit event %d data: %w", ev.Seq, err)
		}
	}
	return ev, nil
}
