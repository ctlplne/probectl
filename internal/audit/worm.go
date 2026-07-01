// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// wormPrefix is the object-key namespace for provider-stream segments.
const wormPrefix = "worm/audit/provider/"

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

// WormExporter writes signed segments and verifies the exported chain.
type WormExporter struct {
	source  WormSource
	objects objectstore.Store
	privPEM []byte
	pubPEM  []byte
	log     *slog.Logger

	gaps            atomic.Uint64 // chain-verification failures observed (never silent)
	lastSuccessUnix atomic.Int64
	metrics         wormExporterMetrics
}

type wormExporterMetrics struct {
	exportFailures    *selfmetrics.Counter
	chainFailures     *selfmetrics.Counter
	signatureFailures *selfmetrics.Counter
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
	reg.Gauge("probectl_audit_worm_last_success_unix_seconds",
		"Unix timestamp of the last successful audit WORM export+verify cycle; 0 until the first success.",
		func() float64 { return float64(w.lastSuccessUnix.Load()) })
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

// Run exports on the interval and verifies the exported chain after each
// export, until ctx is canceled.
func (w *WormExporter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := w.ExportOnce(ctx); err != nil && ctx.Err() == nil {
			w.recordExportFailure()
			w.log.Error("audit worm export failed", "error", err.Error())
		} else if err := w.VerifyWORMChain(ctx); err != nil && ctx.Err() == nil {
			failures := w.recordVerifyFailure(err)
			w.log.Error("AUDIT WORM CHAIN VERIFICATION FAILED — possible purge or tampering",
				"error", err.Error(), "failures_total", failures)
		} else if ctx.Err() == nil {
			w.recordSuccess()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *WormExporter) recordSuccess() {
	w.lastSuccessUnix.Store(time.Now().Unix())
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
	last, err := w.lastExportedSeq(ctx)
	if err != nil {
		return 0, err
	}
	events, err := w.source(ctx, last, MaxExportPageSize)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	seg := WormSegment{
		FormatVersion: 1, Stream: "provider",
		FromSeq: events[0].Seq, ToSeq: events[len(events)-1].Seq,
		ExportedAt: time.Now().UTC(), Events: minimizeEventsForWORM(events),
	}
	raw, err := json.Marshal(seg)
	if err != nil {
		return 0, err
	}
	sig, err := crypto.SignEd25519(w.privPEM, raw)
	if err != nil {
		return 0, fmt.Errorf("audit: sign segment: %w", err)
	}
	key := fmt.Sprintf("%ssegment-%012d-%012d.json", wormPrefix, seg.FromSeq, seg.ToSeq)
	if err := w.objects.Put(ctx, key, "application/json", raw); err != nil {
		return 0, fmt.Errorf("audit: put segment: %w", err)
	}
	if err := w.objects.Put(ctx, key+".sig", "application/octet-stream", sig); err != nil {
		return 0, fmt.Errorf("audit: put signature: %w", err)
	}
	// Publish the verification key once (idempotent overwrite is fine).
	if err := w.objects.Put(ctx, wormPrefix+"signing.pub", "application/x-pem-file", w.pubPEM); err != nil {
		return 0, fmt.Errorf("audit: put public key: %w", err)
	}
	w.log.Info("audit worm segment exported", "from_seq", seg.FromSeq, "to_seq", seg.ToSeq, "events", len(events))
	return len(events), nil
}

// lastExportedSeq derives the cursor from the existing segment keys (no
// mutable state object — the segments themselves are the ledger).
func (w *WormExporter) lastExportedSeq(ctx context.Context) (int64, error) {
	keys, err := w.objects.List(ctx, wormPrefix+"segment-")
	if err != nil {
		return 0, err
	}
	var last int64
	for _, k := range keys {
		if strings.HasSuffix(k, ".sig") {
			continue
		}
		var from, to int64
		base := strings.TrimSuffix(strings.TrimPrefix(k, wormPrefix), ".json")
		if _, err := fmt.Sscanf(base, "segment-%d-%d", &from, &to); err == nil && to > last {
			last = to
		}
	}
	return last, nil
}

// VerifyWORMChain re-verifies the exported history end to end: every
// segment's signature, seq continuity from 1 with no gaps or overlaps, and
// the hash chain across segment boundaries. Any failure is a loud error.
func (w *WormExporter) VerifyWORMChain(ctx context.Context) error {
	keys, err := w.objects.List(ctx, wormPrefix+"segment-")
	if err != nil {
		return err
	}
	var segKeys []string
	for _, k := range keys {
		if !strings.HasSuffix(k, ".sig") {
			segKeys = append(segKeys, k)
		}
	}
	sort.Strings(segKeys) // zero-padded seqs sort chronologically
	wantSeq := int64(1)
	prevHash := genesis // the chain root (audit.go)
	for _, key := range segKeys {
		obj, err := w.objects.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("segment %s unreadable: %w", key, err)
		}
		sig, err := w.objects.Get(ctx, key+".sig")
		if err != nil {
			return fmt.Errorf("segment %s signature missing: %w", key, err)
		}
		ok, err := crypto.VerifyEd25519(w.pubPEM, obj.Data, sig.Data)
		if err != nil || !ok {
			return fmt.Errorf("segment %s signature INVALID (tampered?): %v", key, err)
		}
		var seg WormSegment
		if err := json.Unmarshal(obj.Data, &seg); err != nil {
			return fmt.Errorf("segment %s undecodable: %w", key, err)
		}
		for _, ev := range seg.Events {
			if ev.Seq != wantSeq {
				return fmt.Errorf("seq GAP at %s: want %d, got %d (events purged?)", key, wantSeq, ev.Seq)
			}
			if ev.PrevHash != prevHash {
				return fmt.Errorf("hash chain BROKEN at seq %d in %s", ev.Seq, key)
			}
			prevHash = ev.Hash
			wantSeq++
		}
	}
	return nil
}

// ListProvider returns provider-stream events with seq greater than afterSeq
// in ascending order (the WORM export cursor).
func ListProvider(ctx context.Context, pool *pgxpool.Pool, afterSeq int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	rows, err := pool.Query(ctx,
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
	return out, rows.Err()
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
