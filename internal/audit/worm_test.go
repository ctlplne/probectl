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
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
)

// TestWormExporterRefusesEmptyKey: KEYS-004. The production constructors must
// REFUSE an empty signing key rather than mint an ephemeral per-boot key (which
// would break cross-restart chain verification). Only the explicit test
// constructor mints a throwaway key.
func TestWormExporterRefusesEmptyKey(t *testing.T) {
	store := objectstore.NewMemory()
	src := sourceOf(chainedEvents(1))

	if _, err := NewWormExporter(src, store, nil, nil, testLog()); err == nil {
		t.Error("NewWormExporter with empty PEMs must error (KEYS-004)")
	}
	if _, err := NewWormExporter(src, store, []byte("priv"), nil, testLog()); err == nil {
		t.Error("NewWormExporter with empty pubPEM must error (KEYS-004)")
	}
	// The production PG wiring must also refuse empty PEMs (it errors before
	// touching the pool, so a nil pool is fine here).
	if _, err := NewWormExporterPG(nil, store, nil, nil, testLog()); err == nil {
		t.Error("NewWormExporterPG with empty PEMs must error (KEYS-004)")
	}
	// The explicit test constructor still works.
	if _, err := NewWormExporterEphemeralForTest(src, store, testLog()); err != nil {
		t.Errorf("ephemeral test constructor failed: %v", err)
	}
}

// chainedEvents builds a synthetic, correctly-chained provider stream.
func chainedEvents(n int) []Event {
	out := make([]Event, n)
	prev := genesis
	for i := range out {
		h := "h" + string(rune('0'+i%10)) + "-" + strings.Repeat("x", i%3+1)
		out[i] = Event{Seq: int64(i + 1), Actor: "op", Action: "a", PrevHash: prev, Hash: h}
		prev = h
	}
	return out
}

func sourceOf(events []Event) WormSource {
	return func(_ context.Context, afterSeq int64, limit int) ([]Event, error) {
		var page []Event
		for _, ev := range events {
			if ev.Seq > afterSeq && len(page) < limit {
				page = append(page, ev)
			}
		}
		return page, nil
	}
}

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type failingPutStore struct {
	objectstore.Store
	failSuffix string
	failing    bool
}

func (s *failingPutStore) Put(ctx context.Context, key, contentType string, data []byte) error {
	if s.failing && strings.HasSuffix(key, s.failSuffix) {
		return errors.New("injected WORM object put failure")
	}
	return s.Store.Put(ctx, key, contentType, data)
}

type countingGetStore struct {
	objectstore.Store
	gets map[string]int
}

func (s *countingGetStore) Get(ctx context.Context, key string) (objectstore.Object, error) {
	s.gets[key]++
	return s.Store.Get(ctx, key)
}

func TestWORMObjectSizeBounds(t *testing.T) {
	const segmentKey = wormPrefix + "segment-000000000001-000000000001.json"
	for _, tc := range []struct {
		name        string
		key         string
		contentType string
		limit       int64
	}{
		{name: "public-key", key: wormPrefix + "signing.pub", contentType: "application/x-pem-file", limit: maxWORMPublicKeyBytes},
		{name: "segment", key: segmentKey, contentType: "application/json", limit: maxWORMSegmentBytes},
		{name: "signature", key: segmentKey + ".sig", contentType: "application/octet-stream", limit: maxWORMSignatureBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base := objectstore.NewMemory()
			exporter, err := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(1)), base, testLog())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := exporter.ExportOnce(ctx); err != nil {
				t.Fatal(err)
			}
			if err := base.Put(ctx, tc.key, tc.contentType, bytes.Repeat([]byte("x"), int(tc.limit)+1)); err != nil {
				t.Fatal(err)
			}
			counted := &countingGetStore{Store: base, gets: map[string]int{}}
			exporter.objects = counted

			err = exporter.VerifyWORMChain(ctx)
			if !errors.Is(err, objectstore.ErrTooLarge) {
				t.Fatalf("one-past %s error = %v, want ErrTooLarge", tc.name, err)
			}
			if counted.gets[tc.key] != 0 {
				t.Fatalf("oversized WORM %s used whole-object Get %d time(s), want bounded refusal before buffering", tc.name, counted.gets[tc.key])
			}
		})
	}
}

func TestWORMObjectExactSizeBounds(t *testing.T) {
	ctx := context.Background()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(pub)) >= maxWORMPublicKeyBytes {
		t.Fatalf("generated public key unexpectedly exceeds test ceiling: %d", len(pub))
	}
	pub = append(pub, bytes.Repeat([]byte("\n"), int(maxWORMPublicKeyBytes)-len(pub))...)

	store := objectstore.NewMemory()
	exporter, err := NewWormExporter(sourceOf(chainedEvents(1)), store, priv, pub, testLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exporter.ExportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	const segmentKey = wormPrefix + "segment-000000000001-000000000001.json"
	obj, err := store.Get(ctx, segmentKey)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(obj.Data)) >= maxWORMSegmentBytes {
		t.Fatalf("generated segment unexpectedly exceeds test ceiling: %d", len(obj.Data))
	}
	exactSegment := append(obj.Data, bytes.Repeat([]byte(" "), int(maxWORMSegmentBytes)-len(obj.Data))...)
	sig, err := crypto.SignEd25519(priv, exactSegment)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(sig)) != maxWORMSignatureBytes {
		t.Fatalf("signature size = %d, want exact ceiling %d", len(sig), maxWORMSignatureBytes)
	}
	if err := store.Put(ctx, segmentKey, "application/json", exactSegment); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, segmentKey+".sig", "application/octet-stream", sig); err != nil {
		t.Fatal(err)
	}
	if err := exporter.VerifyWORMChain(ctx); err != nil {
		t.Fatalf("exact-limit public key, segment, and signature must verify: %v", err)
	}
}

func TestWORMEventCardinalityBounds(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		store := objectstore.NewMemory()
		exporter, err := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(MaxExportPageSize)), store, testLog())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exporter.ExportOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := exporter.VerifyWORMChain(context.Background()); err != nil {
			t.Fatalf("exact event limit must verify: %v", err)
		}
	})

	t.Run("export-one-past", func(t *testing.T) {
		ctx := context.Background()
		store := objectstore.NewMemory()
		exporter, err := NewWormExporterEphemeralForTest(
			func(context.Context, int64, int) ([]Event, error) {
				return chainedEvents(MaxExportPageSize + 1), nil
			},
			store,
			testLog(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := exporter.ExportOnce(ctx); err == nil || !strings.Contains(err.Error(), "event limit") {
			t.Fatalf("one-past source cardinality error = %v, want explicit limit rejection", err)
		}
		if keys, err := store.List(ctx, wormPrefix+"segment-"); err != nil {
			t.Fatal(err)
		} else if len(keys) != 0 {
			t.Fatalf("one-past source wrote WORM segment objects: %v", keys)
		}
	})

	t.Run("one-past", func(t *testing.T) {
		ctx := context.Background()
		store := objectstore.NewMemory()
		exporter, err := NewWormExporterEphemeralForTest(sourceOf(nil), store, testLog())
		if err != nil {
			t.Fatal(err)
		}
		if err := exporter.ensurePublicKey(ctx); err != nil {
			t.Fatal(err)
		}
		events := chainedEvents(MaxExportPageSize + 1)
		seg := WormSegment{
			FormatVersion: 1,
			Stream:        "provider",
			FromSeq:       1,
			ToSeq:         int64(len(events)),
			ExportedAt:    time.Now().UTC(),
			Events:        events,
		}
		raw, err := json.Marshal(seg)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(raw)) > maxWORMSegmentBytes {
			t.Fatalf("cardinality fixture exceeds byte ceiling: %d", len(raw))
		}
		sig, err := crypto.SignEd25519(exporter.privPEM, raw)
		if err != nil {
			t.Fatal(err)
		}
		key := wormPrefix + "segment-000000000001-000000001001.json"
		if err := store.Put(ctx, key, "application/json", raw); err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, key+".sig", "application/octet-stream", sig); err != nil {
			t.Fatal(err)
		}
		if err := exporter.VerifyWORMChain(ctx); err == nil || !strings.Contains(err.Error(), "event limit") {
			t.Fatalf("one-past event cardinality error = %v, want explicit limit rejection", err)
		}
	})
}

type providerEventRow struct {
	data []byte
}

func (r providerEventRow) Scan(dest ...any) error {
	*dest[0].(*int64) = 1
	*dest[1].(*string) = "operator"
	*dest[2].(*string) = "provider.test"
	*dest[3].(*string) = "target"
	*dest[4].(*[]byte) = r.data
	*dest[5].(*string) = genesis
	*dest[6].(*string) = "hash"
	*dest[7].(*time.Time) = time.Unix(1700000000, 0).UTC()
	return nil
}

func TestScanProviderEventRejectsCorruptDataJSON(t *testing.T) {
	if _, err := scanProviderEvent(providerEventRow{data: []byte(`{"actor":`)}); err == nil {
		t.Fatal("corrupt provider audit event data must return an error, not an empty event data map")
	}
}

// U-041: export → verify round-trips; incremental exports build separate
// signed segments and the cross-segment chain verifies end to end.
func TestWormExportAndChainVerify(t *testing.T) {
	all := chainedEvents(7)
	store := objectstore.NewMemory()
	ctx := context.Background()

	// First export sees only the first 4 events.
	w, err := NewWormExporterEphemeralForTest(sourceOf(all[:4]), store, testLog())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.ExportOnce(ctx); err != nil || n != 4 {
		t.Fatalf("first export: n=%d err=%v", n, err)
	}
	// Second export picks up the rest from the derived cursor.
	w.source = sourceOf(all)
	if n, err := w.ExportOnce(ctx); err != nil || n != 3 {
		t.Fatalf("second export: n=%d err=%v", n, err)
	}
	// Idempotent when nothing is new.
	if n, err := w.ExportOnce(ctx); err != nil || n != 0 {
		t.Fatalf("noop export: n=%d err=%v", n, err)
	}
	if err := w.VerifyWORMChain(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The public key is published next to the segments.
	if _, err := store.Get(ctx, "worm/audit/provider/signing.pub"); err != nil {
		t.Fatal("verification key not published")
	}
	keys, _ := store.List(ctx, "worm/audit/provider/segment-")
	if len(keys) != 4 { // 2 segments + 2 signatures
		t.Fatalf("objects = %v", keys)
	}
}

func TestWormExportedWatermarkRejectsPartialSegment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failSuffix string
	}{
		{name: "missing_signature", failSuffix: ".sig"},
		{name: "missing_public_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base := objectstore.NewMemory()
			objects := &failingPutStore{Store: base, failSuffix: tc.failSuffix, failing: true}
			w, err := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(3)), objects, testLog())
			if err != nil {
				t.Fatal(err)
			}

			if tc.failSuffix == "" {
				objects.failing = false
				if n, err := w.ExportOnce(ctx); err != nil || n != 3 {
					t.Fatalf("seed signed segment = (%d, %v), want (3, nil)", n, err)
				}
				if deleted, err := base.DeletePrefix(ctx, wormPrefix+"signing.pub"); err != nil || deleted != 1 {
					t.Fatalf("remove public-key companion = (%d, %v), want (1, nil)", deleted, err)
				}
			} else if n, err := w.ExportOnce(ctx); err == nil || n != 0 {
				t.Fatalf("partial export = (%d, %v), want (0, injected error)", n, err)
			}
			keys, err := base.List(ctx, wormPrefix+"segment-")
			if err != nil {
				t.Fatal(err)
			}
			hasUnsignedCandidate := false
			for _, key := range keys {
				if strings.HasSuffix(key, ".json") {
					hasUnsignedCandidate = true
				}
			}
			if !hasUnsignedCandidate {
				t.Fatalf("failure did not leave the partial segment needed by this regression: %v", keys)
			}

			if watermark, err := w.ExportedWatermark(ctx); err == nil {
				t.Fatalf("partial WORM watermark = %d, want fail-closed error", watermark)
			}

			runner := NewRetentionRunnerPG(
				nil,
				RetentionPolicy{Window: time.Hour},
				w.ExportedWatermark,
				testLog(),
			)
			summary, err := runner.Tick(ctx)
			if err == nil {
				t.Fatal("retention accepted a partial WORM watermark")
			}
			if summary.ProviderPruned != 0 {
				t.Fatalf("provider rows pruned from partial WORM watermark = %d, want 0", summary.ProviderPruned)
			}
		})
	}
}

func TestWormExportRetriesMissingSignatureAndPublicKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failSuffix string
	}{
		{name: "signature", failSuffix: ".sig"},
		{name: "public_key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			base := objectstore.NewMemory()
			objects := &failingPutStore{Store: base, failSuffix: tc.failSuffix, failing: true}
			w, err := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(3)), objects, testLog())
			if err != nil {
				t.Fatal(err)
			}

			wantRetry := 3
			if tc.failSuffix == "" {
				objects.failing = false
				if n, err := w.ExportOnce(ctx); err != nil || n != 3 {
					t.Fatalf("seed signed segment = (%d, %v), want (3, nil)", n, err)
				}
				if deleted, err := base.DeletePrefix(ctx, wormPrefix+"signing.pub"); err != nil || deleted != 1 {
					t.Fatalf("remove public-key companion = (%d, %v), want (1, nil)", deleted, err)
				}
				wantRetry = 0
			} else if n, err := w.ExportOnce(ctx); err == nil || n != 0 {
				t.Fatalf("partial export = (%d, %v), want (0, injected error)", n, err)
			}
			objects.failing = false
			if n, err := w.ExportOnce(ctx); err != nil || n != wantRetry {
				t.Fatalf("retry export = (%d, %v), want (%d, nil)", n, err, wantRetry)
			}
			if watermark, err := w.ExportedWatermark(ctx); err != nil || watermark != 3 {
				t.Fatalf("watermark after retry = (%d, %v), want (3, nil)", watermark, err)
			}
			if err := w.VerifyWORMChain(ctx); err != nil {
				t.Fatalf("chain after retry: %v", err)
			}
		})
	}
}

func TestWormExporterMetricsRecordSuccessAndFailures(t *testing.T) {
	reg := metrics.New("test", "abc")
	w, err := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(1)), objectstore.NewMemory(), testLog())
	if err != nil {
		t.Fatal(err)
	}
	w.WithMetrics(reg)

	if got := w.lastSuccessUnix.Load(); got != 0 {
		t.Fatalf("last success starts at %d, want 0 before the first good cycle", got)
	}
	before := time.Now().Unix()
	w.recordSuccess()
	if got := w.lastSuccessUnix.Load(); got < before {
		t.Fatalf("last success = %d, want >= %d", got, before)
	}

	w.recordExportFailure()
	if got := reg.Counter("probectl_audit_worm_export_failures_total", "").Value(); got != 1 {
		t.Fatalf("export failures = %d, want 1", got)
	}
	w.recordVerifyFailure(errors.New("segment worm/audit/provider/segment-0001 signature INVALID (tampered?)"))
	if got := reg.Counter("probectl_audit_worm_chain_failures_total", "").Value(); got != 1 {
		t.Fatalf("chain failures = %d, want 1", got)
	}
	if got := reg.Counter("probectl_audit_worm_signature_failures_total", "").Value(); got != 1 {
		t.Fatalf("signature failures = %d, want 1", got)
	}
}

// Tampering with an exported segment breaks its signature — detected.
func TestWormTamperedSegmentFailsVerification(t *testing.T) {
	store := objectstore.NewMemory()
	ctx := context.Background()
	w, _ := NewWormExporterEphemeralForTest(sourceOf(chainedEvents(3)), store, testLog())
	if _, err := w.ExportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.List(ctx, "worm/audit/provider/segment-")
	var segKey string
	for _, k := range keys {
		if !strings.HasSuffix(k, ".sig") {
			segKey = k
		}
	}
	obj, _ := store.Get(ctx, segKey)
	tampered := []byte(strings.Replace(string(obj.Data), `"action":"a"`, `"action":"evil"`, 1))
	_ = store.Put(ctx, segKey, "application/json", tampered)

	err := w.VerifyWORMChain(ctx)
	if err == nil || !strings.Contains(err.Error(), "signature INVALID") {
		t.Fatalf("tampered segment passed: %v", err)
	}
	if watermark, err := w.ExportedWatermark(ctx); err == nil {
		t.Fatalf("tampered segment advanced watermark to %d", watermark)
	}
}

func TestWormExportMinimizesRawPersonalFields(t *testing.T) {
	store := objectstore.NewMemory()
	ctx := context.Background()
	events := []Event{{
		Seq:      1,
		Actor:    "operator@example.com",
		Action:   "breakglass.grant",
		Target:   "tenant:alice@example.com",
		Data:     map[string]any{"email": "alice@example.com", "reason": "support"},
		PrevHash: genesis,
		Hash:     "h1",
	}}
	w, _ := NewWormExporterEphemeralForTest(sourceOf(events), store, testLog())
	if _, err := w.ExportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.List(ctx, "worm/audit/provider/segment-")
	var segKey string
	for _, k := range keys {
		if !strings.HasSuffix(k, ".sig") {
			segKey = k
		}
	}
	obj, _ := store.Get(ctx, segKey)
	lower := strings.ToLower(string(obj.Data))
	for _, leaked := range []string{"operator@example.com", "alice@example.com", "support"} {
		if strings.Contains(lower, leaked) {
			t.Fatalf("WORM segment leaked %q: %s", leaked, obj.Data)
		}
	}
	if err := w.VerifyWORMChain(ctx); err != nil {
		t.Fatalf("minimized WORM segment must still verify: %v", err)
	}
}

// KEYS-002 (D2): the resolved signing key is STABLE across restarts (a key
// FILE is generated once then reused), an env base64 key passes through, and
// the resolver FAILS CLOSED when WORM export is enabled with no key — the
// control plane must never silently mint an ephemeral per-boot key.
func TestResolveWormSigningKeyStableAndFailClosed(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "worm-signing.pem")

	// First boot generates + persists; second boot REUSES the same key.
	priv1, pub1, gen1, err := ResolveWormSigningKey("", keyFile, false)
	if err != nil || !gen1 {
		t.Fatalf("first resolve: gen=%v err=%v", gen1, err)
	}
	priv2, pub2, gen2, err := ResolveWormSigningKey("", keyFile, false)
	if err != nil || gen2 {
		t.Fatalf("second resolve: gen=%v err=%v", gen2, err)
	}
	if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
		t.Fatal("a persisted key file must yield the SAME keypair across restarts")
	}

	// An env base64 PEM private key passes through and derives its public half.
	pemPriv, _, gerr := crypto.GenerateEd25519KeyPEM()
	if gerr != nil {
		t.Fatal(gerr)
	}
	ep, epub, egen, eerr := ResolveWormSigningKey(base64.StdEncoding.EncodeToString(pemPriv), "", false)
	if eerr != nil || egen || len(epub) == 0 {
		t.Fatalf("env key resolve: gen=%v err=%v", egen, eerr)
	}
	if !bytes.Equal(ep, pemPriv) {
		t.Fatal("env-supplied private PEM must pass through unchanged")
	}

	// No key configured but WORM export enabled → FAIL CLOSED (both profiles).
	if _, _, _, e := ResolveWormSigningKey("", "", false); e == nil || !strings.Contains(e.Error(), "ephemeral") {
		t.Fatalf("no key must fail closed (non-regulated): %v", e)
	}
	if _, _, _, e := ResolveWormSigningKey("", "", true); e == nil || !strings.Contains(e.Error(), "at-rest encryption is required") {
		t.Fatalf("no key in regulated profile must fail closed with context: %v", e)
	}
}

// The exported chain VERIFIES after a restart that reuses the persisted key,
// and FAILS under a fresh (ephemeral) key — the exact regression KEYS-002
// closes (a per-boot key broke cross-restart verification).
func TestWormChainVerifiesAcrossRestartWithPersistedKey(t *testing.T) {
	ctx := context.Background()
	store := objectstore.NewMemory()
	keyFile := filepath.Join(t.TempDir(), "worm-signing.pem")

	// Boot 1: resolve (generate) the key, export segments.
	priv1, pub1, _, err := ResolveWormSigningKey("", keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	w1, err := NewWormExporter(sourceOf(chainedEvents(5)), store, priv1, pub1, testLog())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w1.ExportOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Boot 2: the SAME persisted key → the exported chain verifies.
	priv2, pub2, _, err := ResolveWormSigningKey("", keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	w2, _ := NewWormExporter(sourceOf(nil), store, priv2, pub2, testLog())
	if err := w2.VerifyWORMChain(ctx); err != nil {
		t.Fatalf("chain must verify across a restart with the persisted key: %v", err)
	}

	// A fresh ephemeral key (the OLD per-boot behavior) CANNOT verify it.
	ephPriv, ephPub, _ := crypto.GenerateEd25519KeyPEM()
	w3, _ := NewWormExporter(sourceOf(nil), store, ephPriv, ephPub, testLog())
	if err := w3.VerifyWORMChain(ctx); err == nil {
		t.Fatal("an ephemeral key must NOT verify the chain signed by the persisted key")
	}
}

// A purge in the source (events vanish before export) surfaces as a seq gap.
func TestWormDetectsPurgeGap(t *testing.T) {
	store := objectstore.NewMemory()
	ctx := context.Background()
	all := chainedEvents(6)
	purged := append(append([]Event{}, all[:2]...), all[4:]...) // 3 and 4 are gone

	w, _ := NewWormExporterEphemeralForTest(sourceOf(purged), store, testLog())
	if _, err := w.ExportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	err := w.VerifyWORMChain(ctx)
	if err == nil || !strings.Contains(err.Error(), "GAP") {
		t.Fatalf("purged events not detected: %v", err)
	}
	if watermark, err := w.ExportedWatermark(ctx); err == nil {
		t.Fatalf("gapped segment advanced watermark to %d", watermark)
	}
}
