// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
}
