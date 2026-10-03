// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
)

// exportAndVerify runs the drill's events through the real ephemeral WORM
// exporter (the same path the fixture uses) and reports whether the generated,
// signed chain verifies — i.e. whether the real provider verifier accepts it.
func exportAndVerify(t *testing.T, events []audit.Event) error {
	t.Helper()
	store, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("objectstore: %v", err)
	}
	source := func(_ context.Context, afterSeq int64, limit int) ([]audit.Event, error) {
		out := make([]audit.Event, 0, len(events))
		for _, e := range events {
			if e.Seq > afterSeq && len(out) < limit {
				out = append(out, e)
			}
		}
		return out, nil
	}
	exporter, err := audit.NewWormExporterEphemeralForTest(source, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("exporter: %v", err)
	}
	if _, err := exporter.ExportOnce(context.Background()); err != nil {
		return err
	}
	return exporter.VerifyWORMChain(context.Background())
}

// TestFixtureChainVerifiesWithProductionHash is the backup-drill regression
// (PLAT-14/AUD-02/AUD-03 area): chainedEvents must hash through the production
// canonicalization (audit.CanonicalEventHash) so the freshly generated WORM
// chain verifies. Hand-rolling the header drifted from auditHeader — it omitted
// the AUD-02 created_at field — and the real verifier rejected the chain
// ("WORM source canonical hash invalid"), breaking `make backup-restore-drill`.
func TestFixtureChainVerifiesWithProductionHash(t *testing.T) {
	events, err := chainedEvents("drill-nonce", 3)
	if err != nil {
		t.Fatalf("chainedEvents: %v", err)
	}
	if err := exportAndVerify(t, events); err != nil {
		t.Fatalf("the fixture chain must verify through the real exporter, got: %v", err)
	}

	// Non-vacuity: recomputing a hash the OLD, drifted way (header WITHOUT the
	// created_at field) must make the verifier reject the chain — proving this
	// test actually exercises the canonical form the drill depends on.
	stale := make([]audit.Event, len(events))
	copy(stale, events)
	canonical, err := json.Marshal(stale[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	legacyHeader := stale[0].Actor + "\n" + stale[0].Action + "\n" + stale[0].Target + "\n" // no stream/seq/created_at/prev — a deliberately wrong canonical form
	stale[0].Hash = hex.EncodeToString(crypto.Hash(append([]byte(legacyHeader), canonical...)))
	if err := exportAndVerify(t, stale); err == nil {
		t.Fatal("a drifted (created_at-less / wrong-header) hash must fail WORM verification, but it was accepted")
	}
}
