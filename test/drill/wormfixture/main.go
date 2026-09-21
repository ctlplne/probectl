// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command wormfixture creates a tiny, cryptographically valid provider-audit
// WORM ledger for the backup/restore drill. It is test tooling, not a shipped
// binary: the real exporter is used so the drill protects the exact object-key
// layout and Ed25519 signature format that production writes.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
)

func main() {
	root := flag.String("dir", "", "filesystem object-store root")
	nonce := flag.String("nonce", "", "unique restore-drill marker")
	flag.Parse()
	if *root == "" || *nonce == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./test/drill/wormfixture --dir <path> --nonce <value>")
		os.Exit(2)
	}

	store, err := objectstore.NewFS(*root)
	if err != nil {
		fatal(err)
	}
	events, err := chainedEvents(*nonce, 3)
	if err != nil {
		fatal(err)
	}
	source := func(_ context.Context, afterSeq int64, limit int) ([]audit.Event, error) {
		out := make([]audit.Event, 0, len(events))
		for _, event := range events {
			if event.Seq > afterSeq && len(out) < limit {
				out = append(out, event)
			}
		}
		return out, nil
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	exporter, err := audit.NewWormExporterEphemeralForTest(source, store, logger)
	if err != nil {
		fatal(err)
	}
	if n, err := exporter.ExportOnce(context.Background()); err != nil || n != len(events) {
		fatal(fmt.Errorf("exported %d/%d events: %w", n, len(events), err))
	}
	if err := exporter.VerifyWORMChain(context.Background()); err != nil {
		fatal(fmt.Errorf("verify generated WORM chain: %w", err))
	}
	if err := store.Put(context.Background(), "tenants/11111111-1111-1111-1111-111111111111/support/drill-marker.txt", "text/plain", []byte(*nonce+"\n")); err != nil {
		fatal(err)
	}
	fmt.Printf("wormfixture: generated and verified %d signed events in %s\n", len(events), *root)
}

func chainedEvents(nonce string, count int) ([]audit.Event, error) {
	const stream = "provider"
	previous := ""
	out := make([]audit.Event, 0, count)
	for i := 1; i <= count; i++ {
		data := map[string]any{"drill_nonce": nonce, "index": i}
		actor := "restore-drill"
		action := "backup.fixture"
		target := fmt.Sprintf("object-%d", i)
		canonical, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		header := fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%s\n", stream, i, actor, action, target, previous)
		hash := hex.EncodeToString(crypto.Hash(append([]byte(header), canonical...)))
		out = append(out, audit.Event{
			Seq:       int64(i),
			Actor:     actor,
			Action:    action,
			Target:    target,
			Data:      data,
			PrevHash:  previous,
			Hash:      hash,
			CreatedAt: time.Unix(1_700_000_000+int64(i), 0).UTC(),
		})
		previous = hash
	}
	return out, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wormfixture:", err)
	os.Exit(1)
}
