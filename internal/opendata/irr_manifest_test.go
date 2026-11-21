// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestIRRIndexPreservesPerSourceEvidenceAndExactScope(t *testing.T) {
	const fixture = "route: 192.0.2.0/24\norigin: AS64497\nlast-modified: 2026-10-01T00:00:00Z\nsource: LAB\n"
	dir := t.TempDir()
	var captured bytes.Buffer
	w := gzip.NewWriter(&captured)
	if _, err := w.Write([]byte(fixture)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lab.rpsl.gz"), captured.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, time.November, 19, 0, 0, 0, 0, time.UTC)
	digest := hex.EncodeToString(crypto.Hash(captured.Bytes()))
	inputs := []irrLocalSource{
		{irrSourceReceipt: irrSourceReceipt{Source: "LAB", GeneratedAt: stamp, SHA256: digest, Terms: "https://registry.example/terms"}, File: "lab.rpsl.gz"},
		{irrSourceReceipt: irrSourceReceipt{Source: "FAILED", GeneratedAt: stamp, SHA256: strings.Repeat("0", 64), Terms: "https://registry.example/terms"}, File: "lab.rpsl.gz"},
	}
	manifest, err := json.Marshal(irrManifest{Version: 1, Sources: inputs})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := LoadIRRIndex(t.Context(), path, stamp.Add(time.Hour), 48*time.Hour, 30*24*time.Hour, 2<<20, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, prefix, status string
		origin               uint32
		at                   time.Time
	}{
		{"exact match", "192.0.2.0/24", "match", 64497, stamp.Add(time.Hour)},
		{"same prefix other origin", "192.0.2.0/24", "origin_mismatch", 64498, stamp.Add(time.Hour)},
		{"covering parent is distinct", "192.0.2.0/25", "not_found", 64497, stamp.Add(time.Hour)},
		{"stale snapshot", "192.0.2.0/25", "unavailable", 64497, stamp.Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := index.Assess(t.Context(), netip.MustParsePrefix(tc.prefix), &tc.origin, tc.at, 1<<16)
			if err != nil || len(rows) != 2 || rows[0].Status != tc.status || rows[0].SHA256 != digest ||
				rows[0].ObservedAt == nil || !rows[0].ObservedAt.Equal(stamp) || rows[1].Status != "unavailable" || rows[1].SHA256 != "" {
				t.Fatalf("result misrepresented exact source coverage: %+v, %v", rows, err)
			}
			if tc.status == "match" && (len(rows[0].Objects) != 1 || rows[0].Objects[0].Review != "past_review_age") {
				t.Fatal("the old matching object should retain its distinct review state", rows[0])
			}
		})
	}
}
