// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A delegated-extended stats fixture with a version line, a summary line, and
// real ipv4/ipv6 allocation records.
const rirFixture = `2.3|ripencc|20240101|4|19900101|20240101|+0000
ripencc|*|ipv4|*|2|summary
ripencc|EU|ipv4|192.0.2.0|256|20100101|allocated|id1
arin|US|ipv4|198.51.100.0|256|20000115|assigned|id2
ripencc|NL|ipv6|2001:db8::|32|20011201|allocated|id3`

func loadRIR(t *testing.T) *RIRAllocations {
	t.Helper()
	s := NewRIRAllocations()
	if err := s.Load(strings.NewReader(rirFixture)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRIRLookupIPv4(t *testing.T) {
	e := &Enrichment{}
	if err := loadRIR(t).Enrich(context.Background(), netip.MustParseAddr("192.0.2.55"), e); err != nil {
		t.Fatal(err)
	}
	if e.RIR != "ripencc" || e.AllocationStatus != "allocated" || e.AllocationDate != "20100101" || e.CountryCode != "EU" {
		t.Errorf("v4 enrichment = %+v", e)
	}
	if len(e.Sources) != 1 || e.Sources[0].Source != "rir-stats" {
		t.Errorf("provenance = %+v", e.Sources)
	}
}

func TestRIRLookupIPv6(t *testing.T) {
	e := &Enrichment{}
	if err := loadRIR(t).Enrich(context.Background(), netip.MustParseAddr("2001:db8::dead"), e); err != nil {
		t.Fatal(err)
	}
	if e.RIR != "ripencc" || e.AllocationStatus != "allocated" || e.AllocationDate != "20011201" || e.CountryCode != "NL" {
		t.Errorf("v6 enrichment = %+v", e)
	}
}

func TestRIRSecondBlockBoundary(t *testing.T) {
	e := &Enrichment{}
	if err := loadRIR(t).Enrich(context.Background(), netip.MustParseAddr("198.51.100.200"), e); err != nil {
		t.Fatal(err)
	}
	if e.RIR != "arin" || e.AllocationStatus != "assigned" {
		t.Errorf("expected arin/assigned, got %+v", e)
	}
}

func TestRIRUnallocatedYieldsNothing(t *testing.T) {
	e := &Enrichment{}
	if err := loadRIR(t).Enrich(context.Background(), netip.MustParseAddr("10.0.0.1"), e); err != nil {
		t.Fatal(err)
	}
	if e.RIR != "" || len(e.Sources) != 0 {
		t.Errorf("unallocated IP should add nothing: %+v", e)
	}
}

func TestLoadRIRDir(t *testing.T) {
	dir := t.TempDir()
	stats := "arin|US|ipv4|192.0.2.0|256|20100714|assigned|opaque\nripencc|NL|ipv6|2001:db8::|32|20080512|allocated|opaque\n"
	if err := os.WriteFile(filepath.Join(dir, "delegated-test-extended-latest"), []byte(stats), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}

	idx, files, err := LoadRIRDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Fatalf("files loaded = %d, want 1 (dotfiles and subdirs skipped)", files)
	}
	if v4, v6 := idx.Size(); v4 != 1 || v6 != 1 {
		t.Fatalf("Size() = (%d, %d), want (1, 1)", v4, v6)
	}
	e := &Enrichment{}
	if err := idx.Enrich(context.Background(), netip.MustParseAddr("192.0.2.7"), e); err != nil {
		t.Fatal(err)
	}
	if e.RIR != "arin" || e.AllocationStatus != "assigned" || e.CountryCode != "US" {
		t.Fatalf("loaded dir did not serve: %+v", e)
	}
}

func TestLoadRIRDirFailsClosed(t *testing.T) {
	if _, _, err := LoadRIRDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing directory must error")
	}
	if _, _, err := LoadRIRDir(t.TempDir()); err == nil {
		t.Fatal("empty directory must error — a silently empty index would look healthy")
	}
}
