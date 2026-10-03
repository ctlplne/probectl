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
	"testing"
)

// ASN enrichment from a local MaxMind GeoLite2-ASN-style CSV — no Team Cymru
// DNS, no outbound call (air-gap — docs/guardrails.md G7-2). RTP-14.
func TestASNFileEnrich(t *testing.T) {
	dir := t.TempDir()
	// The org field carries a comma, so quoted-field parsing must hold.
	csv := "network,autonomous_system_number,autonomous_system_organization\n" +
		"192.0.2.0/24,64500,\"EXAMPLE-NET, US\"\n" +
		"203.0.113.0/24,AS64501,Example-Two\n" +
		"2001:db8::/32,64502,Example-v6\n"
	path := filepath.Join(dir, "GeoLite2-ASN-Blocks.csv")
	if err := os.WriteFile(path, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}

	idx, err := LoadASNFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Size() != 3 {
		t.Fatalf("Size = %d, want 3", idx.Size())
	}

	e := &Enrichment{}
	if err := idx.Enrich(context.Background(), netip.MustParseAddr("192.0.2.7"), e); err != nil {
		t.Fatal(err)
	}
	if e.ASN != 64500 || e.ASName != "EXAMPLE-NET, US" || e.Prefix != "192.0.2.0/24" {
		t.Fatalf("v4 enrich = %+v", e)
	}
	if len(e.Sources) != 1 || e.Sources[0].Source != "asn-file" {
		t.Fatalf("provenance = %+v", e.Sources)
	}

	// "AS"-prefixed AS number is accepted.
	e2 := &Enrichment{}
	if err := idx.Enrich(context.Background(), netip.MustParseAddr("203.0.113.9"), e2); err != nil {
		t.Fatal(err)
	}
	if e2.ASN != 64501 || e2.ASName != "Example-Two" {
		t.Fatalf("v4 AS-prefixed enrich = %+v", e2)
	}

	// IPv6 lookup.
	e6 := &Enrichment{}
	if err := idx.Enrich(context.Background(), netip.MustParseAddr("2001:db8::1"), e6); err != nil {
		t.Fatal(err)
	}
	if e6.ASN != 64502 || e6.Prefix != "2001:db8::/32" {
		t.Fatalf("v6 enrich = %+v", e6)
	}

	// A clean IP outside every block contributes nothing (absence, not error).
	clean := &Enrichment{}
	if err := idx.Enrich(context.Background(), netip.MustParseAddr("8.8.8.8"), clean); err != nil {
		t.Fatal(err)
	}
	if clean.ASN != 0 || len(clean.Sources) != 0 {
		t.Fatalf("clean IP should add nothing: %+v", clean)
	}

	// Commercial posture fails closed (restricted — MaxMind EULA governs resale).
	if idx.Descriptor().AUP.CommercialUse != CommercialRestricted {
		t.Fatalf("asn-file commercial posture = %q, want restricted", idx.Descriptor().AUP.CommercialUse)
	}
}

func TestLoadASNFileErrors(t *testing.T) {
	if _, err := LoadASNFile(filepath.Join(t.TempDir(), "missing.csv")); err == nil {
		t.Error("missing file should error (registers unavailable)")
	}
	empty := filepath.Join(t.TempDir(), "empty.csv")
	if err := os.WriteFile(empty, []byte("network,asn,org\n# only a header and a comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadASNFile(empty); err == nil {
		t.Error("a file with no usable rows should error")
	}
}
