// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGeoFile(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "geo.json")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestGeoTableLongestPrefixAndPrivateRanges(t *testing.T) {
	file := writeGeoFile(t, `[
		{"cidr":"10.0.0.0/8","lat":52.52,"lon":13.40,"city":"Berlin DC","country":"DE"},
		{"cidr":"10.0.2.0/24","lat":48.14,"lon":11.58,"city":"Munich edge","country":"DE"},
		{"cidr":"192.0.2.0/24","lat":38.95,"lon":-77.45,"city":"Ashburn","country":"US"}
	]`)
	table, err := LoadGeoTable(file)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		ip   string
		city string
	}{
		{"10.0.2.7", "Munich edge"}, // /24 beats /8
		{"10.9.9.9", "Berlin DC"},   // operator table is authoritative for private space
		{"192.0.2.9", "Ashburn"},
		{"203.0.113.5", ""}, // unmapped → no location, never invented
		{"not-an-ip", ""},   // malformed responder → nil, no panic
	}
	for _, tc := range cases {
		geo := table.Lookup(tc.ip)
		switch {
		case tc.city == "" && geo != nil:
			t.Errorf("%s: expected no location, got %+v", tc.ip, geo)
		case tc.city != "" && (geo == nil || geo.City != tc.city):
			t.Errorf("%s: expected %q, got %+v", tc.ip, tc.city, geo)
		case geo != nil && geo.Source != "operator-table":
			t.Errorf("%s: source = %q, want operator-table", tc.ip, geo.Source)
		}
	}
}

func TestGeoTableFailsClosedOnBadFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"invalid json", `{not json`},
		{"empty set", `[]`},
		{"bad cidr", `[{"cidr":"10.0.0.0","lat":1,"lon":1}]`},
		{"lat out of range", `[{"cidr":"10.0.0.0/8","lat":91,"lon":0}]`},
		{"lon out of range", `[{"cidr":"10.0.0.0/8","lat":0,"lon":-181}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadGeoTable(writeGeoFile(t, tc.content)); err == nil {
				t.Fatal("expected load to fail closed, got nil error")
			}
		})
	}
	if _, err := LoadGeoTable(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing file to error")
	}
}

func TestLoadGeoTableBoundsFile(t *testing.T) {
	const maxBytes = 1 << 20
	valid := `[{"cidr":"10.0.0.0/8","lat":1,"lon":2,"city":"bounded"}]`
	exact := valid + strings.Repeat(" ", maxBytes-len(valid))

	table, err := LoadGeoTable(writeGeoFile(t, exact))
	if err != nil {
		t.Fatalf("exact-limit file should load: %v", err)
	}
	if got := table.Lookup("10.1.2.3"); got == nil || got.City != "bounded" {
		t.Fatalf("exact-limit file lookup = %+v, want bounded location", got)
	}

	_, err = LoadGeoTable(writeGeoFile(t, exact+" "))
	if err == nil {
		t.Fatal("one-byte-oversized valid JSON should fail before decoding, got nil error")
	}
	if !strings.Contains(err.Error(), "1048576-byte limit") {
		t.Fatalf("oversized file error = %q, want finite-read limit", err)
	}
}

func TestEnrichAttachesWithoutOverwriting(t *testing.T) {
	file := writeGeoFile(t, `[{"cidr":"192.0.2.0/24","lat":38.95,"lon":-77.45,"city":"Ashburn"}]`)
	table, err := LoadGeoTable(file)
	if err != nil {
		t.Fatal(err)
	}
	preset := &HopGeo{Lat: 1, Lon: 2, City: "agent-said", Source: "agent"}
	p := Path{Hops: []Hop{{TTL: 1, Nodes: []HopNode{
		{IP: "192.0.2.9"},
		{IP: "192.0.2.10", Geo: preset},
		{IP: "198.51.100.1"},
	}}}}

	table.Enrich(&p)

	if got := p.Hops[0].Nodes[0].Geo; got == nil || got.City != "Ashburn" {
		t.Fatalf("node 0: expected Ashburn enrichment, got %+v", got)
	}
	if got := p.Hops[0].Nodes[1].Geo; got != preset {
		t.Fatalf("node 1: existing geo must never be overwritten, got %+v", got)
	}
	if got := p.Hops[0].Nodes[2].Geo; got != nil {
		t.Fatalf("node 2: unmapped responder must stay unlocated, got %+v", got)
	}
	// A nil table is a no-op, never a panic.
	var none *GeoTable
	none.Enrich(&p)
}
