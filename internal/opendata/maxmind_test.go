// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestGeoEnrich(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	g := NewGeo(fakeGeo{res: map[netip.Addr]GeoResult{
		addr: {CountryCode: "US", City: "Mountain View", Latitude: 37.4056, Longitude: -122.0775},
	}})
	e := &Enrichment{}
	if err := g.Enrich(context.Background(), addr, e); err != nil {
		t.Fatal(err)
	}
	if e.CountryCode != "US" || e.City != "Mountain View" || e.Latitude == 0 {
		t.Errorf("geo enrichment = %+v", e)
	}
	if len(e.Sources) != 1 || e.Sources[0].Source != "maxmind-geolite2" {
		t.Errorf("provenance = %+v", e.Sources)
	}
}

func TestGeoNoRecord(t *testing.T) {
	e := &Enrichment{}
	if err := NewGeo(fakeGeo{res: map[netip.Addr]GeoResult{}}).
		Enrich(context.Background(), netip.MustParseAddr("10.0.0.1"), e); err != nil {
		t.Fatal(err)
	}
	if e.CountryCode != "" || len(e.Sources) != 0 {
		t.Errorf("absent record should add nothing: %+v", e)
	}
}

func TestGeoReaderErrorPropagates(t *testing.T) {
	err := NewGeo(fakeGeo{err: errors.New("db corrupt")}).
		Enrich(context.Background(), netip.MustParseAddr("8.8.8.8"), &Enrichment{})
	if err == nil {
		t.Fatal("expected a reader error")
	}
}

// TestMMDBReader exercises the real MaxMind reader against a committed, SYNTHETIC
// MaxMind-DB fixture (testdata/geoip-test.mmdb — our own fabricated data, not
// GeoLite2, so there is no MaxMind licensing concern; see testdata/README.md to
// regenerate). PROBECTL_GEOIP_DB still overrides it with a real GeoLite2 db.
// TQ-13: this no longer SKIPs by default — the reader is exercised on every run.
func TestMMDBReader(t *testing.T) {
	path := os.Getenv("PROBECTL_GEOIP_DB")
	if path == "" {
		path = filepath.Join("testdata", "geoip-test.mmdb")
	}
	r, err := OpenMMDB(path)
	if err != nil {
		t.Fatal(err)
	}
	geo, ok, err := r.LookupGeo(netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !ok {
		t.Fatal("expected a record for 8.8.8.8 in the fixture")
	}
	if geo.CountryCode != "US" || geo.City != "Mountain View" {
		t.Fatalf("fixture lookup = %+v, want US / Mountain View", geo)
	}
	if geo.Latitude == 0 || geo.Longitude == 0 {
		t.Fatalf("fixture lookup missing coordinates: %+v", geo)
	}
}
