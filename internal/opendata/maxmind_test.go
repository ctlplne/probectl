package opendata

import (
	"context"
	"errors"
	"net/netip"
	"os"
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

// TestMMDBReader exercises the real MaxMind reader; it skips unless a GeoLite2
// database is provided (netctl does not ship one — MaxMind licensing).
func TestMMDBReader(t *testing.T) {
	path := os.Getenv("NETCTL_GEOIP_DB")
	if path == "" {
		t.Skip("set NETCTL_GEOIP_DB to a GeoLite2 .mmdb to test the MMDB reader")
	}
	r, err := OpenMMDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.LookupGeo(netip.MustParseAddr("8.8.8.8")); err != nil {
		t.Fatalf("lookup: %v", err)
	}
}
