package opendata

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// GeoReader resolves an IP to geographic context. It is injectable so the geo
// source is testable without a GeoLite2 database; the MaxMind MMDB-backed reader
// (OpenMMDB) is the production implementation.
type GeoReader interface {
	LookupGeo(addr netip.Addr) (GeoResult, bool, error)
}

// GeoResult is the geo context a reader returns.
type GeoResult struct {
	CountryCode string
	City        string
	Latitude    float64
	Longitude   float64
}

type geoSource struct {
	reader GeoReader
}

// NewGeo builds the MaxMind GeoLite2 geo source over the given reader.
func NewGeo(reader GeoReader) Source { return &geoSource{reader: reader} }

func (g *geoSource) Descriptor() Descriptor {
	return Descriptor{
		Name:    "maxmind-geolite2",
		Kind:    KindGeo,
		Cadence: 7 * 24 * time.Hour,
		AUP: AUP{
			License:       "GeoLite2 EULA (CC BY-SA 4.0 attribution)",
			URL:           "https://www.maxmind.com/en/geolite2/eula",
			Attribution:   "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com",
			CommercialUse: CommercialAttribution,
		},
	}
}

func (g *geoSource) Enrich(_ context.Context, addr netip.Addr, e *Enrichment) error {
	res, ok, err := g.reader.LookupGeo(addr)
	if err != nil {
		return fmt.Errorf("geo lookup: %w", err)
	}
	if !ok {
		return nil
	}
	var fields []string
	if e.CountryCode == "" && res.CountryCode != "" {
		e.CountryCode = res.CountryCode
		fields = append(fields, "country_code")
	}
	if e.City == "" && res.City != "" {
		e.City = res.City
		fields = append(fields, "city")
	}
	if e.Latitude == 0 && e.Longitude == 0 && (res.Latitude != 0 || res.Longitude != 0) {
		e.Latitude, e.Longitude = res.Latitude, res.Longitude
		fields = append(fields, "lat_lon")
	}
	if len(fields) > 0 {
		e.addProvenance(g.Descriptor(), fields...)
	}
	return nil
}

// --- MaxMind MMDB-backed reader (GeoLite2-City / -Country) ---

type mmdbGeoReader struct {
	db *maxminddb.Reader
}

// OpenMMDB opens a MaxMind .mmdb database for the geo source. The operator
// supplies the GeoLite2 database under MaxMind's license; probectl does not ship it
// (S15 watch-out — respect MaxMind licensing).
func OpenMMDB(path string) (GeoReader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opendata: open mmdb %q: %w", path, err)
	}
	return &mmdbGeoReader{db: db}, nil
}

// Close releases the underlying database.
func (m *mmdbGeoReader) Close() error { return m.db.Close() }

// geoLite2City is the subset of the GeoLite2-City record probectl reads.
type geoLite2City struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

func (m *mmdbGeoReader) LookupGeo(addr netip.Addr) (GeoResult, bool, error) {
	var rec geoLite2City
	if err := m.db.Lookup(net.IP(addr.AsSlice()), &rec); err != nil {
		return GeoResult{}, false, err
	}
	city := rec.City.Names["en"]
	if rec.Country.ISOCode == "" && city == "" && rec.Location.Latitude == 0 && rec.Location.Longitude == 0 {
		return GeoResult{}, false, nil // no record for this IP
	}
	return GeoResult{
		CountryCode: rec.Country.ISOCode,
		City:        city,
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
	}, true, nil
}
