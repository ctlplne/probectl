// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
)

const maxGeoTableFileBytes = 1 << 20

// Hop geolocation, guardrail-shaped: the ONLY source is a file the operator
// supplies (PROBECTL_HOP_GEO_FILE) — a JSON array of CIDR→location rows. No
// GeoIP service is ever contacted (§7.2), and unlike public GeoIP data the
// operator's own site table is authoritative for their private ranges, which
// is where most interesting hops live. Longest prefix wins. A malformed file
// fails closed at load time: the deployment starts with enrichment disabled
// rather than serving invented locations.

// GeoTableEntry is one operator-supplied mapping row.
type GeoTableEntry struct {
	CIDR    string  `json:"cidr"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"country,omitempty"`
}

type geoRow struct {
	prefix netip.Prefix
	geo    HopGeo
}

// GeoTable answers longest-prefix location lookups for responder IPs.
type GeoTable struct {
	rows []geoRow // sorted by prefix length, most specific first
}

// LoadGeoTable reads and validates the operator's mapping file. Any invalid
// row rejects the whole file (fail closed — a half-trusted table would serve
// half-invented maps).
func LoadGeoTable(file string) (*GeoTable, error) {
	raw, err := readGeoTableFile(file)
	if err != nil {
		return nil, fmt.Errorf("hop geo table: %w", err)
	}
	var entries []GeoTableEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("hop geo table: parse: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("hop geo table: no entries")
	}
	rows := make([]geoRow, 0, len(entries))
	for i, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("hop geo table: entry %d: cidr %q: %w", i, entry.CIDR, err)
		}
		if entry.Lat < -90 || entry.Lat > 90 || entry.Lon < -180 || entry.Lon > 180 {
			return nil, fmt.Errorf("hop geo table: entry %d: lat/lon out of range", i)
		}
		rows = append(rows, geoRow{
			prefix: prefix.Masked(),
			geo: HopGeo{
				Lat:     entry.Lat,
				Lon:     entry.Lon,
				City:    entry.City,
				Country: entry.Country,
				Source:  "operator-table",
			},
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].prefix.Bits() > rows[j].prefix.Bits() })
	return &GeoTable{rows: rows}, nil
}

func readGeoTableFile(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxGeoTableFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maxGeoTableFileBytes {
		return nil, fmt.Errorf("file exceeds %d-byte limit", maxGeoTableFileBytes)
	}
	return raw, nil
}

// Lookup returns the most specific matching location, or nil. Private ranges
// match like any other — the operator's table is authoritative for their own
// address plan.
func (t *GeoTable) Lookup(ip string) *HopGeo {
	if t == nil {
		return nil
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	for _, row := range t.rows {
		if row.prefix.Contains(addr) {
			geo := row.geo
			return &geo
		}
	}
	return nil
}

// Enrich attaches locations to every responder the table can place. Existing
// Geo values (e.g. from a future agent-side source) are never overwritten.
func (t *GeoTable) Enrich(p *Path) {
	if t == nil || p == nil {
		return
	}
	for hi := range p.Hops {
		for ni := range p.Hops[hi].Nodes {
			node := &p.Hops[hi].Nodes[ni]
			if node.Geo == nil {
				node.Geo = t.Lookup(node.IP)
			}
		}
	}
}
