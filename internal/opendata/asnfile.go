// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ASNFile resolves an IP to its origin ASN from an operator-supplied LOCAL
// file, so ASN enrichment works air-gapped — with NO Team Cymru DNS lookup and
// no outbound call (docs/guardrails.md G7-2). The file is the MaxMind
// GeoLite2-ASN CSV edition, or any compatible CSV whose rows are
//
//	network,autonomous_system_number,autonomous_system_organization
//
// (a CIDR, an AS number, and an optional AS name). probectl never ships or
// fetches it — the operator supplies it, exactly like the geo .mmdb and the
// RIR stats. The file is UNTRUSTED input: it is parsed once into an in-memory
// prefix index (ingest once, serve from memory — S15), malformed rows are
// skipped, and lookups never fail. The CIDR is also surfaced as the matched
// prefix.
type ASNFile struct {
	v4 []asnV4Range
	v6 []asnV6Entry
}

type asnMeta struct {
	asn    uint32
	name   string
	prefix string // the matched network, for provenance / Enrichment.Prefix
}

type asnV4Range struct {
	lo, hi uint32
	asnMeta
}

type asnV6Entry struct {
	prefix netip.Prefix
	asnMeta
}

// NewASNFile returns an empty index. Load one with LoadASNFile; an empty index
// is used to register a configured-but-unavailable source for visibility.
func NewASNFile() *ASNFile { return &ASNFile{} }

// LoadASNFile builds an IP→ASN index from a local CSV file. An unreadable
// file, or a file with no usable rows, is an error so a misconfigured path
// cannot register a silently empty source (it registers "unavailable"
// instead).
func LoadASNFile(path string) (*ASNFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opendata: open asn file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	a := NewASNFile()
	if err := a.Load(f); err != nil {
		return nil, fmt.Errorf("opendata: load asn file %q: %w", path, err)
	}
	if a.Size() == 0 {
		return nil, fmt.Errorf("opendata: asn file %q contains no usable IP→ASN rows", path)
	}
	return a, nil
}

// Size reports the number of indexed prefixes (v4 ranges + v6 prefixes).
func (a *ASNFile) Size() int { return len(a.v4) + len(a.v6) }

// Load streams a GeoLite2-ASN-style CSV into the index. Blank lines, comments,
// the header row, and malformed rows are skipped (untrusted input).
func (a *ASNFile) Load(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitCSVLine(line)
		if len(fields) < 2 {
			continue
		}
		network := strings.TrimSpace(fields[0])
		if network == "" || strings.EqualFold(network, "network") { // header row
			continue
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(fields[1])), "AS"), 10, 32)
		if err != nil {
			continue
		}
		name := ""
		if len(fields) >= 3 {
			name = strings.TrimSpace(fields[2])
		}
		a.add(network, uint32(asn), name)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("opendata: read asn file: %w", err)
	}
	sort.Slice(a.v4, func(i, j int) bool { return a.v4[i].lo < a.v4[j].lo })
	return nil
}

func (a *ASNFile) add(network string, asn uint32, name string) {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return
	}
	prefix = prefix.Masked()
	meta := asnMeta{asn: asn, name: name, prefix: prefix.String()}
	if prefix.Addr().Is4() {
		b := prefix.Addr().As4()
		lo := binary.BigEndian.Uint32(b[:])
		bits := prefix.Bits()
		var hi uint32
		if bits <= 0 {
			hi = ^uint32(0)
		} else {
			hi = lo + (uint32(1)<<uint(32-bits) - 1)
		}
		if hi < lo { // overflow guard (untrusted input)
			return
		}
		a.v4 = append(a.v4, asnV4Range{lo: lo, hi: hi, asnMeta: meta})
		return
	}
	a.v6 = append(a.v6, asnV6Entry{prefix: prefix, asnMeta: meta})
}

func (a *ASNFile) Descriptor() Descriptor {
	return Descriptor{
		Name:    "asn-file",
		Kind:    KindASN,
		Cadence: 24 * time.Hour,
		AUP: AUP{
			License:        "Operator-supplied local IP→ASN file (e.g. the MaxMind GeoLite2-ASN CSV)",
			URL:            "https://dev.maxmind.com/geoip/docs/databases/asn",
			Attribution:    "When the MaxMind GeoLite2-ASN dataset is used: this product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com",
			CommercialUse:  CommercialRestricted,
			Redistribution: "Operator-supplied; the source dataset's own terms (e.g. the MaxMind GeoLite EULA) govern sharing, resale, or redistribution",
		},
	}
}

func (a *ASNFile) Enrich(_ context.Context, addr netip.Addr, e *Enrichment) error {
	meta, ok := a.lookup(addr)
	if !ok {
		return nil // no mapping for this IP — absence is not a failure
	}
	fields := []string{"asn"}
	if e.ASN == 0 {
		e.ASN = meta.asn
	}
	if e.Prefix == "" && meta.prefix != "" {
		e.Prefix = meta.prefix
		fields = append(fields, "prefix")
	}
	if e.ASName == "" && meta.name != "" {
		e.ASName = meta.name
		fields = append(fields, "as_name")
	}
	e.addProvenance(a.Descriptor(), fields...)
	return nil
}

// lookup returns the ASN metadata for the most-specific covering prefix.
func (a *ASNFile) lookup(addr netip.Addr) (asnMeta, bool) {
	if addr.Is4() {
		b := addr.As4()
		target := binary.BigEndian.Uint32(b[:])
		// First range whose lo > target; the candidate is the one before it
		// (GeoLite2-ASN blocks are disjoint, so at most one contains target).
		i := sort.Search(len(a.v4), func(i int) bool { return a.v4[i].lo > target })
		if i > 0 && a.v4[i-1].lo <= target && target <= a.v4[i-1].hi {
			return a.v4[i-1].asnMeta, true
		}
		return asnMeta{}, false
	}
	best := -1
	bestBits := -1
	for i, ent := range a.v6 {
		if ent.prefix.Contains(addr) && ent.prefix.Bits() > bestBits {
			best, bestBits = i, ent.prefix.Bits()
		}
	}
	if best < 0 {
		return asnMeta{}, false
	}
	return a.v6[best].asnMeta, true
}

// splitCSVLine splits one CSV line on commas, honoring double-quoted fields
// (a MaxMind AS organization can contain commas). It is deliberately small —
// the file is untrusted and only the first three fields are read.
func splitCSVLine(line string) []string {
	var fields []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			if inQuote && i+1 < len(line) && line[i+1] == '"' { // escaped quote
				b.WriteByte('"')
				i++
			} else {
				inQuote = !inQuote
			}
		case c == ',' && !inQuote:
			fields = append(fields, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	fields = append(fields, b.String())
	return fields
}
