package opendata

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RIRAllocations indexes the RIRs' delegated-extended statistics — the
// authoritative map of which RIR allocated a block, to which country, and its
// status. The file is parsed once into a sorted index (ingest once, then serve
// from memory — S15) and is bounds-checked as untrusted input.
//
// Record format (pipe-separated):
//
//	registry|cc|type|start|value|date|status[|opaque-id]
//
// For ipv4, start is the first address and value the address count; for ipv6,
// start is the prefix and value the prefix length.
type RIRAllocations struct {
	v4 []v4Range
	v6 []v6Entry
}

type allocMeta struct {
	cc       string
	registry string
	status   string
	date     string
}

type v4Range struct {
	lo, hi uint32
	allocMeta
}

type v6Entry struct {
	prefix netip.Prefix
	allocMeta
}

// NewRIRAllocations returns an empty index; load one or more RIR stats files with
// Load (loading several RIRs builds a global allocation view).
func NewRIRAllocations() *RIRAllocations { return &RIRAllocations{} }

// Load streams a delegated-extended stats file into the index.
func (s *RIRAllocations) Load(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 {
			continue
		}
		registry, cc, typ, start, value, date, status := f[0], f[1], f[2], f[3], f[4], f[5], f[6]
		if start == "*" || cc == "*" { // version / summary header lines
			continue
		}
		meta := allocMeta{cc: strings.ToUpper(cc), registry: strings.ToLower(registry), status: status, date: date}
		switch typ {
		case "ipv4":
			s.loadV4(start, value, meta)
		case "ipv6":
			s.loadV6(start, value, meta)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("opendata: read rir stats: %w", err)
	}
	sort.Slice(s.v4, func(i, j int) bool { return s.v4[i].lo < s.v4[j].lo })
	return nil
}

func (s *RIRAllocations) loadV4(start, value string, meta allocMeta) {
	addr, err := netip.ParseAddr(start)
	if err != nil || !addr.Is4() {
		return
	}
	count, err := strconv.ParseUint(value, 10, 32)
	if err != nil || count == 0 {
		return
	}
	b := addr.As4()
	lo := binary.BigEndian.Uint32(b[:])
	hi := lo + uint32(count-1)
	if hi < lo { // overflow guard (untrusted input)
		return
	}
	s.v4 = append(s.v4, v4Range{lo: lo, hi: hi, allocMeta: meta})
}

func (s *RIRAllocations) loadV6(start, value string, meta allocMeta) {
	prefix, err := netip.ParsePrefix(start + "/" + value)
	if err != nil {
		return
	}
	s.v6 = append(s.v6, v6Entry{prefix: prefix.Masked(), allocMeta: meta})
}

func (s *RIRAllocations) Descriptor() Descriptor {
	return Descriptor{
		Name:    "rir-stats",
		Kind:    KindAllocation,
		Cadence: 24 * time.Hour,
		AUP: AUP{
			License:       "RIR delegated statistics (open data)",
			URL:           "https://www.nro.net/about/rirs/statistics/",
			CommercialUse: CommercialAllowed,
		},
	}
}

func (s *RIRAllocations) Enrich(_ context.Context, addr netip.Addr, e *Enrichment) error {
	meta, ok := s.lookup(addr)
	if !ok {
		return nil
	}
	fields := []string{"rir", "allocation_status"}
	if e.RIR == "" {
		e.RIR = meta.registry
	}
	if e.AllocationStatus == "" {
		e.AllocationStatus = meta.status
	}
	if e.AllocationDate == "" && meta.date != "" {
		e.AllocationDate = meta.date
		fields = append(fields, "allocation_date")
	}
	if e.CountryCode == "" && meta.cc != "" {
		e.CountryCode = meta.cc
		fields = append(fields, "country_code")
	}
	e.addProvenance(s.Descriptor(), fields...)
	return nil
}

func (s *RIRAllocations) lookup(addr netip.Addr) (allocMeta, bool) {
	if addr.Is4() {
		b := addr.As4()
		target := binary.BigEndian.Uint32(b[:])
		// First range whose lo > target; the candidate is the one before it.
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].lo > target })
		if i > 0 && s.v4[i-1].lo <= target && target <= s.v4[i-1].hi {
			return s.v4[i-1].allocMeta, true
		}
		return allocMeta{}, false
	}
	// IPv6: most-specific covering prefix.
	best := -1
	bestBits := -1
	for i, ent := range s.v6 {
		if ent.prefix.Contains(addr) && ent.prefix.Bits() > bestBits {
			best, bestBits = i, ent.prefix.Bits()
		}
	}
	if best < 0 {
		return allocMeta{}, false
	}
	return s.v6[best].allocMeta, true
}
