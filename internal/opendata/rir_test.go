package opendata

import (
	"context"
	"net/netip"
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
