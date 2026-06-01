package opendata

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestCymruOriginName(t *testing.T) {
	if got := cymruOriginName(netip.MustParseAddr("1.2.3.4")); got != "4.3.2.1.origin.asn.cymru.com" {
		t.Errorf("v4 name = %q", got)
	}
	v6 := cymruOriginName(netip.MustParseAddr("2001:db8::1"))
	if !strings.HasSuffix(v6, ".origin6.asn.cymru.com") {
		t.Errorf("v6 name = %q, want origin6 zone", v6)
	}
	if !strings.HasPrefix(v6, "1.0.0.0.") { // last nibble of ::1 reversed first
		t.Errorf("v6 name = %q, want reversed-nibble prefix", v6)
	}
}

func TestParseCymruOrigin(t *testing.T) {
	asn, prefix, cc, reg, ok := parseCymruOrigin([]string{"23028 13335 | 1.1.1.0/24 | US | arin | 2010-07-14"})
	if !ok || asn != 23028 || prefix != "1.1.1.0/24" || cc != "US" || reg != "arin" {
		t.Fatalf("got asn=%d prefix=%q cc=%q reg=%q ok=%v", asn, prefix, cc, reg, ok)
	}
	if _, _, _, _, ok := parseCymruOrigin([]string{"garbage"}); ok {
		t.Error("malformed record should not parse")
	}
	if _, _, _, _, ok := parseCymruOrigin(nil); ok {
		t.Error("empty txts should not parse")
	}
}

func TestCymruEnrich(t *testing.T) {
	res := fakeResolver{txts: map[string][]string{
		"4.3.2.1.origin.asn.cymru.com": {"13335 | 1.1.1.0/24 | US | arin | 2010-07-14"},
		"AS13335.asn.cymru.com":        {"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"},
	}}
	e := &Enrichment{IP: "1.2.3.4"}
	if err := NewCymru(res).Enrich(context.Background(), netip.MustParseAddr("1.2.3.4"), e); err != nil {
		t.Fatal(err)
	}
	if e.ASN != 13335 || e.Prefix != "1.1.1.0/24" || e.CountryCode != "US" || e.RIR != "arin" {
		t.Errorf("enrichment = %+v", e)
	}
	if e.ASName != "CLOUDFLARENET, US" {
		t.Errorf("as_name = %q", e.ASName)
	}
	if len(e.Sources) != 1 || e.Sources[0].Source != "team-cymru" {
		t.Errorf("provenance = %+v", e.Sources)
	}
}

func TestCymruResolverErrorPropagates(t *testing.T) {
	// A resolver error must surface so the Enricher can mark the source degraded.
	err := NewCymru(fakeResolver{err: errors.New("dns down")}).
		Enrich(context.Background(), netip.MustParseAddr("1.2.3.4"), &Enrichment{})
	if err == nil {
		t.Fatal("expected a lookup error")
	}
}

func TestCymruNoMappingIsNotAnError(t *testing.T) {
	e := &Enrichment{}
	if err := NewCymru(fakeResolver{txts: map[string][]string{}}).
		Enrich(context.Background(), netip.MustParseAddr("10.0.0.1"), e); err != nil {
		t.Fatalf("absence of data should not error: %v", err)
	}
	if e.ASN != 0 || len(e.Sources) != 0 {
		t.Errorf("no data should add nothing: %+v", e)
	}
}
