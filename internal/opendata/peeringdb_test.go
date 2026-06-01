package opendata

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

const pdbNetixlan = `{"data":[
  {"ix_id":31,"name":"DE-CIX Frankfurt","ipaddr4":"80.81.192.1","ipaddr6":"2001:7f8::1","speed":100000},
  {"ix_id":18,"name":"AMS-IX","ipaddr4":"80.249.208.1","ipaddr6":"","speed":40000}
]}`

func TestPeeringDBEnrichAndCache(t *testing.T) {
	doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.String(), "asn=13335") {
			t.Errorf("unexpected url %s", req.URL)
		}
		return jsonResp(http.StatusOK, pdbNetixlan), nil
	}}
	s := NewPeeringDB(doer)

	e := &Enrichment{ASN: 13335}
	if err := s.Enrich(context.Background(), netip.Addr{}, e); err != nil {
		t.Fatal(err)
	}
	if len(e.IXPs) != 2 || e.IXPs[0].Name != "DE-CIX Frankfurt" || e.IXPs[0].IXID != 31 || e.IXPs[0].SpeedM != 100000 {
		t.Fatalf("ixps = %+v", e.IXPs)
	}
	if len(e.Sources) != 1 || e.Sources[0].Source != "peeringdb" {
		t.Errorf("provenance = %+v", e.Sources)
	}

	// A second lookup of the same ASN is served from cache (no extra HTTP call).
	if err := s.Enrich(context.Background(), netip.Addr{}, &Enrichment{ASN: 13335}); err != nil {
		t.Fatal(err)
	}
	if doer.calls != 1 {
		t.Errorf("expected 1 HTTP call (cached), got %d", doer.calls)
	}
}

func TestPeeringDBNoASNSkips(t *testing.T) {
	doer := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		t.Fatal("PeeringDB must not be queried without an ASN")
		return nil, nil
	}}
	if err := NewPeeringDB(doer).Enrich(context.Background(), netip.Addr{}, &Enrichment{ASN: 0}); err != nil {
		t.Fatal(err)
	}
	if doer.calls != 0 {
		t.Errorf("expected 0 calls, got %d", doer.calls)
	}
}

func TestPeeringDBErrorStatus(t *testing.T) {
	doer := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusServiceUnavailable, ""), nil
	}}
	if err := NewPeeringDB(doer).Enrich(context.Background(), netip.Addr{}, &Enrichment{ASN: 1}); err == nil {
		t.Fatal("a non-200 status should error")
	}
}
