package opendata

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// TestEnricherMergesAllPlanes is the S15 Done-when: an IP is enriched with
// ASN + geo + IXP + allocation from independent sources, each recording
// provenance, with PeeringDB keyed on the ASN a prior source resolved.
func TestEnricherMergesAllPlanes(t *testing.T) {
	en := NewEnricher(discardLogger())
	en.Register(&fakeSource{desc: Descriptor{Name: "asn", Kind: KindASN}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.ASN, e.ASName = 13335, "CLOUDFLARENET"
		e.addProvenance(Descriptor{Name: "asn"}, "asn")
		return nil
	}})
	en.Register(&fakeSource{desc: Descriptor{Name: "geo", Kind: KindGeo}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.CountryCode, e.City = "US", "San Francisco"
		e.addProvenance(Descriptor{Name: "geo"}, "geo")
		return nil
	}})
	en.Register(&fakeSource{desc: Descriptor{Name: "ixp", Kind: KindIXP}, fn: func(_ netip.Addr, e *Enrichment) error {
		if e.ASN == 0 { // depends on the ASN source running first
			return nil
		}
		e.IXPs = []IXP{{Name: "DE-CIX"}}
		e.addProvenance(Descriptor{Name: "ixp"}, "ixps")
		return nil
	}})
	en.Register(&fakeSource{desc: Descriptor{Name: "alloc", Kind: KindAllocation}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.RIR, e.AllocationStatus = "arin", "allocated"
		e.addProvenance(Descriptor{Name: "alloc"}, "alloc")
		return nil
	}})

	e, err := en.Enrich(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if e.ASN != 13335 || e.ASName != "CLOUDFLARENET" {
		t.Errorf("asn = %d/%q", e.ASN, e.ASName)
	}
	if e.CountryCode != "US" || e.City != "San Francisco" {
		t.Errorf("geo = %q/%q", e.CountryCode, e.City)
	}
	if len(e.IXPs) != 1 || e.IXPs[0].Name != "DE-CIX" {
		t.Errorf("ixps = %+v", e.IXPs)
	}
	if e.RIR != "arin" || e.AllocationStatus != "allocated" {
		t.Errorf("alloc = %q/%q", e.RIR, e.AllocationStatus)
	}
	if len(e.Sources) != 4 {
		t.Errorf("expected 4 provenance entries, got %d (%+v)", len(e.Sources), e.Sources)
	}
}

// TestEnricherDegradesOnFailure proves a failing source is logged + skipped and
// does NOT break enrichment (S15 Done-when, graceful degradation).
func TestEnricherDegradesOnFailure(t *testing.T) {
	en := NewEnricher(discardLogger())
	en.Register(&fakeSource{desc: Descriptor{Name: "good"}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.CountryCode = "US"
		return nil
	}})
	en.Register(&fakeSource{desc: Descriptor{Name: "bad"}, fn: func(_ netip.Addr, _ *Enrichment) error {
		return errors.New("upstream unavailable")
	}})

	e, err := en.Enrich(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("a source failure must not fail enrichment: %v", err)
	}
	if e.CountryCode != "US" {
		t.Error("the healthy source's contribution should still be present")
	}
	bad, _ := statusByName(en.Status(), "bad")
	if bad.Health.Status != "degraded" || bad.Health.LastError == "" {
		t.Errorf("bad source health = %+v, want degraded", bad.Health)
	}
	good, _ := statusByName(en.Status(), "good")
	if good.Health.Status != "ok" {
		t.Errorf("good source health = %+v, want ok", good.Health)
	}
}

func TestEnricherSkipsDisabledSource(t *testing.T) {
	en := NewEnricher(discardLogger(), WithCacheTTL(0))
	src := &fakeSource{desc: Descriptor{Name: "src"}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.CountryCode = "US"
		return nil
	}}
	en.Register(src)
	en.SetEnabled("src", false)

	e, err := en.Enrich(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if src.calls != 0 || e.CountryCode != "" {
		t.Errorf("disabled source ran: calls=%d e=%+v", src.calls, e)
	}
	st, _ := statusByName(en.Status(), "src")
	if st.Health.Enabled || st.Health.Status != "disabled" {
		t.Errorf("status = %+v, want disabled", st.Health)
	}
}

func TestEnricherCachesByIP(t *testing.T) {
	en := NewEnricher(discardLogger()) // default 1h TTL
	src := &fakeSource{desc: Descriptor{Name: "src"}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.CountryCode = "US"
		return nil
	}}
	en.Register(src)

	for i := 0; i < 3; i++ {
		if _, err := en.Enrich(context.Background(), "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
	}
	if src.calls != 1 {
		t.Errorf("expected 1 source call (cached), got %d", src.calls)
	}
}

func TestEnricherContainsPanic(t *testing.T) {
	en := NewEnricher(discardLogger())
	en.Register(&fakeSource{desc: Descriptor{Name: "panic"}, fn: func(_ netip.Addr, _ *Enrichment) error {
		panic("boom")
	}})
	en.Register(&fakeSource{desc: Descriptor{Name: "ok"}, fn: func(_ netip.Addr, e *Enrichment) error {
		e.CountryCode = "US"
		return nil
	}})

	e, err := en.Enrich(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatalf("a panicking source must not crash enrichment: %v", err)
	}
	if e.CountryCode != "US" {
		t.Error("the healthy source should still apply after a panic")
	}
	st, _ := statusByName(en.Status(), "panic")
	if st.Health.Status != "degraded" {
		t.Errorf("panicking source health = %+v, want degraded", st.Health)
	}
}

func TestEnricherInvalidIP(t *testing.T) {
	if _, err := NewEnricher(discardLogger()).Enrich(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("an invalid IP should error")
	}
}
