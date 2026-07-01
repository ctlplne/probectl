// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

const testJA3 = "0123456789abcdef0123456789abcdef"

// the real IOC store is used here (not a mock) so the S27↔S28 tie is exercised
// end-to-end: a captured leaf's SHA1 + the client JA3 are matched against feeds.
func TestAnalyzeThreatIntelCertAndJA3(t *testing.T) {
	leaf := cert(t, crypto.TestCertOptions{CommonName: "evil.example", DNSNames: []string{"evil.example"}, NotAfter: time.Now().Add(365 * 24 * time.Hour)})
	sha1 := crypto.CertSHA1(leaf)

	store := opendata.NewIOCStore()
	store.Load([]opendata.IOC{
		{Type: opendata.IOCTypeCertSHA1, Value: sha1, Source: "sslbl", Category: opendata.CategoryMaliciousCert, Confidence: 95, License: "abuse.ch CC0"},
		{Type: opendata.IOCTypeJA3, Value: testJA3, Source: "sslbl_ja3", Category: opendata.CategoryMaliciousJA3, Confidence: 85, License: "abuse.ch CC0"},
	})

	a := NewAnalyzer(Config{}, nil).WithIntel(store)
	p := a.Analyze(context.Background(), TLSObservation{
		Target: "evil.example", Source: "http", TLSVersion: "1.3", Cipher: "TLS_AES_128_GCM_SHA256",
		JA3:  "0123456789ABCDEF0123456789ABCDEF", // uppercase → still matches (store lowercases)
		Leaf: leaf, ObservedAt: time.Now(),
	})

	if !hasKind(p.Findings, FindingMaliciousCert) || !hasKind(p.Findings, FindingMaliciousJA3) {
		t.Fatalf("want malicious_cert + malicious_ja3, got %+v", p.Findings)
	}
	if p.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", p.Severity)
	}
	// a malicious-cert finding is NOT a renewal case → no trustctl handoff
	if p.Handoff != nil {
		t.Errorf("malicious cert should not produce a renewal handoff: %+v", p.Handoff)
	}

	var cf, jf Finding
	for _, f := range p.Findings {
		if f.Kind == FindingMaliciousCert {
			cf = f
		}
		if f.Kind == FindingMaliciousJA3 {
			jf = f
		}
	}
	if cf.Source != "sslbl" || cf.Type != string(opendata.IOCTypeCertSHA1) ||
		cf.Category != opendata.CategoryMaliciousCert || cf.License != "abuse.ch CC0" ||
		cf.Confidence != 95 || cf.Indicator != sha1 {
		t.Errorf("cert finding provenance = %+v", cf)
	}
	if jf.Source != "sslbl_ja3" || jf.Type != string(opendata.IOCTypeJA3) ||
		jf.Category != opendata.CategoryMaliciousJA3 || jf.License != "abuse.ch CC0" ||
		jf.Confidence != 85 || jf.Indicator != testJA3 {
		t.Errorf("JA3 finding provenance = %+v", jf)
	}

	// signals carry intel.* provenance so an analyst can see/why and tune it
	sigs := ToSignals("tenant-a", p)
	foundCert, foundJA3 := false, false
	for _, s := range sigs {
		if s.Kind == "tls.malicious_cert" {
			foundCert = true
			if s.Attributes["intel.source"] != "sslbl" ||
				s.Attributes["intel.type"] != string(opendata.IOCTypeCertSHA1) ||
				s.Attributes["intel.category"] != opendata.CategoryMaliciousCert ||
				s.Attributes["intel.license"] != "abuse.ch CC0" ||
				s.Attributes["intel.confidence"] != "95" || s.Attributes["intel.indicator"] != sha1 {
				t.Errorf("signal intel attrs = %+v", s.Attributes)
			}
		}
		if s.Kind == "tls.malicious_ja3" {
			foundJA3 = true
			if s.Attributes["intel.source"] != "sslbl_ja3" ||
				s.Attributes["intel.type"] != string(opendata.IOCTypeJA3) ||
				s.Attributes["intel.category"] != opendata.CategoryMaliciousJA3 ||
				s.Attributes["intel.license"] != "abuse.ch CC0" ||
				s.Attributes["intel.confidence"] != "85" || s.Attributes["intel.indicator"] != testJA3 {
				t.Errorf("JA3 signal intel attrs = %+v", s.Attributes)
			}
		}
	}
	if !foundCert || !foundJA3 {
		t.Errorf("missing intel signals: cert=%v ja3=%v", foundCert, foundJA3)
	}
}

func TestAnalyzeThreatIntelNoMatch(t *testing.T) {
	leaf := cert(t, crypto.TestCertOptions{CommonName: "good.example", DNSNames: []string{"good.example"}, NotAfter: time.Now().Add(365 * 24 * time.Hour)})
	store := opendata.NewIOCStore()
	store.Load([]opendata.IOC{{Type: opendata.IOCTypeCertSHA1, Value: "ffffffffffffffffffffffffffffffffffffffff", Source: "sslbl", Confidence: 95}})

	a := NewAnalyzer(Config{}, nil).WithIntel(store)
	p := a.Analyze(context.Background(), TLSObservation{Target: "good.example", TLSVersion: "1.3", Cipher: "TLS_AES_128_GCM_SHA256", JA3: "deadbeefdeadbeefdeadbeefdeadbeef", Leaf: leaf, ObservedAt: time.Now()})
	if hasKind(p.Findings, FindingMaliciousCert) || hasKind(p.Findings, FindingMaliciousJA3) {
		t.Errorf("a clean cert/JA3 must not match IOCs: %+v", p.Findings)
	}
}

func TestAnalyzeNilIntelDisabled(t *testing.T) {
	leaf := cert(t, crypto.TestCertOptions{CommonName: "x.example", DNSNames: []string{"x.example"}, NotAfter: time.Now().Add(365 * 24 * time.Hour)})
	a := NewAnalyzer(Config{}, nil) // no WithIntel → scoring disabled, must not panic
	p := a.Analyze(context.Background(), TLSObservation{Target: "x.example", TLSVersion: "1.3", Cipher: "TLS_AES_128_GCM_SHA256", JA3: testJA3, Leaf: leaf, ObservedAt: time.Now()})
	if hasKind(p.Findings, FindingMaliciousCert) || hasKind(p.Findings, FindingMaliciousJA3) {
		t.Errorf("nil intel must not produce IOC findings: %+v", p.Findings)
	}
}

// JA3 is matched even when no leaf cert was captured (client fingerprint is
// independent of the server cert).
func TestAnalyzeThreatIntelJA3WithoutLeaf(t *testing.T) {
	store := opendata.NewIOCStore()
	store.Load([]opendata.IOC{{Type: opendata.IOCTypeJA3, Value: testJA3, Source: "sslbl_ja3", Category: opendata.CategoryMaliciousJA3, Confidence: 85}})
	a := NewAnalyzer(Config{}, nil).WithIntel(store)
	p := a.Analyze(context.Background(), TLSObservation{Target: "noleaf.example", TLSVersion: "1.3", Cipher: "TLS_AES_128_GCM_SHA256", JA3: testJA3, ObservedAt: time.Now()})
	if !hasKind(p.Findings, FindingMaliciousJA3) {
		t.Errorf("want malicious_ja3 without a leaf, got %+v", p.Findings)
	}
}
