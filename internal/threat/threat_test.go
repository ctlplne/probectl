package threat

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func cert(t *testing.T, o crypto.TestCertOptions) *x509.Certificate {
	t.Helper()
	c, _, err := crypto.GenerateTestCert(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasKind(findings []Finding, k FindingKind) bool {
	for _, f := range findings {
		if f.Kind == k {
			return true
		}
	}
	return false
}

func TestAnalyzeExpiredExpiringHealthy(t *testing.T) {
	a := NewAnalyzer(Config{ExpiryWarning: 21 * 24 * time.Hour, CertctlURL: "https://certctl.example"}, nil)
	now := time.Now()

	expired := cert(t, crypto.TestCertOptions{CommonName: "old.example", DNSNames: []string{"old.example"}, NotAfter: now.Add(-time.Hour)})
	p := a.Analyze(context.Background(), TLSObservation{Target: "old.example", TLSVersion: "1.3", Cipher: "TLS_AES_128_GCM_SHA256", Leaf: expired, ObservedAt: now})
	if !hasKind(p.Findings, FindingExpired) || p.Severity != SeverityCritical {
		t.Errorf("expired cert should be a critical finding, got %+v", p)
	}
	if p.Handoff == nil || p.Handoff.URL == "" || !strings.Contains(p.Handoff.URL, "old.example") {
		t.Errorf("expired cert should offer a certctl handoff to the domain, got %+v", p.Handoff)
	}

	exp := cert(t, crypto.TestCertOptions{CommonName: "soon.example", DNSNames: []string{"soon.example"}, NotAfter: now.Add(10 * 24 * time.Hour)})
	if p := a.Analyze(context.Background(), TLSObservation{Target: "soon.example", TLSVersion: "1.3", Leaf: exp, ObservedAt: now}); !hasKind(p.Findings, FindingExpiringSoon) {
		t.Errorf("cert within the expiry window should be expiring_soon, got %+v", p.Findings)
	}

	good := cert(t, crypto.TestCertOptions{CommonName: "good.example", DNSNames: []string{"good.example"}, NotAfter: now.Add(365 * 24 * time.Hour)})
	p = a.Analyze(context.Background(), TLSObservation{Target: "good.example", TLSVersion: "1.3", Cipher: "TLS_AES_256_GCM_SHA384", Leaf: good, ObservedAt: now})
	if len(p.Findings) != 0 || p.Handoff != nil {
		t.Errorf("a healthy cert should have no findings or handoff, got %+v", p)
	}
}

func TestAnalyzeSelfSignedWeakKeyProtocolCipher(t *testing.T) {
	a := NewAnalyzer(Config{}, nil)
	now := time.Now()

	ss := cert(t, crypto.TestCertOptions{CommonName: "self.example", DNSNames: []string{"self.example"}, SelfSigned: true})
	p := a.Analyze(context.Background(), TLSObservation{Target: "self.example", TLSVersion: "1.0", Cipher: "TLS_RSA_WITH_RC4_128_SHA", Leaf: ss, ObservedAt: now})
	for _, want := range []FindingKind{FindingSelfSigned, FindingDeprecatedTLS, FindingWeakCipher} {
		if !hasKind(p.Findings, want) {
			t.Errorf("expected %s, got %+v", want, p.Findings)
		}
	}

	weak := cert(t, crypto.TestCertOptions{CommonName: "weak.example", DNSNames: []string{"weak.example"}, RSABits: 1024})
	if p := a.Analyze(context.Background(), TLSObservation{Target: "weak.example", TLSVersion: "1.2", Leaf: weak, ObservedAt: now}); !hasKind(p.Findings, FindingWeakKey) {
		t.Errorf("a 1024-bit RSA key should be weak_key, got %+v", p.Findings)
	}
}

func TestAnalyzeUntrustedChain(t *testing.T) {
	no := false
	p := NewAnalyzer(Config{}, nil).Analyze(context.Background(),
		TLSObservation{Target: "x", TLSVersion: "1.2", Verified: &no, ObservedAt: time.Now()})
	if !hasKind(p.Findings, FindingUntrustedChain) || p.Severity != SeverityCritical {
		t.Errorf("an unverified chain should be a critical finding, got %+v", p)
	}
}

type fakeCT struct {
	finding Finding
	ok      bool
}

func (f fakeCT) Check(context.Context, *x509.Certificate) (Finding, bool) { return f.finding, f.ok }

func TestAnalyzeCTCorrelation(t *testing.T) {
	a := NewAnalyzer(Config{}, fakeCT{finding: Finding{Kind: FindingCTNotLogged, Severity: SeverityInfo, Message: "not in CT"}, ok: true})
	c := cert(t, crypto.TestCertOptions{CommonName: "ct.example", DNSNames: []string{"ct.example"}})
	if p := a.Analyze(context.Background(), TLSObservation{Target: "ct.example", TLSVersion: "1.3", Leaf: c, ObservedAt: time.Now()}); !hasKind(p.Findings, FindingCTNotLogged) {
		t.Errorf("the CT checker's anomaly should appear in findings, got %+v", p.Findings)
	}
}

func TestCrtShGraceful(t *testing.T) {
	leaf := cert(t, crypto.TestCertOptions{CommonName: "crtsh.example"})

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer empty.Close()
	if f, ok := (&CrtSh{endpoint: empty.URL, client: empty.Client()}).Check(context.Background(), leaf); !ok || f.Kind != FindingCTNotLogged {
		t.Errorf("a serial absent from CT should be ct_not_logged, got %v/%v", f, ok)
	}

	logged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[{"id":1}]`)) }))
	defer logged.Close()
	if _, ok := (&CrtSh{endpoint: logged.URL, client: logged.Client()}).Check(context.Background(), leaf); ok {
		t.Error("a logged cert should yield no finding")
	}

	// A down / unreachable CT source degrades gracefully (no finding, no error).
	if _, ok := NewCrtSh("https://127.0.0.1:1", time.Second).Check(context.Background(), leaf); ok {
		t.Error("an unreachable CT source must degrade gracefully")
	}
}

func TestFromCanaryAttributes(t *testing.T) {
	now := time.Now()
	c := cert(t, crypto.TestCertOptions{CommonName: "obs.example", DNSNames: []string{"obs.example"}})
	attrs := map[string]string{
		"tls.protocol.version": "1.2",
		"tls.cipher":           "TLS_AES_128_GCM_SHA256",
		"tls.server.verified":  "true",
		"tls.server.cert":      base64.StdEncoding.EncodeToString(c.Raw),
	}
	obs, ok := FromCanaryAttributes("obs.example", attrs, now)
	if !ok || obs.TLSVersion != "1.2" || obs.Leaf == nil || obs.Verified == nil || !*obs.Verified {
		t.Fatalf("observation = %+v ok=%v", obs, ok)
	}
	if obs.Leaf.Subject.CommonName != "obs.example" {
		t.Errorf("leaf CN = %s", obs.Leaf.Subject.CommonName)
	}
	if _, ok := FromCanaryAttributes("x", map[string]string{}, now); ok {
		t.Error("a result with no TLS attributes must yield no observation")
	}
}

func TestToSignals(t *testing.T) {
	p := Posture{
		Target: "x", Source: "http", TLSVersion: "1.0",
		Findings:   []Finding{{Kind: FindingDeprecatedTLS, Severity: SeverityWarning, Message: "deprecated TLS version 1.0"}},
		Handoff:    &HandoffPayload{URL: "https://certctl.example/renew?domain=x"},
		ObservedAt: time.Now(),
	}
	sigs := ToSignals("tenant-a", p)
	if len(sigs) != 1 || sigs[0].Plane != "threat" || sigs[0].Kind != "tls.deprecated_protocol" || sigs[0].TenantID != "tenant-a" {
		t.Errorf("signal = %+v", sigs)
	}
	if sigs[0].Attributes["certctl.handoff_url"] == "" {
		t.Error("the certctl handoff URL should be carried in the signal attributes")
	}
	if ToSignals("t", Posture{}) != nil {
		t.Error("a clean posture should emit no signals")
	}
}
