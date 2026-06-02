package threat

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
)

// Config tunes the analyzer.
type Config struct {
	ExpiryWarning time.Duration    // expiring_soon window (default 21 days)
	MinRSABits    int              // weak-key threshold for RSA (default 2048)
	CertctlURL    string           // certctl handoff base URL (empty → no deep-link)
	Now           func() time.Time // injectable clock (tests)
}

func (c Config) withDefaults() Config {
	if c.ExpiryWarning <= 0 {
		c.ExpiryWarning = 21 * 24 * time.Hour
	}
	if c.MinRSABits <= 0 {
		c.MinRSABits = 2048
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Analyzer analyzes captured TLS observations into posture findings. It does NOT
// re-handshake — it reuses already-captured data (S27 watch-out).
type Analyzer struct {
	cfg Config
	ct  CTChecker // optional; nil disables CT correlation
}

// NewAnalyzer builds an analyzer. ct may be nil (CT correlation disabled).
func NewAnalyzer(cfg Config, ct CTChecker) *Analyzer {
	return &Analyzer{cfg: cfg.withDefaults(), ct: ct}
}

// Analyze produces the TLS/cert posture for an observation.
func (a *Analyzer) Analyze(ctx context.Context, obs TLSObservation) Posture {
	now := a.cfg.Now()
	p := Posture{
		Target: obs.Target, Source: obs.Source, TLSVersion: obs.TLSVersion,
		Cipher: obs.Cipher, ObservedAt: obs.ObservedAt, Severity: SeverityInfo,
	}

	// Protocol + cipher posture (from the captured handshake).
	if v, ok := deprecatedTLS(obs.TLSVersion); ok {
		p.add(Finding{FindingDeprecatedTLS, SeverityWarning, "deprecated TLS version " + v})
	}
	if weakCipher(obs.Cipher) {
		p.add(Finding{FindingWeakCipher, SeverityWarning, "weak cipher suite " + obs.Cipher})
	}
	if obs.Verified != nil && !*obs.Verified {
		p.add(Finding{FindingUntrustedChain, SeverityCritical, "the certificate chain did not verify against the trust store"})
	}

	// Certificate posture (from the parsed leaf, when its DER was captured).
	if obs.Leaf != nil {
		cert := parseCert(obs.Leaf)
		p.Leaf = &cert
		switch {
		case now.After(cert.NotAfter):
			p.add(Finding{FindingExpired, SeverityCritical, "certificate expired on " + cert.NotAfter.UTC().Format(time.RFC3339)})
		case cert.NotAfter.Sub(now) <= a.cfg.ExpiryWarning:
			days := int(cert.NotAfter.Sub(now).Hours() / 24)
			p.add(Finding{FindingExpiringSoon, SeverityWarning, fmt.Sprintf("certificate expires in %d day(s)", days)})
		}
		if now.Before(cert.NotBefore) {
			p.add(Finding{FindingNotYetValid, SeverityWarning, "certificate is not yet valid"})
		}
		if cert.SelfSigned {
			p.add(Finding{FindingSelfSigned, SeverityWarning, "self-signed certificate"})
		}
		if cert.KeyType == "RSA" && cert.KeyBits > 0 && cert.KeyBits < a.cfg.MinRSABits {
			p.add(Finding{FindingWeakKey, SeverityWarning, fmt.Sprintf("weak RSA key (%d bits < %d)", cert.KeyBits, a.cfg.MinRSABits)})
		}
		if a.ct != nil {
			if f, ok := a.ct.Check(ctx, obs.Leaf); ok {
				p.add(f)
			}
		}
		if hasCertFinding(p.Findings) {
			p.Handoff = a.buildHandoff(obs.Target, cert, p.Findings)
		}
	}
	return p
}

func parseCert(c *x509.Certificate) Certificate {
	keyType, keyBits := crypto.CertKeyInfo(c)
	return Certificate{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SANs:               c.DNSNames,
		SerialNumber:       c.SerialNumber.String(),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		KeyType:            keyType,
		KeyBits:            keyBits,
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
		SelfSigned:         c.Subject.String() == c.Issuer.String(),
	}
}

func deprecatedTLS(v string) (string, bool) {
	switch v {
	case "1.0", "1.1":
		return v, true
	default:
		return "", false
	}
}

func weakCipher(name string) bool {
	u := strings.ToUpper(name)
	for _, w := range []string{"RC4", "3DES", "_DES_", "NULL", "EXPORT", "MD5", "ANON"} {
		if strings.Contains(u, w) {
			return true
		}
	}
	return false
}

// hasCertFinding reports whether any certificate-level (renewable/replaceable)
// finding is present — the ones a certctl handoff addresses.
func hasCertFinding(findings []Finding) bool {
	for _, f := range findings {
		switch f.Kind {
		case FindingExpired, FindingExpiringSoon, FindingNotYetValid, FindingSelfSigned, FindingWeakKey, FindingUntrustedChain:
			return true
		}
	}
	return false
}

func (a *Analyzer) buildHandoff(target string, cert Certificate, findings []Finding) *HandoffPayload {
	h := &HandoffPayload{
		Target:   target,
		Subject:  cert.Subject,
		Issuer:   cert.Issuer,
		SANs:     cert.SANs,
		Serial:   cert.SerialNumber,
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
		Reason:   handoffReason(findings),
	}
	if a.cfg.CertctlURL != "" {
		if u, err := url.Parse(strings.TrimRight(a.cfg.CertctlURL, "/") + "/renew"); err == nil {
			q := u.Query()
			q.Set("domain", primaryDomain(cert))
			q.Set("serial", cert.SerialNumber)
			q.Set("reason", h.Reason)
			u.RawQuery = q.Encode()
			h.URL = u.String()
		}
	}
	return h
}

func handoffReason(findings []Finding) string {
	best := ""
	bestRank := 0
	for _, f := range findings {
		if !hasCertFinding([]Finding{f}) {
			continue
		}
		if sevRank(f.Severity) >= bestRank {
			best, bestRank = string(f.Kind), sevRank(f.Severity)
		}
	}
	return best
}

func primaryDomain(cert Certificate) string {
	if len(cert.SANs) > 0 {
		return cert.SANs[0]
	}
	// Fall back to the subject CN-ish leading component.
	if i := strings.Index(cert.Subject, "CN="); i >= 0 {
		rest := cert.Subject[i+3:]
		if j := strings.IndexByte(rest, ','); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return cert.Subject
}
