package threat

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

// CertIntel scores a leaf certificate's SHA1 fingerprint and/or a client JA3
// fingerprint against threat-intel IOCs (S28). The opendata IOC store satisfies
// this; a nil scorer disables IOC matching. Matches are confidence-scored signals
// with source attribution, never an inline block (guardrail 9).
type CertIntel interface {
	ScoreCert(sha1, ja3 string) []opendata.IOCMatch
}

// Config tunes the analyzer.
type Config struct {
	ExpiryWarning time.Duration    // expiring_soon window (default 21 days)
	MinRSABits    int              // weak-key threshold for RSA (default 2048)
	TrustctlURL   string           // trustctl handoff base URL (empty → no deep-link)
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
	cfg   Config
	ct    CTChecker // optional; nil disables CT correlation
	intel CertIntel // optional; nil disables threat-intel IOC scoring (S28)
}

// NewAnalyzer builds an analyzer. ct may be nil (CT correlation disabled).
func NewAnalyzer(cfg Config, ct CTChecker) *Analyzer {
	return &Analyzer{cfg: cfg.withDefaults(), ct: ct}
}

// WithIntel attaches an optional threat-intel cert/JA3 scorer (S28) and returns
// the analyzer for chaining. A nil scorer leaves IOC matching disabled.
func (a *Analyzer) WithIntel(intel CertIntel) *Analyzer {
	a.intel = intel
	return a
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
		p.add(Finding{Kind: FindingDeprecatedTLS, Severity: SeverityWarning, Message: "deprecated TLS version " + v})
	}
	if weakCipher(obs.Cipher) {
		p.add(Finding{Kind: FindingWeakCipher, Severity: SeverityWarning, Message: "weak cipher suite " + obs.Cipher})
	}
	if obs.Verified != nil && !*obs.Verified {
		p.add(Finding{Kind: FindingUntrustedChain, Severity: SeverityCritical, Message: "the certificate chain did not verify against the trust store"})
	}

	// Certificate posture (from the parsed leaf, when its DER was captured).
	if obs.Leaf != nil {
		cert := parseCert(obs.Leaf)
		p.Leaf = &cert
		switch {
		case now.After(cert.NotAfter):
			p.add(Finding{Kind: FindingExpired, Severity: SeverityCritical, Message: "certificate expired on " + cert.NotAfter.UTC().Format(time.RFC3339)})
		case cert.NotAfter.Sub(now) <= a.cfg.ExpiryWarning:
			days := int(cert.NotAfter.Sub(now).Hours() / 24)
			p.add(Finding{Kind: FindingExpiringSoon, Severity: SeverityWarning, Message: fmt.Sprintf("certificate expires in %d day(s)", days)})
		}
		if now.Before(cert.NotBefore) {
			p.add(Finding{Kind: FindingNotYetValid, Severity: SeverityWarning, Message: "certificate is not yet valid"})
		}
		if cert.SelfSigned {
			p.add(Finding{Kind: FindingSelfSigned, Severity: SeverityWarning, Message: "self-signed certificate"})
		}
		if cert.KeyType == "RSA" && cert.KeyBits > 0 && cert.KeyBits < a.cfg.MinRSABits {
			p.add(Finding{Kind: FindingWeakKey, Severity: SeverityWarning, Message: fmt.Sprintf("weak RSA key (%d bits < %d)", cert.KeyBits, a.cfg.MinRSABits)})
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

	// Threat-intel: match the leaf cert SHA1 and/or the client JA3 against IOCs
	// (S28). Runs after leaf parse so the signal carries cert context. A match is a
	// confidence-scored signal with source attribution — NOT an inline block.
	if a.intel != nil {
		sha1 := ""
		if obs.Leaf != nil {
			sha1 = crypto.CertSHA1(obs.Leaf)
		}
		for _, m := range a.intel.ScoreCert(sha1, obs.JA3) {
			p.add(intelFinding(m))
		}
	}
	return p
}

// intelFinding maps a threat-intel IOC match to a critical posture finding,
// preserving the feed's source + confidence for downstream signal attribution.
func intelFinding(m opendata.IOCMatch) Finding {
	kind := FindingMaliciousJA3
	what := "client JA3"
	if m.Type == opendata.IOCTypeCertSHA1 {
		kind = FindingMaliciousCert
		what = "server certificate"
	}
	return Finding{
		Kind:       kind,
		Severity:   SeverityCritical,
		Message:    fmt.Sprintf("%s matches threat-intel indicator %s (%s) from %s", what, m.Indicator, m.Category, m.Source),
		Source:     m.Source,
		Confidence: m.Confidence,
		Indicator:  m.Indicator,
	}
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
// finding is present — the ones a trustctl handoff addresses.
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
	if a.cfg.TrustctlURL != "" {
		if u, err := url.Parse(strings.TrimRight(a.cfg.TrustctlURL, "/") + "/renew"); err == nil {
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
