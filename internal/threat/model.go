package threat

import (
	"crypto/x509"
	"time"
)

// Severity orders findings (mirrors incident severity).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

// Certificate is a parsed view of one X.509 certificate.
type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SANs               []string  `json:"sans,omitempty"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyType            string    `json:"key_type"`
	KeyBits            int       `json:"key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SelfSigned         bool      `json:"self_signed"`
	IsCA               bool      `json:"is_ca"`
}

// TLSObservation is captured TLS posture for a target — built from ALREADY-
// captured data (S13 HTTP synthetic / S21 eBPF L7), NEVER a fresh handshake.
type TLSObservation struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`      // "http" (S13) | "ebpf" (S21)
	TLSVersion string            `json:"tls_version"` // "1.3" | "1.2" | "1.1" | "1.0"
	Cipher     string            `json:"cipher"`
	Verified   *bool             `json:"verified,omitempty"` // chain verified by the capturer
	JA3        string            `json:"ja3,omitempty"`
	JA3S       string            `json:"ja3s,omitempty"`
	Leaf       *x509.Certificate `json:"-"` // the parsed leaf, when the DER was captured
	ObservedAt time.Time         `json:"observed_at"`
}

// FindingKind enumerates TLS/cert posture issues.
type FindingKind string

const (
	FindingExpired        FindingKind = "cert_expired"
	FindingExpiringSoon   FindingKind = "cert_expiring_soon"
	FindingNotYetValid    FindingKind = "cert_not_yet_valid"
	FindingSelfSigned     FindingKind = "cert_self_signed"
	FindingWeakKey        FindingKind = "weak_key"
	FindingUntrustedChain FindingKind = "untrusted_chain"
	FindingDeprecatedTLS  FindingKind = "deprecated_protocol"
	FindingWeakCipher     FindingKind = "weak_cipher"
	FindingCTNotLogged    FindingKind = "ct_not_logged"
	FindingMaliciousCert  FindingKind = "malicious_cert" // leaf SHA1 in a threat-intel feed (S28)
	FindingMaliciousJA3   FindingKind = "malicious_ja3"  // client JA3 in a threat-intel feed (S28)
)

// Finding is one posture issue. The Source/Confidence/Indicator fields are set
// only on threat-intel IOC-match findings (S28) — a match is a confidence-scored
// SIGNAL with source attribution, never an automatic block (guardrail 9).
type Finding struct {
	Kind       FindingKind `json:"kind"`
	Severity   Severity    `json:"severity"`
	Message    string      `json:"message"`
	Source     string      `json:"source,omitempty"`     // threat-intel feed name
	Confidence int         `json:"confidence,omitempty"` // 0..100
	Indicator  string      `json:"indicator,omitempty"`  // the matched IOC value
}

// HandoffPayload is the trustctl renewal/replace handoff for a certificate finding.
type HandoffPayload struct {
	Target   string   `json:"target"`
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	SANs     []string `json:"sans,omitempty"`
	Serial   string   `json:"serial"`
	NotAfter string   `json:"not_after"`
	Reason   string   `json:"reason"`
	URL      string   `json:"url,omitempty"` // deep-link into trustctl (when configured)
}

// Posture is the analyzed TLS/cert posture for a target.
type Posture struct {
	Target     string          `json:"target"`
	Source     string          `json:"source"`
	TLSVersion string          `json:"tls_version"`
	Cipher     string          `json:"cipher"`
	Leaf       *Certificate    `json:"leaf,omitempty"`
	Findings   []Finding       `json:"findings"`
	Severity   Severity        `json:"severity"`
	Handoff    *HandoffPayload `json:"handoff,omitempty"`
	ObservedAt time.Time       `json:"observed_at"`
}

func (p *Posture) add(f Finding) {
	p.Findings = append(p.Findings, f)
	if sevRank(f.Severity) > sevRank(p.Severity) {
		p.Severity = f.Severity
	}
}
