package threat

import (
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// FromCanaryAttributes builds a TLSObservation from the HTTP synthetic canary's
// captured TLS attributes (S13's attachTLS, extended for S27). It REUSES the
// already-captured handshake — it never opens a new connection. Returns ok=false
// when the result carried no TLS (a non-HTTPS probe).
func FromCanaryAttributes(target string, attrs map[string]string, observedAt time.Time) (TLSObservation, bool) {
	version := attrs["tls.protocol.version"]
	if version == "" {
		return TLSObservation{}, false
	}
	obs := TLSObservation{
		Target:     target,
		Source:     "http",
		TLSVersion: version,
		Cipher:     attrs["tls.cipher"],
		JA3:        attrs["tls.ja3"],
		JA3S:       attrs["tls.ja3s"],
		ObservedAt: observedAt,
	}
	if v, ok := attrs["tls.server.verified"]; ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			obs.Verified = &b
		}
	}
	if raw := attrs["tls.server.cert"]; raw != "" {
		if der, err := base64.StdEncoding.DecodeString(raw); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				obs.Leaf = cert
			}
		}
	}
	return obs, true
}
