package crypto

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// TLS policy (WIRE-005/WIRE-007), owned HERE so the rest of the codebase
// imports no crypto package directly:
//
//   - probectl↔probectl endpoints (API/OTLP/MCP servers, agent mTLS, the
//     enrollment client) use hardenedServerTLS: **TLS 1.3 floor** — both ends
//     are ours (or modern browsers), nothing older needs to connect.
//   - OUTBOUND probe/integration clients (canary HTTP/DNS, gNMI devices)
//     keep the 1.2 floor via hardenedTLS: they speak to THIRD-PARTY endpoints
//     the operator monitors, where a 1.3-only floor would break legitimate
//     targets. Certificate validation is always on.
//
// hardenedTLS returns the base config: TLS 1.2 minimum (1.3 negotiated when
// available), AEAD-only cipher suites for 1.2, and modern curve preferences.
func hardenedTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// hardenedServerTLS is the policy for every probectl-OWNED listener and
// probectl↔probectl client: TLS 1.3 floor (WIRE-007). The 1.2 suite list is
// retained harmlessly (ignored at 1.3) so a deliberate future floor change
// stays AEAD-only without edits.
func hardenedServerTLS() *tls.Config {
	cfg := hardenedTLS()
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

// ServerTLSConfig builds the hardened server TLS config from a cert/key pair
// (no client auth) — the ONE config every probectl HTTPS listener uses
// (API, OTLP, MCP; WIRE-005): TLS 1.3 floor.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: load server keypair: %w", err)
	}
	cfg := hardenedServerTLS()
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

// ConfigureServerTLS sets a hardened TLS config (with the loaded keypair) on srv,
// so callers serve HTTPS via srv.ListenAndServeTLS("", "") without importing any
// crypto package. Returns an error if the keypair cannot be loaded.
func ConfigureServerTLS(srv *http.Server, certFile, keyFile string) error {
	cfg, err := ServerTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = cfg
	return nil
}

// HardenedClientTLSConfig returns a hardened *tls.Config for OUTBOUND client
// connections (TLS 1.2+, modern ciphers/curves). Certificate validation is ALWAYS
// on — InsecureSkipVerify is never set (CLAUDE.md §7 guardrail 12). Used for
// remote model endpoints and any other outbound fetch that needs the policy.
func HardenedClientTLSConfig() *tls.Config { return hardenedTLS() }

// InternalClientTLSConfig is the client policy for probectl↔probectl calls
// (the enrollment/rotation client): TLS 1.3 floor — the server is ours
// (WIRE-007). Validation is always on; callers may add a pin or RootCAs.
func InternalClientTLSConfig() *tls.Config { return hardenedServerTLS() }

// HardenedHTTPClient returns an *http.Client whose transport validates server
// certificates with the hardened TLS policy. timeout bounds the entire request
// (a non-positive value leaves it unbounded — callers should pass a positive
// timeout). The only crypto policy routes through internal/crypto, so callers
// import no crypto package directly.
func HardenedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     hardenedTLS(),
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}
