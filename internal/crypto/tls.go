package crypto

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// hardenedTLS returns a base TLS config: TLS 1.2 minimum (1.3 negotiated when
// available), AEAD-only cipher suites for 1.2, and modern curve preferences.
// internal/crypto owns this policy so the rest of the codebase imports no crypto
// package directly.
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

// ServerTLSConfig builds a hardened server TLS config from a cert/key pair (no
// client auth) — for the HTTPS API.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: load server keypair: %w", err)
	}
	cfg := hardenedTLS()
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
