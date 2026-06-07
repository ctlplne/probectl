package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ServerMTLSConfig builds a server TLS config that requires and verifies a client
// certificate against the CA bundle in caFile. This is the agent-transport server
// policy consumed by the gRPC server in S4. Non-mTLS connections are rejected.
func ServerMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cfg, err := ServerTLSConfig(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.VerifyPeerCertificate = requirePinnedTrustDomain
	return cfg, nil
}

// requirePinnedTrustDomain is a server-side VerifyPeerCertificate hook
// (U-011): after CA validation, the client leaf must carry a SPIFFE URI in
// the pinned trust domain — a valid-chain certificate from a FOREIGN trust
// domain is refused at the handshake, before any request is read.
func requirePinnedTrustDomain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("crypto: no client certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("crypto: parse client leaf: %w", err)
	}
	if _, err := SPIFFEIDFromCert(leaf); err != nil {
		return fmt.Errorf("crypto: client identity rejected: %w", err)
	}
	return nil
}

// ClientMTLSConfig builds a client TLS config presenting a client certificate and
// verifying the server against the CA bundle in caFile (the agent side, S4/S5).
func ClientMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: load client keypair: %w", err)
	}
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, err
	}
	cfg := hardenedServerTLS() // probectl↔probectl: TLS 1.3 floor (WIRE-007)
	cfg.Certificates = []tls.Certificate{cert}
	cfg.RootCAs = pool
	return cfg, nil
}

// LoadCertPool reads a PEM CA bundle from caFile into an x509 cert pool.
func LoadCertPool(caFile string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("crypto: read ca file: %w", err)
	}
	return CertPoolFromPEM(raw)
}

// CertPoolFromPEM builds an x509 cert pool from PEM bytes.
func CertPoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("crypto: no certificates found in PEM data")
	}
	return pool, nil
}
