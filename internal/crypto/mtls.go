// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

// ServerMTLSConfig builds a server TLS config that requires and verifies a client
// certificate against the CA bundle in caFile. This is the agent-transport server
// policy consumed by the gRPC server in S4. Non-mTLS connections are rejected.
func ServerMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	return serverMTLSConfig(certFile, keyFile, caFile, requirePinnedTrustDomain)
}

// ServerBMPMTLSConfig is the BMP-plane sibling of ServerMTLSConfig. It trusts
// the same operator-owned enrollment CA but accepts only the dedicated
// /bmp/<router-id> SPIFFE shape; agent SVIDs fail closed at the handshake.
func ServerBMPMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	return serverMTLSConfig(certFile, keyFile, caFile, requireBMPTrustDomain)
}

// IssuedIdentityVerifier checks an exact certificate tuple in the existing
// enrollment registry. It is deliberately a function seam so internal/crypto
// owns TLS policy without importing the storage implementation.
type IssuedIdentityVerifier func(ctx context.Context, tenantID, identityID, spiffeID, serial string) (bool, error)

// ServerBMPMTLSConfigRegistered adds an authoritative issued-identity lookup to
// the BMP handshake. A CA-valid but unrecorded certificate is rejected before
// TLS completes. The same finite timeout that bounds the surrounding handshake
// should be supplied here so registry failure cannot hold a socket forever.
func ServerBMPMTLSConfigRegistered(certFile, keyFile, caFile string, verify IssuedIdentityVerifier, timeout time.Duration) (*tls.Config, error) {
	if verify == nil {
		return nil, errors.New("crypto: BMP issued-identity verifier is required")
	}
	if timeout <= 0 {
		return nil, errors.New("crypto: BMP issued-identity timeout must be positive")
	}
	cfg, err := ServerBMPMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	base := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if err := base(rawCerts, chains); err != nil {
			return err
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("crypto: parse BMP client leaf: %w", err)
		}
		id, err := BMPSPIFFEIDFromCert(leaf)
		if err != nil {
			return fmt.Errorf("crypto: BMP client identity rejected: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		issued, err := verify(
			ctx,
			id.TenantID,
			id.AgentID,
			id.String(),
			leaf.SerialNumber.Text(16),
		)
		cancel()
		if err != nil {
			return fmt.Errorf("crypto: BMP identity registry unavailable: %w", err)
		}
		if !issued {
			return errors.New("crypto: unregistered BMP client identity refused")
		}
		return nil
	}
	return cfg, nil
}

func serverMTLSConfig(certFile, keyFile, caFile string, verify func([][]byte, [][]*x509.Certificate) error) (*tls.Config, error) {
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
	cfg.VerifyPeerCertificate = verify
	return cfg, nil
}

// requirePinnedTrustDomain is a server-side VerifyPeerCertificate hook
// (U-011): after CA validation, the client leaf must carry a SPIFFE URI in
// the pinned trust domain — a valid-chain certificate from a FOREIGN trust
// domain is refused at the handshake, before any request is read.
func requirePinnedTrustDomain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return requireSPIFFEPlane(rawCerts, SPIFFEIDFromCert)
}

func requireBMPTrustDomain(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return requireSPIFFEPlane(rawCerts, BMPSPIFFEIDFromCert)
}

func requireSPIFFEPlane(rawCerts [][]byte, parse func(*x509.Certificate) (SPIFFEID, error)) error {
	if len(rawCerts) == 0 {
		return errors.New("crypto: no client certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("crypto: parse client leaf: %w", err)
	}
	if _, err := parse(leaf); err != nil {
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
