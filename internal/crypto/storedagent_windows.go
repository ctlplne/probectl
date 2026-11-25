// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"fmt"
	"time"
)

// StoredWindowsAgentIdentity validates a device's coherent certificate and key.
func StoredWindowsAgentIdentity(certPEM, keyPEM []byte) (SPIFFEID, time.Time, time.Time, error) {
	pair, id, err := parseWindowsAgentKeyPair(certPEM, keyPEM)
	if err != nil {
		return SPIFFEID{}, time.Time{}, time.Time{}, err
	}
	return id, pair.Leaf.NotBefore, pair.Leaf.NotAfter, nil
}

// WindowsAgentTLSConfig builds the usual hardened mTLS config around an
// account-protected record. Each handshake reads the current complete pair.
func WindowsAgentTLSConfig(serverCA []byte, expected SPIFFEID, load func() ([]byte, []byte, error)) (*tls.Config, error) {
	pool, err := CertPoolFromPEM(serverCA)
	if err != nil {
		return nil, err
	}
	cfg := InternalClientTLSConfig()
	cfg.RootCAs = pool
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certPEM, keyPEM, err := load()
		if err != nil {
			return nil, err
		}
		defer Zeroize(keyPEM)
		pair, id, err := parseWindowsAgentKeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		if id != expected {
			return nil, fmt.Errorf("stored Windows certificate changed the device identity")
		}
		return &pair, nil
	}
	return cfg, nil
}

func parseWindowsAgentKeyPair(certPEM, keyPEM []byte) (tls.Certificate, SPIFFEID, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, SPIFFEID{}, fmt.Errorf("load Windows device keypair: %w", err)
	}
	if pair.Leaf == nil {
		pair.Leaf, err = ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, SPIFFEID{}, err
		}
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) || !now.Before(pair.Leaf.NotAfter) {
		return tls.Certificate{}, SPIFFEID{}, fmt.Errorf("stored Windows device certificate is outside its validity period")
	}
	id, err := SPIFFEIDFromCert(pair.Leaf)
	return pair, id, err
}
