// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RevocationList is a registry-driven mTLS deny-list (U-038). Agent certs are
// short-lived, but "short-lived" is still a window: a compromised cert can be
// denied IMMEDIATELY — at the TLS handshake, before it expires — by serial
// and/or by SPIFFE id. The control plane refreshes the list from the agent
// registry (Replace); the mTLS server consults it on every connection.
// Safe for concurrent use.
type RevocationList struct {
	mu      sync.RWMutex
	serials map[string]struct{}
	ids     map[string]struct{}
}

// NewRevocationList returns an empty deny-list (no revocations → no effect).
func NewRevocationList() *RevocationList {
	return &RevocationList{serials: map[string]struct{}{}, ids: map[string]struct{}{}}
}

// NormalizeSerial canonicalizes a certificate serial for matching: lower-case
// hex, no "0x" prefix, no colon/space separators. Operators paste serials in
// many shapes; the cert's own serial is compared the same way.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	return strings.NewReplacer(":", "", " ", "").Replace(s)
}

// RevokeSerial denies a certificate by serial number.
func (r *RevocationList) RevokeSerial(serial string) {
	if serial == "" {
		return
	}
	r.mu.Lock()
	r.serials[NormalizeSerial(serial)] = struct{}{}
	r.mu.Unlock()
}

// RevokeID denies every certificate carrying spiffeID (e.g. a compromised
// agent identity, across re-issued certs).
func (r *RevocationList) RevokeID(spiffeID string) {
	if spiffeID == "" {
		return
	}
	r.mu.Lock()
	r.ids[spiffeID] = struct{}{}
	r.mu.Unlock()
}

// Replace atomically swaps the whole deny-list — the registry-refresh path.
func (r *RevocationList) Replace(serials, spiffeIDs []string) {
	ns := make(map[string]struct{}, len(serials))
	for _, s := range serials {
		if s != "" {
			ns[NormalizeSerial(s)] = struct{}{}
		}
	}
	ni := make(map[string]struct{}, len(spiffeIDs))
	for _, id := range spiffeIDs {
		if id != "" {
			ni[id] = struct{}{}
		}
	}
	r.mu.Lock()
	r.serials, r.ids = ns, ni
	r.mu.Unlock()
}

// IsRevoked reports whether a cert with the given (normalized-on-input) serial
// or SPIFFE id is denied.
func (r *RevocationList) IsRevoked(serial, spiffeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if serial != "" {
		if _, ok := r.serials[NormalizeSerial(serial)]; ok {
			return true
		}
	}
	if spiffeID != "" {
		if _, ok := r.ids[spiffeID]; ok {
			return true
		}
	}
	return false
}

// Empty reports whether the deny-list has no entries (the hot-path fast exit).
func (r *RevocationList) Empty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.serials) == 0 && len(r.ids) == 0
}

// Size returns the number of revoked serials + ids.
func (r *RevocationList) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.serials) + len(r.ids)
}

// revocationGuard wraps a base VerifyPeerCertificate with a deny-list check:
// after the base (CA + trust-domain pin) passes, a revoked serial or SPIFFE id
// is refused at the handshake.
func revocationGuard(rl *RevocationList, base func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if base != nil {
			if err := base(rawCerts, chains); err != nil {
				return err
			}
		}
		if rl == nil || rl.Empty() {
			return nil
		}
		if len(rawCerts) == 0 {
			return errors.New("crypto: no client certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("crypto: parse client leaf: %w", err)
		}
		serial := leaf.SerialNumber.Text(16)
		id := ""
		if sid, e := RegisteredSPIFFEIDFromCert(leaf); e == nil {
			id = sid.String()
		}
		if rl.IsRevoked(serial, id) {
			return fmt.Errorf("crypto: client certificate REVOKED (serial %s) — refused at handshake (U-038)", serial)
		}
		return nil
	}
}

// ServerMTLSConfigRevocable is ServerMTLSConfig plus a registry deny-list
// (U-038): the handshake refuses a revoked cert after CA + trust-domain
// verification. A nil/empty list is a no-op.
func ServerMTLSConfigRevocable(certFile, keyFile, caFile string, rl *RevocationList) (*tls.Config, error) {
	cfg, err := ServerMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, err
	}
	return withRevocationList(cfg, rl), nil
}

// ServerBMPMTLSConfigRegisteredRevocable composes the BMP plane pin, exact
// registry-issued identity check, and the existing live RevocationList in one
// handshake policy. Revocation augments both checks and cannot weaken either.
func ServerBMPMTLSConfigRegisteredRevocable(
	certFile, keyFile, caFile string,
	verify IssuedIdentityVerifier,
	timeout time.Duration,
	rl *RevocationList,
) (*tls.Config, error) {
	cfg, err := ServerBMPMTLSConfigRegistered(
		certFile,
		keyFile,
		caFile,
		verify,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	return withRevocationList(cfg, rl), nil
}

func withRevocationList(cfg *tls.Config, rl *RevocationList) *tls.Config {
	cfg.VerifyPeerCertificate = revocationGuard(rl, cfg.VerifyPeerCertificate)
	return cfg
}
