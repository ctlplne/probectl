// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// RotatingIdentity is the trustctl-issued machine-identity integration (S41,
// closing the trustctl loop): trustctl renews certificates by writing the new
// cert/key IN PLACE, and this identity picks the renewal up per-handshake —
// no process restart, no missed rotation. It also (optionally) enforces that
// its own certificate carries the expected SPIFFE URI prefix, so an agent
// can never accidentally present another workload's identity (guardrail 4).
//
// Reload policy: stat the cert file at most once per CheckInterval; reload
// when mtime/size change AND the new pair parses + matches the SPIFFE
// expectation. A broken renewal keeps serving the previous valid identity
// (trustctl retries) — but a SPIFFE MISMATCH fails closed.
type RotatingIdentity struct {
	certFile string
	keyFile  string
	spiffe   string // optional required URI prefix, e.g. "spiffe://probectl/tenant/"

	mu       sync.Mutex
	cert     *tls.Certificate
	leaf     *x509.Certificate
	mtime    time.Time
	size     int64
	checked  time.Time
	interval time.Duration
}

// DefaultIdentityCheckInterval bounds how often the cert file is stat'ed.
const DefaultIdentityCheckInterval = 10 * time.Second

// NewRotatingIdentity loads the initial pair (failing closed if invalid) and
// returns the reload-aware identity. The SPIFFE URI pin is REQUIRED (U-011):
// spiffePrefix "" applies the default trust-domain pin
// ("spiffe://" + TrustDomain + "/") rather than disabling the check, so no
// caller can construct an unpinned identity.
func NewRotatingIdentity(certFile, keyFile, spiffePrefix string) (*RotatingIdentity, error) {
	if spiffePrefix == "" {
		spiffePrefix = "spiffe://" + TrustDomain + "/"
	}
	ri := &RotatingIdentity{
		certFile: certFile, keyFile: keyFile, spiffe: spiffePrefix,
		interval: DefaultIdentityCheckInterval,
	}
	if err := ri.reload(); err != nil {
		return nil, err
	}
	return ri, nil
}

// reload parses and validates the on-disk pair; on success it becomes current.
func (ri *RotatingIdentity) reload() error {
	cert, err := tls.LoadX509KeyPair(ri.certFile, ri.keyFile)
	if err != nil {
		return fmt.Errorf("crypto: load identity keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("crypto: parse identity leaf: %w", err)
	}
	if ri.spiffe != "" {
		ok := false
		for _, u := range leaf.URIs {
			if strings.HasPrefix(u.String(), ri.spiffe) {
				ok = true
				break
			}
		}
		if !ok {
			// Fail closed: a renewed cert with the WRONG identity must never be
			// presented (it would be an identity confusion, not a hiccup).
			return fmt.Errorf("crypto: identity certificate lacks required SPIFFE prefix %s", ri.spiffe)
		}
	}
	st, err := os.Stat(ri.certFile)
	if err != nil {
		return fmt.Errorf("crypto: stat identity cert: %w", err)
	}
	ri.cert = &cert
	ri.leaf = leaf
	ri.mtime = st.ModTime()
	ri.size = st.Size()
	return nil
}

// current returns the identity, reloading if the file changed (rate-limited).
func (ri *RotatingIdentity) current() *tls.Certificate {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	now := time.Now()
	if now.Sub(ri.checked) >= ri.interval {
		ri.checked = now
		if st, err := os.Stat(ri.certFile); err == nil &&
			(!st.ModTime().Equal(ri.mtime) || st.Size() != ri.size) {
			// A renewal landed. Try it; keep the previous valid pair on parse
			// failure (mid-write), fail closed on SPIFFE mismatch by keeping
			// the OLD identity and re-trying next interval (the old cert is
			// still the last attested identity).
			_ = ri.reload()
		}
	}
	return ri.cert
}

// Leaf returns the current leaf certificate (expiry/identity introspection).
func (ri *RotatingIdentity) Leaf() *x509.Certificate {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	return ri.leaf
}

// GetClientCertificate is the tls.Config hook for the agent (client) side.
func (ri *RotatingIdentity) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return ri.current(), nil
}

// GetCertificate is the tls.Config hook for the server side.
func (ri *RotatingIdentity) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ri.current(), nil
}

// ClientMTLSConfigRotating is ClientMTLSConfig with a trustctl-rotating
// identity: renewals written in place are presented on the next handshake.
// This is a probectl-owned mTLS channel, so it uses the internal TLS 1.3 floor.
func ClientMTLSConfigRotating(certFile, keyFile, caFile, spiffePrefix string) (*tls.Config, *RotatingIdentity, error) {
	ri, err := NewRotatingIdentity(certFile, keyFile, spiffePrefix)
	if err != nil {
		return nil, nil, err
	}
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, nil, err
	}
	cfg := hardenedServerTLS()
	cfg.GetClientCertificate = ri.GetClientCertificate
	cfg.RootCAs = pool
	return cfg, ri, nil
}

// ServerMTLSConfigRotating is ServerMTLSConfig with a rotating server
// identity (the control plane's agent-transport cert can be trustctl-managed
// too). This is a probectl-owned listener, so it uses the internal TLS 1.3
// floor.
func ServerMTLSConfigRotating(certFile, keyFile, caFile, spiffePrefix string) (*tls.Config, *RotatingIdentity, error) {
	ri, err := NewRotatingIdentity(certFile, keyFile, spiffePrefix)
	if err != nil {
		return nil, nil, err
	}
	pool, err := LoadCertPool(caFile)
	if err != nil {
		return nil, nil, err
	}
	cfg := hardenedServerTLS()
	cfg.GetCertificate = ri.GetCertificate
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.VerifyPeerCertificate = requirePinnedTrustDomain
	return cfg, ri, nil
}
