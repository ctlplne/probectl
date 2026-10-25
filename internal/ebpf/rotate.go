// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// SVID rotation for the eBPF collector (D-43 R2). The collector's eBPF-plane
// certificate is short-lived (the enrollment service's leaf TTL), and the policy
// channel needs it: without rotation, consented capture would stop on every
// fleet within a day. The agent renews it the way the probe agent does — over
// the existing POST /enroll/agent/rotate endpoint, proving possession of the
// CURRENT key over a CSR for a NEW key generated here (the private key never
// leaves the host) — at two thirds of its lifetime, and atomically replaces
// the files the rotating mTLS identity reloads on its next handshake. The
// rotated identity always equals the old one (the server refuses anything
// else), and this side checks it too.

// rotationCheckEvery is how often the agent checks whether its certificate is
// due for renewal.
const rotationCheckEvery = time.Minute

// identityRotator renews the policy channel's certificate.
type identityRotator struct {
	endpoint          string
	certFile, keyFile string
	hc                *http.Client
	now               func() time.Time
	log               *slog.Logger
}

// newIdentityRotator builds the rotator for a configured channel. The control
// plane's HTTPS API is verified against the same CA as its agent listener
// (control_plane.ca_file).
func newIdentityRotator(cp ControlPlaneConfig, log *slog.Logger) (*identityRotator, error) {
	u, err := url.Parse(strings.TrimSpace(cp.RotateURL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("ebpf: control_plane.rotate_url must be the control plane's https:// API base URL")
	}
	// The hardened client (U-036): TLS 1.2+, AEAD-only, verification always
	// on, anchored on the control plane's CA.
	hc, err := crypto.HardenedHTTPClientWithCAFile(30*time.Second, cp.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ebpf: control-plane CA: %w", err)
	}
	if t, ok := hc.Transport.(*http.Transport); ok && cp.ServerName != "" {
		t.TLSClientConfig.ServerName = cp.ServerName
	}
	u.RawQuery, u.Fragment = "", ""
	return &identityRotator{
		endpoint: strings.TrimRight(u.String(), "/") + "/enroll/agent/rotate",
		certFile: cp.CertFile, keyFile: cp.KeyFile, hc: hc,
		now: time.Now, log: log,
	}, nil
}

// rotationDue reports whether now is past two thirds of the lifetime.
func rotationDue(notBefore, notAfter, now time.Time) bool {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return true
	}
	return now.After(notBefore.Add(life * 2 / 3))
}

// check renews the certificate when it is due. It returns whether it rotated.
func (r *identityRotator) check(ctx context.Context) (bool, error) {
	leaf, err := readLeaf(r.certFile)
	if err != nil {
		return false, err
	}
	if !rotationDue(leaf.NotBefore, leaf.NotAfter, r.now()) {
		return false, nil
	}
	notAfter, err := r.rotate(ctx, leaf)
	if err != nil {
		return false, fmt.Errorf("%w (current certificate expires %s)", err, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	r.log.Info("ebpf control-plane certificate rotated", "not_after", notAfter.UTC().Format(time.RFC3339))
	return true, nil
}

type rotatedIdentity struct {
	CertPEM  string    `json:"cert_pem"`
	SPIFFEID string    `json:"spiffe_id"`
	NotAfter time.Time `json:"not_after"`
}

// rotate exchanges the current certificate for a fresh one of the same
// identity and replaces the files.
func (r *identityRotator) rotate(ctx context.Context, leaf *x509.Certificate) (time.Time, error) {
	curCert, err := os.ReadFile(r.certFile)
	if err != nil {
		return time.Time{}, err
	}
	curKey, err := os.ReadFile(r.keyFile)
	if err != nil {
		return time.Time{}, err
	}
	current, err := crypto.EBPFSPIFFEIDFromCert(leaf)
	if err != nil {
		return time.Time{}, fmt.Errorf("ebpf: rotate: current certificate is not an eBPF collector identity: %w", err)
	}
	csrPEM, newKeyPEM, err := crypto.CreateCSR(leaf.Subject.CommonName)
	if err != nil {
		return time.Time{}, err
	}
	proof, err := crypto.ECDSASignPEM(curKey, csrPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("ebpf: rotate: sign possession proof: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"cert_pem": string(curCert), "csr_pem": string(csrPEM), "proof": hex.EncodeToString(proof),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.hc.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("ebpf: rotate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("ebpf: rotate: control plane answered %d", resp.StatusCode)
	}
	var out rotatedIdentity
	if err := json.Unmarshal(raw, &out); err != nil || out.CertPEM == "" {
		return time.Time{}, errors.New("ebpf: rotate: malformed identity response")
	}
	newLeaf, err := firstLeaf([]byte(out.CertPEM))
	if err != nil {
		return time.Time{}, fmt.Errorf("ebpf: rotate: %w", err)
	}
	if got, err := crypto.EBPFSPIFFEIDFromCert(newLeaf); err != nil || got != current {
		return time.Time{}, fmt.Errorf("ebpf: rotate: the control plane issued a different identity (%v) — refused", got)
	}
	// Key first, then the certificate: the rotating identity reloads the pair
	// on the next handshake; a handshake between the two renames fails once
	// and is retried, never presents a mismatched pair as valid.
	if err := writeAtomic(r.keyFile, newKeyPEM); err != nil {
		return time.Time{}, err
	}
	if err := writeAtomic(r.certFile, []byte(out.CertPEM)); err != nil {
		return time.Time{}, err
	}
	return newLeaf.NotAfter, nil
}

// seedIdentity copies the operator-provided identity (a read-only Secret
// mount) into the writable identity files when they are missing, hold another
// identity, or the seed's certificate outlives them — a fresh registration
// replaces a rotated one, a rotated one is never overwritten by its older seed
// (D-43 R2).
func seedIdentity(seedDir, certFile, keyFile string) (bool, error) {
	if seedDir == "" {
		return false, nil
	}
	seedCert, seedKey := filepath.Join(seedDir, "cert.pem"), filepath.Join(seedDir, "key.pem")
	seed, err := readLeaf(seedCert)
	if err != nil {
		return false, fmt.Errorf("ebpf: identity seed: %w", err)
	}
	if cur, err := readLeaf(certFile); err == nil && !seed.NotAfter.After(cur.NotAfter) && sameIdentity(seed, cur) {
		return false, nil
	}
	certPEM, err := os.ReadFile(seedCert)
	if err != nil {
		return false, err
	}
	keyPEM, err := os.ReadFile(seedKey)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return false, err
	}
	if err := writeAtomic(keyFile, keyPEM); err != nil {
		return false, err
	}
	return true, writeAtomic(certFile, certPEM)
}

// sameIdentity reports whether two certificates name the same SPIFFE ID.
func sameIdentity(a, b *x509.Certificate) bool {
	if len(a.URIs) != 1 || len(b.URIs) != 1 {
		return false
	}
	return a.URIs[0].String() == b.URIs[0].String()
}

func readLeaf(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return firstLeaf(raw)
}

func firstLeaf(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// writeAtomic replaces path with data, owner-only, via a same-directory rename.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runRotation is the agent's rotation loop: it checks every minute and keeps
// retrying while the current certificate is still valid.
func (a *Agent) runRotation(ctx context.Context) {
	if a.rotator == nil {
		return
	}
	t := time.NewTicker(rotationCheckEvery)
	defer t.Stop()
	for {
		if _, err := a.rotator.check(ctx); err != nil {
			a.rotationFailures.Add(1)
			a.log.Error("ebpf control-plane certificate rotation FAILED (retried; the policy channel stops when it expires)", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
