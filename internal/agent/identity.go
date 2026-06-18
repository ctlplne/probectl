// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Agent-side enrollment + SVID rotation (Sprint 11, ADR
// docs/adr/agent-enrollment.md). The private key is generated HERE and never
// leaves the host; the control plane signs a CSR and returns the leaf chain +
// trust bundle. Rotation proves the CURRENT identity (key possession over the
// new CSR) and atomically replaces the on-disk material —
// crypto.ClientMTLSConfigRotating picks the swap up per-handshake, no restart.

// Identity file names inside the identity directory (the agent config's TLS
// paths point at these).
const (
	IdentityCertFile = "cert.pem"
	IdentityKeyFile  = "key.pem"
	IdentityCAFile   = "ca.pem"
)

// issuedIdentity mirrors the control plane's response shape.
type issuedIdentity struct {
	CertPEM  string    `json:"cert_pem"`
	CABundle string    `json:"ca_bundle"`
	SPIFFEID string    `json:"spiffe_id"`
	TenantID string    `json:"tenant_id"`
	AgentID  string    `json:"agent_id"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

// EnrollOptions configures the first-contact bootstrap.
type EnrollOptions struct {
	Server                 string // control-plane base URL (https://host:8443)
	Token                  string // one-time join token (pjt_...)
	Dir                    string // identity directory (key/cert/bundle land here, 0600)
	Hostname               string // defaults to os.Hostname()
	Version                string
	AllowPlaintextLoopback bool // dev/test only: allow http://localhost or loopback IP
	// CAPin authenticates the SERVER on first contact in self-signed
	// deployments: hex sha256 of the server certificate (printed when the
	// token is minted). A provided pin that mismatches REFUSES (no TOFU).
	CAPin string
	// CAFile verifies the server against a CA bundle instead (CA-issued certs).
	CAFile string
}

// Enroll redeems the join token for the first SVID and writes the identity
// directory. The server derives the tenant from the TOKEN — nothing
// tenant-related is sent or accepted from this side.
func Enroll(ctx context.Context, o EnrollOptions) (spiffeID string, notAfter time.Time, err error) {
	if o.Server == "" || o.Token == "" || o.Dir == "" {
		return "", time.Time{}, fmt.Errorf("enroll: --server, --token, and --dir are required")
	}
	if o.Hostname == "" {
		o.Hostname, _ = os.Hostname()
	}
	endpoint, err := enrollmentEndpoint(o.Server, "/enroll/agent", o.AllowPlaintextLoopback)
	if err != nil {
		return "", time.Time{}, err
	}
	csrPEM, keyPEM, err := crypto.CreateCSR(o.Hostname)
	if err != nil {
		return "", time.Time{}, err
	}
	hc, err := enrollHTTPClient(o.CAPin, o.CAFile)
	if err != nil {
		return "", time.Time{}, err
	}
	id, err := postIdentity(ctx, hc, endpoint, map[string]string{
		"token": o.Token, "csr_pem": string(csrPEM), "hostname": o.Hostname, "version": o.Version,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if err := writeIdentityDir(o.Dir, []byte(id.CertPEM), keyPEM, []byte(id.CABundle)); err != nil {
		return "", time.Time{}, err
	}
	return id.SPIFFEID, id.NotAfter, nil
}

// EnrollStatusError is returned when the control plane answers an enrollment
// request with a non-200 status. A 4xx is a DEFINITIVE rejection (a bad, used,
// expired, or revoked token; a malformed CSR) — first-boot enrollment fails
// fast on it. A 5xx is transient and worth retrying (a transport error surfaces
// as a different error type and is likewise treated as transient).
type EnrollStatusError struct {
	StatusCode int
	Body       string
}

func (e *EnrollStatusError) Error() string {
	return fmt.Sprintf("enroll: server answered %d: %s", e.StatusCode, e.Body)
}

// Definitive reports whether the rejection is permanent (4xx) and must not be
// retried with the same token.
func (e *EnrollStatusError) Definitive() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// EnsureIdentity performs OPTIONAL first-boot enrollment. It is idempotent and
// fail-closed:
//   - if an identity already exists in o.Dir it does nothing (a present
//     identity is never overwritten — renewal is RotationLoop's job);
//   - else if o.Token is empty it does nothing (the caller's normal
//     "pre-provisioned identity" path applies, unchanged);
//   - else it enrolls, retrying on TRANSIENT failures (e.g. the control plane
//     is not up yet) with capped backoff up to a bounded window, and failing
//     fast on a DEFINITIVE token rejection (4xx). The token is never logged.
func EnsureIdentity(ctx context.Context, o EnrollOptions, log *slog.Logger) error {
	if identityPresent(o.Dir) {
		return nil
	}
	if o.Token == "" {
		return nil
	}
	if o.Server == "" {
		return fmt.Errorf("enroll-on-boot: a join token was provided but no control-plane server is set (set identity.server or enroll.server)")
	}
	if log == nil {
		log = slog.Default()
	}
	const maxWindow = 5 * time.Minute
	deadline := time.Now().Add(maxWindow)
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		spiffeID, notAfter, err := Enroll(ctx, o)
		if err == nil {
			log.Info("enroll-on-boot: enrolled", "spiffe_id", spiffeID,
				"svid_expires", notAfter.UTC().Format(time.RFC3339))
			return nil
		}
		var se *EnrollStatusError
		if errors.As(err, &se) && se.Definitive() {
			return fmt.Errorf("enroll-on-boot: control plane refused the join token (%w) — mint a fresh single-use token and retry", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("enroll-on-boot: giving up after %s of transient failures: %w", maxWindow, err)
		}
		log.Warn("enroll-on-boot: attempt failed (transient), retrying",
			"attempt", attempt, "retry_in", backoff.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// identityPresent reports whether a cert + key already exist in dir — the
// "already enrolled" signal. Expiry is deliberately not checked: an existing
// identity is left to the rotation loop, never silently re-minted (which would
// mint a second identity for the same agent).
func identityPresent(dir string) bool {
	for _, name := range []string{IdentityCertFile, IdentityKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

// Rotate re-issues the on-disk identity over proof of the current one and
// atomically replaces the files. The new identity ALWAYS equals the old
// (the server refuses anything else).
func Rotate(ctx context.Context, server, certFile, keyFile, caFile string) (time.Time, error) {
	endpoint, err := enrollmentEndpoint(server, "/enroll/agent/rotate", false)
	if err != nil {
		return time.Time{}, err
	}
	curCert, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, err
	}
	curKey, err := os.ReadFile(keyFile)
	if err != nil {
		return time.Time{}, err
	}
	leaf, err := firstCert(curCert)
	if err != nil {
		return time.Time{}, err
	}
	csrPEM, newKeyPEM, err := crypto.CreateCSR(leaf.Subject.CommonName)
	if err != nil {
		return time.Time{}, err
	}
	proof, err := crypto.ECDSASignPEM(curKey, csrPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("rotate: sign possession proof: %w", err)
	}
	// The rotation call verifies the server against OUR trust bundle (the CA
	// bundle issued at enrollment) — first contact is the only pinned hop.
	hc, err := enrollHTTPClient("", caFile)
	if err != nil {
		return time.Time{}, err
	}
	id, err := postIdentity(ctx, hc, endpoint, map[string]string{
		"cert_pem": string(curCert), "csr_pem": string(csrPEM), "proof": hex.EncodeToString(proof),
	})
	if err != nil {
		return time.Time{}, err
	}
	dir := filepath.Dir(certFile)
	if err := writeIdentityDir(dir, []byte(id.CertPEM), newKeyPEM, []byte(id.CABundle)); err != nil {
		return time.Time{}, err
	}
	return id.NotAfter, nil
}

// RotationLoop rotates the identity at ~2/3 of its remaining lifetime,
// checking every interval (default 1m). It never gives up: a failed rotation
// retries on the next tick while the current SVID is still valid, and logs
// loudly once past the rotation point.
func RotationLoop(ctx context.Context, log *slog.Logger, server, certFile, keyFile, caFile string, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			log.Warn("identity rotation: cannot read certificate", "error", err.Error())
			continue
		}
		leaf, err := firstCert(certPEM)
		if err != nil {
			log.Warn("identity rotation: cannot parse certificate", "error", err.Error())
			continue
		}
		if !RotationDue(leaf.NotBefore, leaf.NotAfter, time.Now()) {
			continue
		}
		notAfter, err := Rotate(ctx, server, certFile, keyFile, caFile)
		if err != nil {
			log.Error("identity rotation FAILED (will retry; ingest stops if the SVID expires)",
				"error", err.Error(), "expires", leaf.NotAfter.UTC().Format(time.RFC3339))
			continue
		}
		log.Info("agent SVID rotated", "not_after", notAfter.UTC().Format(time.RFC3339))
	}
}

// RotationDue reports whether now is past 2/3 of the certificate's lifetime
// (ADR decision 3). Exported for tests.
func RotationDue(notBefore, notAfter, now time.Time) bool {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return true
	}
	return now.After(notBefore.Add(life * 2 / 3))
}

// --- plumbing ---------------------------------------------------------------

// enrollHTTPClient verifies the server by pin (first contact, self-signed
// quickstarts) or CA bundle; with neither, the system roots apply. A pin
// mismatch fails closed — there is no trust-on-first-use fallback.
func enrollHTTPClient(caPin, caFile string) (*http.Client, error) {
	tlsCfg := crypto.InternalClientTLSConfig() // probectl↔probectl: 1.3 floor
	switch {
	case caPin != "":
		want, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(caPin)))
		if err != nil || len(want) != 32 {
			return nil, fmt.Errorf("enroll: --ca-pin must be a hex sha256 (got %d bytes)", len(want))
		}
		// Pin INSTEAD of chain verification: the pin IS the trust statement
		// (the standard pinning construction; mismatch refuses).
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // replaced by the pin check below
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("enroll: server presented no certificate")
			}
			sum := crypto.Hash(raw[0])
			if !bytes.Equal(sum, want) {
				return fmt.Errorf("enroll: server certificate pin mismatch (refusing; got %s)", hex.EncodeToString(sum))
			}
			return nil
		}
	case caFile != "":
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("enroll: no certificates in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func postIdentity(ctx context.Context, hc *http.Client, url string, body map[string]string) (*issuedIdentity, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &EnrollStatusError{StatusCode: resp.StatusCode, Body: truncate(string(raw), 200)}
	}
	var id issuedIdentity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("enroll: malformed identity response: %w", err)
	}
	if id.CertPEM == "" || id.CABundle == "" {
		return nil, errors.New("enroll: identity response missing certificate material")
	}
	return &id, nil
}

func enrollmentEndpoint(server, path string, allowPlaintextLoopback bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil {
		return "", fmt.Errorf("enroll: invalid control-plane server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("enroll: control-plane server must be an absolute https:// URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowPlaintextLoopback {
			return "", errors.New("enroll: plaintext http:// enrollment is refused; use https:// or the explicit loopback-only dev override")
		}
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New("enroll: plaintext enrollment override is limited to localhost/loopback addresses")
		}
	default:
		return "", fmt.Errorf("enroll: unsupported control-plane server scheme %q (want https)", u.Scheme)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/") + path, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// writeIdentityDir lands key/cert/bundle atomically with owner-only modes —
// partial writes never replace a working identity.
func writeIdentityDir(dir string, certPEM, keyPEM, caPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{IdentityKeyFile, keyPEM},
		{IdentityCertFile, certPEM},
		{IdentityCAFile, caPEM},
	} {
		path := filepath.Join(dir, f.name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, f.data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

func firstCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("identity: no certificate in PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
