// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package enroll is the agent trust root (Sprint 11 — WIRE-002/RED-002/
// TENANT-103/ARCH-004; ADR docs/adr/agent-enrollment.md): one-time,
// tenant-scoped join tokens bootstrap a CSR-based issuance of short-lived
// SPIFFE SVIDs from the repo-managed root→intermediate agent CA. The Sprint 4
// server-side tenant binding now reads identities THIS package issued.
//
// Security posture, stated:
//   - the TOKEN names the tenant — an agent can never request one;
//   - tokens are single-use (atomic consume), short-lived, stored as hashes;
//   - the agent's private key never leaves the agent (CSR);
//   - the server controls SAN/EKU/TTL — CSR-requested extensions are ignored;
//   - rotation requires proof of the CURRENT identity (chain + possession)
//     and never changes it;
//   - every issued serial is recorded (Sprint 12 revocation feeds from it).
package enroll

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/usage"
)

const (
	// DefaultLeafTTL bounds stolen-key exposure (ADR decision 2).
	DefaultLeafTTL = 24 * time.Hour
	// DefaultTokenTTL bounds stolen-token exposure (ADR decision 1).
	DefaultTokenTTL = time.Hour

	rootCN  = "probectl agent root"
	interCN = "probectl agent issuing"

	// caSealScope/caSealAAD bind the sealed intermediate key to its purpose —
	// a deployment-global secret, sealed like every other secret at rest.
	caSealScope = "deployment"
	caSealAAD   = "agent-ca-intermediate"
)

// Refusals. ErrInvalidToken is deliberately uninformative (replay, expiry,
// revocation, and unknown all look identical to the caller).
var (
	ErrInvalidToken  = errors.New("enroll: invalid enrollment token")
	ErrBadCSR        = errors.New("enroll: invalid CSR")
	ErrNotOurs       = errors.New("enroll: certificate was not issued by this deployment (fail closed)")
	ErrInvalidProof  = errors.New("enroll: rotation proof invalid")
	ErrIdentityFixed = errors.New("enroll: rotation cannot change identity")
	// ErrInvalidCollectorPlane refuses ambiguous bus-collector registrations.
	ErrInvalidCollectorPlane = errors.New("enroll: invalid collector plane")
	// ErrRevoked refuses any issuance for an operator-revoked agent identity
	// (Sprint 12, WIRE-003): no resurrection by re-enrollment or rotation.
	ErrRevoked = errors.New("enroll: agent identity is revoked")
	// ErrQuotaExceeded: the tenant's agent quota (the MSP's commercial cap) is
	// full; a bus collector counts like any other agent (DPR-081).
	ErrQuotaExceeded = errors.New("enroll: tenant agent quota exceeded")
)

// tenantRefusal preserves a tenant identity only after the service has resolved
// it from a consumed tenant-bound token or a certificate that verified against
// this deployment's CA. Error deliberately returns only the refusal cause: the
// tenant must never become part of an API error string.
type tenantRefusal struct {
	tenantID string
	cause    error
}

func (e *tenantRefusal) Error() string { return e.cause.Error() }
func (e *tenantRefusal) Unwrap() error { return e.cause }

func refuseTenant(tenantID string, cause error) error {
	return &tenantRefusal{tenantID: tenantID, cause: cause}
}

// RefusalTenant returns the safely resolved tenant carried by a refusal. False
// means the caller must treat the attempt as deployment-scoped; it must never
// infer a tenant from unverified request material.
func RefusalTenant(err error) (string, bool) {
	var refusal *tenantRefusal
	if !errors.As(err, &refusal) || strings.TrimSpace(refusal.tenantID) == "" {
		return "", false
	}
	return refusal.tenantID, true
}

// Service issues and rotates agent SVIDs.
type Service struct {
	pool    *pgxpool.Pool
	ca      *crypto.CA // the issuing intermediate (unsealed in memory only)
	rootPEM []byte
	// prevCA is the superseded issuing intermediate during a renewal overlap
	// (DPR-177): agents still holding a leaf it signed must verify and rotate.
	// Nil when there is none, or once the old one is past its own NotAfter.
	prevCA  *x509.Certificate
	leafTTL time.Duration
	log     *slog.Logger
	now     func() time.Time
}

// InitCA generates the hierarchy ONCE: root (10y) → intermediate (1y). The
// intermediate key is sealed via tenantcrypto before storage; the ROOT key is
// returned to the caller for offline custody and never persisted. Refuses to
// overwrite an existing hierarchy.
// sealCAKey seals the agent-CA intermediate key and REFUSES a plaintext result
// (KEYS-003). tenantcrypto.Seal returns the input UNCHANGED (no scheme prefix)
// when no envelope key is configured (keyless dev); the CA-forging intermediate
// key is far too sensitive for that passthrough, so persisting a
// non-scheme-prefixed value is refused — `agent-ca init` must run with a
// configured envelope key. Fail closed.
func sealCAKey(ctx context.Context, interKey []byte) (string, error) {
	sealed, err := tenantcrypto.Seal(ctx, caSealScope, interKey, []byte(caSealAAD))
	if err != nil {
		return "", fmt.Errorf("enroll: seal intermediate key: %w", err)
	}
	if !tenantcrypto.HasScheme(sealed) {
		return "", errors.New("enroll: refusing to persist the agent-CA intermediate key as plaintext — configure an envelope key (PROBECTL_ENVELOPE_KEY / BYOK) before `agent-ca init` (KEYS-003)")
	}
	return sealed, nil
}

// CAInitialized reports whether the agent CA hierarchy already exists, so a
// repeatable bootstrap can tell "already done" from "failed" without asking
// InitCA to overwrite anything (DPR-136).
func CAInitialized(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	_, _, err := store.NewAgentCA(pool).Load(ctx, "root")
	if err == nil {
		return true, nil
	}
	if errors.Is(err, store.ErrAgentCANotInitialized) {
		return false, nil
	}
	return false, err
}

func InitCA(ctx context.Context, pool *pgxpool.Pool) (rootKeyPEM []byte, err error) {
	cas := store.NewAgentCA(pool)
	if _, _, err := cas.Load(ctx, "root"); err == nil {
		return nil, fmt.Errorf("enroll: agent CA already initialized (refusing to overwrite the trust root)")
	} else if !errors.Is(err, store.ErrAgentCANotInitialized) {
		return nil, err
	}
	root, err := crypto.GenerateRootCA(rootCN, 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	inter, err := root.IssueIntermediate(interCN, 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	interKey, err := inter.KeyPEM()
	if err != nil {
		return nil, err
	}
	sealed, err := sealCAKey(ctx, interKey)
	if err != nil {
		return nil, err
	}
	if err := cas.Save(ctx, "root", string(root.CertPEM()), ""); err != nil {
		return nil, err
	}
	if err := cas.Save(ctx, "intermediate", string(inter.CertPEM()), sealed); err != nil {
		return nil, err
	}
	rootKey, err := root.KeyPEM()
	if err != nil {
		return nil, err
	}
	return rootKey, nil
}

// previousIntermediate is where a superseded issuing intermediate is kept until
// its own NotAfter, so agents still holding a leaf it signed can verify and
// rotate their way onto the new one.
const previousIntermediate = "intermediate_previous"

// RenewIntermediate mints a NEW issuing intermediate from the offline root and
// supersedes the current one, keeping the old certificate until it expires.
//
// DPR-177: the shipped intermediate lives one year and the root that can
// replace it is deliberately offline, so the deployment cannot renew itself —
// and there was no command for an operator to do it either. A year after
// `agent-ca init`, enrollment and rotation refuse, and the fleet stops within
// one SVID lifetime. The root key is supplied by the operator for this one
// call and is never persisted, exactly as at init.
//
// The overlap is what makes this safe to run at any time: every agent still
// holding a leaf signed by the previous intermediate keeps verifying, and its
// normal rotation moves it onto the new chain. Nothing has to be re-enrolled.
func RenewIntermediate(ctx context.Context, pool *pgxpool.Pool, rootKeyPEM []byte, ttl time.Duration) (notAfter time.Time, err error) {
	if ttl <= 0 {
		ttl = 365 * 24 * time.Hour
	}
	cas := store.NewAgentCA(pool)
	rootCertPEM, _, err := cas.Load(ctx, "root")
	if err != nil {
		return time.Time{}, err
	}
	root, err := crypto.LoadCA([]byte(rootCertPEM), rootKeyPEM)
	if err != nil {
		// A mismatched key fails HERE, before anything is written: the operator
		// brought the wrong file, which is a far more likely accident than a
		// corrupted store.
		return time.Time{}, fmt.Errorf("enroll: the supplied root key does not open this deployment's root CA: %w", err)
	}
	current, _, err := cas.Load(ctx, "intermediate")
	if err != nil {
		return time.Time{}, err
	}
	inter, err := root.IssueIntermediate(interCN, ttl)
	if err != nil {
		return time.Time{}, err
	}
	interKey, err := inter.KeyPEM()
	if err != nil {
		return time.Time{}, err
	}
	sealed, err := sealCAKey(ctx, interKey)
	if err != nil {
		return time.Time{}, err
	}
	// Previous first: if the process dies between the two writes, the worst
	// state is a deployment that trusts one chain twice, never one that has
	// dropped the chain its agents are still using.
	if err := cas.Save(ctx, previousIntermediate, current, ""); err != nil {
		return time.Time{}, err
	}
	if err := cas.Save(ctx, "intermediate", string(inter.CertPEM()), sealed); err != nil {
		return time.Time{}, err
	}
	return inter.Cert().NotAfter, nil
}

// loadPreviousIntermediate returns the superseded issuing certificate while it
// is still inside its own validity, and nothing once it is not: an expired
// intermediate in the verification pool would keep vouching for leaves that
// should no longer verify.
func loadPreviousIntermediate(ctx context.Context, cas store.AgentCA, now time.Time) *x509.Certificate {
	certPEM, _, err := cas.Load(ctx, previousIntermediate)
	if err != nil || certPEM == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !now.Before(cert.NotAfter) {
		return nil
	}
	return cert
}

// Load builds the service from the persisted hierarchy (unsealing the
// intermediate key through tenantcrypto). store.ErrAgentCANotInitialized
// tells the caller enrollment is not configured yet.
func Load(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) (*Service, error) {
	cas := store.NewAgentCA(pool)
	rootCert, _, err := cas.Load(ctx, "root")
	if err != nil {
		return nil, err
	}
	interCert, sealedKey, err := cas.Load(ctx, "intermediate")
	if err != nil {
		return nil, err
	}
	if sealedKey == "" {
		return nil, fmt.Errorf("enroll: intermediate key missing (re-run agent-ca init)")
	}
	interKey, err := tenantcrypto.Open(ctx, caSealScope, sealedKey, []byte(caSealAAD))
	if err != nil {
		return nil, fmt.Errorf("enroll: unseal intermediate key (is the envelope key configured?): %w", err)
	}
	ca, err := crypto.LoadCA([]byte(interCert), interKey)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{pool: pool, ca: ca, rootPEM: []byte(rootCert),
		prevCA:  loadPreviousIntermediate(ctx, cas, time.Now()),
		leafTTL: DefaultLeafTTL, log: log, now: time.Now}, nil
}

// IssuingWindow reports when the issuing intermediate was signed and when it
// stops signing.
//
// DPR-177: the intermediate that signs every agent SVID lives ONE YEAR, the
// root that could replace it is deliberately offline, and nothing anywhere
// watched the date. A year after `agent-ca init` every rotation and every
// enrollment starts failing, and the whole fleet is gone within one SVID
// lifetime — silently, because an agent keeps working until its own leaf
// expires. A deployment cannot be asked to remember a date nobody shows it.
func (s *Service) IssuingWindow() (notBefore, notAfter time.Time) {
	cert := s.ca.Cert()
	if cert == nil {
		return time.Time{}, time.Time{}
	}
	return cert.NotBefore, cert.NotAfter
}

// Bundle is the trust bundle transports verify against (root + intermediate,
// plus the superseded intermediate while it is still inside its own validity —
// DPR-177, so a renewal never orphans an agent mid-rotation).
func (s *Service) Bundle() []byte {
	out := append(append([]byte{}, s.rootPEM...), s.ca.CertPEM()...)
	if s.prevCA != nil && s.now().Before(s.prevCA.NotAfter) {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.prevCA.Raw})...)
	}
	return out
}

// PublicBundle returns the agent CA trust bundle — the root + intermediate
// CERTIFICATES, i.e. the public trust anchor a verifier needs (notably the
// control plane's agent gRPC client-CA pool, PROBECTL_AGENT_TLS_CA_FILE).
// Unlike Load it never unseals the intermediate KEY, so it needs no envelope
// key and can export the public CA on any host with database access. Returns
// store.ErrAgentCANotInitialized when the CA has not been created yet.
func PublicBundle(ctx context.Context, pool *pgxpool.Pool) ([]byte, error) {
	cas := store.NewAgentCA(pool)
	rootCert, _, err := cas.Load(ctx, "root")
	if err != nil {
		return nil, err
	}
	interCert, _, err := cas.Load(ctx, "intermediate")
	if err != nil {
		return nil, err
	}
	out := rootCert + interCert
	// DPR-177: a renewal overlap has TWO valid issuing certificates, and this
	// bundle is what the agent gRPC listener verifies clients against. Leaving
	// the superseded one out would refuse every agent that has not rotated yet.
	if prev := loadPreviousIntermediate(ctx, cas, time.Now()); prev != nil {
		out += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: prev.Raw}))
	}
	return []byte(out), nil
}

// MintToken creates a one-time join token for a tenant (operator path,
// audited by the caller). Returns the DISPLAY token — shown once, never
// stored (only its hash is).
func (s *Service) MintToken(ctx context.Context, tenantID, agentID, name, createdBy string, ttl time.Duration) (display, id string, err error) {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	raw, err := crypto.Random(32)
	if err != nil {
		return "", "", err
	}
	display = "pjt_" + hex.EncodeToString(raw)
	id, err = store.NewEnrollTokens(s.pool).Create(ctx, tenantID, agentID, name, createdBy,
		crypto.Hash([]byte(display)), ttl)
	if err != nil {
		return "", "", err
	}
	return display, id, nil
}

// Request is the pre-identity bootstrap call.
type Request struct {
	Token    string `json:"token"`
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	// Attestor reserves the cloud-IID/OIDC extension seam (ADR decision 1).
	// Only "join-token" (or empty) is implemented.
	Attestor string `json:"attestor,omitempty"`
}

// Identity is an issued SVID + its trust context.
type Identity struct {
	CertPEM  string    `json:"cert_pem"`  // leaf + intermediate (chain)
	CABundle string    `json:"ca_bundle"` // root + intermediate (trust anchors)
	SPIFFEID string    `json:"spiffe_id"`
	TenantID string    `json:"tenant_id"`
	AgentID  string    `json:"agent_id"`
	Plane    string    `json:"plane"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

// Enroll consumes a join token and issues the first SVID. The tenant comes
// ONLY from the token; the agent id comes from the token's pin or is
// assigned here. The agent is registered in the tenant's registry, so the
// Sprint 4 binding immediately vouches for the pair.
func (s *Service) Enroll(ctx context.Context, req Request) (*Identity, error) {
	if req.Attestor != "" && req.Attestor != "join-token" {
		return nil, fmt.Errorf("enroll: attestor %q not supported (join-token only; see ADR)", req.Attestor)
	}
	if !strings.HasPrefix(req.Token, "pjt_") {
		return nil, ErrInvalidToken
	}
	hostname := strings.TrimSpace(req.Hostname)

	tenantID, pinned, err := store.NewEnrollTokens(s.pool).Consume(ctx, crypto.Hash([]byte(req.Token)), hostname)
	if err != nil {
		if errors.Is(err, store.ErrEnrollTokenInvalid) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	agentID := pinned
	if agentID == "" {
		agentID, err = newAgentID()
		if err != nil {
			return nil, err
		}
	} else if revoked, rerr := store.NewAgentIdentities(s.pool).IsAgentRevoked(ctx, tenantID, agentID); rerr != nil {
		return nil, rerr
	} else if revoked {
		return nil, refuseTenant(tenantID, ErrRevoked) // a revoked identity cannot be re-enrolled (WIRE-003)
	}
	return s.issue(ctx, tenantID, agentID, hostname, req.Version, req.CSRPEM, "agent", nil, "" /* first issuance */)
}

// CollectorIdentity is what a bus-only collector gets from registration: a
// UUID agent id (and its tenant) to stamp on the records it publishes. No
// certificate — these collectors authenticate to the bus separately; the
// registry row is what the control-plane tenant-binding verifies against.
type CollectorIdentity struct {
	TenantID string    `json:"tenant_id"`
	AgentID  string    `json:"agent_id"`
	Plane    string    `json:"plane"`
	SVID     *Identity `json:"svid,omitempty"`
}

// RegisterCollector is the sanctioned registration path for bus-publishing
// collectors: the BGP, eBPF, flow, device, and endpoint planes (ARCH-011). They
// publish straight to the bus rather than streaming over the agent gRPC, so
// they never went through Enroll and had NO registry row; the tenant-binding
// then rejected their batches fail-closed. RegisterCollector consumes a
// one-time enroll token, mints a UUID identity, and writes the agents-registry
// row, returning the UUID for the collector to stamp on its records. It issues
// no certificate (bus auth is separate); that is the only difference from
// Enroll.
func (s *Service) RegisterCollector(ctx context.Context, token, hostname, plane, csrPEM string) (*CollectorIdentity, error) {
	if !strings.HasPrefix(token, "pjt_") {
		return nil, ErrInvalidToken
	}
	hostname = strings.TrimSpace(hostname)
	plane, err := NormalizeCollectorPlane(plane)
	if err != nil {
		return nil, err
	}
	if plane == "bmp" && strings.TrimSpace(csrPEM) == "" {
		return nil, ErrBadCSR
	}
	tenantID, pinned, err := store.NewEnrollTokens(s.pool).Consume(ctx, crypto.Hash([]byte(token)), hostname)
	if err != nil {
		if errors.Is(err, store.ErrEnrollTokenInvalid) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	return s.registerCollector(ctx, tenantID, pinned, hostname, plane, csrPEM)
}

// RegisterCollectorForTenant is the authenticated tenant-admin path. The
// expectedTenantID comes from the caller's principal, not from the token. Token
// consumption runs through ConsumeForTenant so a stolen token from another
// tenant cannot be burned or used to create a foreign registry row.
func (s *Service) RegisterCollectorForTenant(ctx context.Context, expectedTenantID, token, hostname, plane, csrPEM string) (*CollectorIdentity, error) {
	if !strings.HasPrefix(token, "pjt_") {
		return nil, ErrInvalidToken
	}
	expectedTenantID = strings.TrimSpace(expectedTenantID)
	if expectedTenantID == "" {
		return nil, tenancy.ErrNoTenant
	}
	hostname = strings.TrimSpace(hostname)
	plane, err := NormalizeCollectorPlane(plane)
	if err != nil {
		return nil, err
	}
	if plane == "bmp" && strings.TrimSpace(csrPEM) == "" {
		return nil, ErrBadCSR
	}
	pinned, err := store.NewEnrollTokens(s.pool).ConsumeForTenant(ctx, expectedTenantID, crypto.Hash([]byte(token)), hostname)
	if err != nil {
		if errors.Is(err, store.ErrEnrollTokenInvalid) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	return s.registerCollector(ctx, expectedTenantID, pinned, hostname, plane, csrPEM)
}

// NormalizeCollectorPlane returns the canonical bus-collector plane name.
func NormalizeCollectorPlane(plane string) (string, error) {
	plane = strings.ToLower(strings.TrimSpace(plane))
	switch plane {
	case "bgp", "bmp", "flow", "device", "ebpf", "endpoint":
		return plane, nil
	default:
		return "", ErrInvalidCollectorPlane
	}
}

func (s *Service) registerCollector(ctx context.Context, tenantID, pinned, hostname, plane, csrPEM string) (*CollectorIdentity, error) {
	agentID := pinned
	if agentID == "" {
		var err error
		if agentID, err = newAgentID(); err != nil {
			return nil, err
		}
	} else if revoked, rerr := store.NewAgentIdentities(s.pool).IsAgentRevoked(ctx, tenantID, agentID); rerr != nil {
		return nil, rerr
	} else if revoked {
		return nil, refuseTenant(tenantID, ErrRevoked)
	}
	if plane == "bmp" {
		svid, err := s.issue(
			ctx,
			tenantID,
			agentID,
			hostname,
			"",
			csrPEM,
			"bmp",
			[]string{"collector", "bmp"},
			"",
		)
		if err != nil {
			return nil, err
		}
		s.log.Info("bmp router registered",
			"tenant_id", tenantID, "agent_id", agentID, "plane", plane, "hostname", hostname)
		return &CollectorIdentity{
			TenantID: tenantID,
			AgentID:  agentID,
			Plane:    plane,
			SVID:     svid,
		}, nil
	}
	spiffe := crypto.AgentSPIFFEID(tenantID, agentID)
	name := hostname
	if name == "" {
		name = agentID
	}
	caps := []string{"collector", plane}
	// DPR-081: a collector is a metered agent. The gRPC registration path
	// consulted the quota seam; this path minted a fresh identity every time
	// and never did, so an MSP tenant capped at five agents ran twelve.
	if qerr := usage.AllowCreate(ctx, tenantID, usage.MeterAgents); qerr != nil {
		return nil, fmt.Errorf("%w: %v", ErrQuotaExceeded, qerr)
	}
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, e := (store.Agents{}).Register(ctx, sc, agentID, name, hostname, "", spiffe, caps)
			return e
		})
	if err != nil {
		return nil, err
	}
	s.log.Info("bus collector registered",
		"tenant_id", tenantID, "agent_id", agentID, "plane", plane, "hostname", hostname)
	return &CollectorIdentity{TenantID: tenantID, AgentID: agentID, Plane: plane}, nil
}

// newAgentID mints a random v4 UUID for an agent. The agents registry keys on
// a uuid column (migrations/0006), so the id must be a UUID — not the old
// "agent-<hex>" form. No external uuid dependency: 16 crypto-random bytes with
// the version (4) and variant (10x) bits set, formatted canonically.
func newAgentID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RotateRequest re-issues an identity over proof of the CURRENT one: the
// presented cert must chain to OUR hierarchy, be time-valid, have an issued
// serial on record, and the CSR must be signed by the presented cert's key
// (possession). Identity never changes on rotation.
type RotateRequest struct {
	CertPEM  string `json:"cert_pem"` // the CURRENT leaf
	CSRPEM   string `json:"csr_pem"`  // for the NEW key
	ProofHex string `json:"proof"`    // hex ECDSA sig over CSRPEM by the CURRENT key
}

// Rotate verifies the current identity and issues a fresh SVID for it.
func (s *Service) Rotate(ctx context.Context, req RotateRequest) (*Identity, error) {
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrNotOurs
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrNotOurs
	}
	// Chain: leaf → intermediate → root, time-valid, client-auth.
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.rootPEM) {
		return nil, fmt.Errorf("enroll: root bundle unreadable")
	}
	inters.AddCert(s.ca.Cert())
	// DPR-177: during a renewal overlap the presented leaf may still be signed
	// by the superseded intermediate. Rotation is precisely how such an agent
	// moves onto the new chain, so refusing it here would strand every agent
	// that had not rotated in the minutes before the renewal.
	if s.prevCA != nil && s.now().Before(s.prevCA.NotAfter) {
		inters.AddCert(s.prevCA)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, CurrentTime: s.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, ErrNotOurs
	}
	id, err := crypto.RegisteredSPIFFEIDFromCert(cert)
	if err != nil {
		return nil, ErrNotOurs
	}
	// Possession: the CSR for the NEW key is signed by the CURRENT key.
	proof, err := hex.DecodeString(req.ProofHex)
	if err != nil || crypto.ECDSAVerifyCert(cert, []byte(req.CSRPEM), proof) != nil {
		return nil, refuseTenant(id.TenantID, ErrInvalidProof)
	}
	// Revocation (Sprint 12): a revoked identity cannot rotate its way back.
	if revoked, rerr := store.NewAgentIdentities(s.pool).IsAgentRevoked(ctx, id.TenantID, id.AgentID); rerr != nil {
		return nil, rerr
	} else if revoked {
		return nil, refuseTenant(id.TenantID, ErrRevoked)
	}
	// Provenance: the serial must be one WE issued for this identity.
	oldSerial := cert.SerialNumber.Text(16)
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), s.pool,
		func(ctx context.Context, _ tenancy.Scope) error {
			known, kerr := store.NewAgentIdentities(s.pool).KnownSerial(ctx, id.TenantID, id.AgentID, oldSerial)
			if kerr != nil {
				return kerr
			}
			if !known {
				return ErrNotOurs
			}
			return nil
		})
	if err != nil {
		if errors.Is(err, ErrNotOurs) {
			return nil, refuseTenant(id.TenantID, ErrNotOurs)
		}
		return nil, err
	}
	return s.issue(ctx, id.TenantID, id.AgentID, cert.Subject.CommonName, "", req.CSRPEM, id.Plane, nil, oldSerial)
}

// issue signs the CSR for (tenant, agent), records the identity, and (on first
// issuance) reserves the agent so the Sprint 4 binding vouches for it. Reserve
// deliberately does not claim an operational connection; the authenticated
// mTLS Register RPC owns that transition.
func (s *Service) issue(ctx context.Context, tenantID, agentID, hostname, version, csrPEM, plane string, capabilities []string, rotatedFrom string) (*Identity, error) {
	var spiffe string
	switch plane {
	case "", "agent":
		plane = "agent"
		spiffe = crypto.AgentSPIFFEID(tenantID, agentID)
	case "bmp":
		spiffe = crypto.BMPSPIFFEID(tenantID, agentID)
	default:
		return nil, refuseTenant(tenantID, ErrInvalidCollectorPlane)
	}
	leafPEM, serial, err := s.ca.SignCSR([]byte(csrPEM), spiffe, s.leafTTL)
	if err != nil {
		return nil, refuseTenant(tenantID, fmt.Errorf("%w: %v", ErrBadCSR, err))
	}
	serialHex := serial.Text(16)
	notAfter := s.now().Add(s.leafTTL)

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if err := store.NewAgentIdentities(s.pool).Record(ctx, tenantID, agentID, spiffe, serialHex, notAfter, rotatedFrom); err != nil {
				return err
			}
			if rotatedFrom == "" {
				name := hostname
				if name == "" {
					name = agentID
				}
				if _, err := (store.Agents{}).Reserve(ctx, sc, agentID, name, hostname, version, spiffe, capabilities); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	action := "enrolled"
	if rotatedFrom != "" {
		action = "rotated"
	}
	s.log.Info("agent SVID "+action,
		"tenant_id", tenantID, "agent_id", agentID, "serial", serialHex,
		"plane", plane, "not_after", notAfter.UTC().Format(time.RFC3339), "rotated_from", rotatedFrom)

	chain := append(append([]byte{}, leafPEM...), s.ca.CertPEM()...)
	return &Identity{
		CertPEM: string(chain), CABundle: string(s.Bundle()),
		SPIFFEID: spiffe, TenantID: tenantID, AgentID: agentID,
		Plane: plane, Serial: serialHex, NotAfter: notAfter,
	}, nil
}

// Revoke stamps every identity of (tenant, agent) revoked, returns the
// material for the LIVE handshake deny-list, and blocks future issuance for
// the id (Sprint 12, WIRE-003 residual). Callers audit and feed the list.
func (s *Service) Revoke(ctx context.Context, tenantID, agentID, revokedBy string) (serials []string, spiffeID string, err error) {
	serials, spiffeID, err = store.NewAgentIdentities(s.pool).RevokeAgent(ctx, tenantID, agentID, revokedBy)
	if err != nil {
		return nil, "", err
	}
	s.log.Warn("agent identity REVOKED — handshakes refuse it from the next connection",
		"tenant_id", tenantID, "agent_id", agentID, "live_serials", len(serials), "revoked_by", revokedBy)
	return serials, spiffeID, nil
}

// ListRevoked returns the persisted deny-list (boot reload + refresh).
func (s *Service) ListRevoked(ctx context.Context) (serials, spiffeIDs []string, err error) {
	return store.NewAgentIdentities(s.pool).ListRevoked(ctx)
}
