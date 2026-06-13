// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package tenantcrypto is the core per-tenant at-rest encryption seam (S-T6,
// F56): sensitive tenant-owned values are sealed through ONE dispatcher, and
// WHICH key seals them is a deployment property — the deployment envelope by
// default, the per-tenant keyring (ee/tenantkeys) when the byok feature is
// licensed, plaintext passthrough only in keyless dev setups.
//
// The stored format is self-describing ("<scheme>:..."), so reads dispatch to
// whichever sealer produced the value: rotating the PRIMARY sealer (e.g.
// installing per-tenant keys) never breaks existing rows — decrypt-on-read
// compatibility is structural. The fail-safe rule (the S-T6 watch-out): once
// a value is sealed under a tenant key, opening it requires THAT key — an
// unavailable or destroyed key is an ERROR, never a silent fallback to a
// shared key.
package tenantcrypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Sealer seals and opens tenant-scoped values. Scheme is the stored-format
// prefix this sealer owns (reads dispatch on it).
type Sealer interface {
	// Scheme is the format prefix (e.g. "dv1", "tk1") — no colons.
	Scheme() string
	// Seal returns the self-describing stored string for plaintext.
	Seal(ctx context.Context, tenantID string, plaintext, aad []byte) (string, error)
	// Open reverses Seal for a value carrying this sealer's scheme.
	Open(ctx context.Context, tenantID string, stored string, aad []byte) ([]byte, error)
}

// Destroyer is implemented by sealers whose keys can be destroyed per tenant
// (crypto-offboarding). Returns how many key versions were destroyed.
type Destroyer interface {
	DestroyKeys(ctx context.Context, tenantID string) (int, error)
}

// ErrUnknownScheme marks a stored value no registered sealer can open.
type ErrUnknownScheme struct{ Scheme string }

func (e ErrUnknownScheme) Error() string {
	return fmt.Sprintf("tenantcrypto: no sealer registered for scheme %q (key material unavailable — failing safe, never falling back)", e.Scheme)
}

var (
	mu      sync.RWMutex
	primary Sealer
	openers = map[string]Sealer{}
)

// SetPrimary installs the sealer used for NEW seals and registers it as an
// opener. nil clears the primary (passthrough writes).
func SetPrimary(s Sealer) {
	mu.Lock()
	defer mu.Unlock()
	primary = s
	if s != nil {
		openers[s.Scheme()] = s
	}
}

// AddOpener registers a decrypt-only sealer (legacy formats stay readable
// after the primary changes).
func AddOpener(s Sealer) {
	if s == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	openers[s.Scheme()] = s
}

// Reset clears the registry (tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	primary = nil
	openers = map[string]Sealer{}
}

// Seal seals plaintext for a tenant via the primary sealer. With no primary
// installed (keyless dev), the value is stored as-is — the pre-S-T6
// behavior, kept honest by the self-describing format on the way back.
func Seal(ctx context.Context, tenantID string, plaintext, aad []byte) (string, error) {
	mu.RLock()
	p := primary
	mu.RUnlock()
	if p == nil {
		return string(plaintext), nil
	}
	return p.Seal(ctx, tenantID, plaintext, aad)
}

// Open reverses Seal: values dispatch by scheme prefix; values with no
// recognized scheme are legacy plaintext and return as-is (decrypt-on-read
// compatibility). A recognized scheme with no registered sealer FAILS — the
// fail-safe rule.
func Open(ctx context.Context, tenantID string, stored string, aad []byte) ([]byte, error) {
	scheme, _, ok := strings.Cut(stored, ":")
	if !ok || !schemeRegistered(scheme) {
		if ok && looksLikeScheme(scheme) {
			return nil, ErrUnknownScheme{Scheme: scheme}
		}
		return []byte(stored), nil // legacy plaintext
	}
	mu.RLock()
	s := openers[scheme]
	mu.RUnlock()
	return s.Open(ctx, tenantID, stored, aad)
}

// DestroyKeys destroys a tenant's keys via the primary sealer when it
// supports crypto-offboarding (0, nil otherwise — recorded honestly by the
// caller).
func DestroyKeys(ctx context.Context, tenantID string) (int, bool, error) {
	mu.RLock()
	p := primary
	mu.RUnlock()
	d, ok := p.(Destroyer)
	if !ok {
		return 0, false, nil
	}
	n, err := d.DestroyKeys(ctx, tenantID)
	return n, true, err
}

// HasScheme reports whether a stored value carries a REGISTERED sealer scheme
// prefix (e.g. "dv1:...", "tk1:...") — i.e. it was genuinely sealed, not the
// keyless-dev plaintext passthrough (KEYS-003). Callers handling especially
// sensitive material (the agent-CA key) use this to refuse persisting an
// unsealed value.
func HasScheme(stored string) bool {
	scheme, _, ok := strings.Cut(stored, ":")
	return ok && schemeRegistered(scheme)
}

func schemeRegistered(scheme string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := openers[scheme]
	return ok
}

// looksLikeScheme distinguishes sealed-format prefixes from plaintext that
// happens to contain a colon (e.g. a webhook secret "user:pass"): sealed
// schemes are short, lowercase alphanumerics this package or ee/tenantkeys
// minted ("dv1", "tk1", ...).
func looksLikeScheme(s string) bool {
	if len(s) < 2 || len(s) > 8 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return knownSchemes[s]
}

// knownSchemes are the formats probectl has ever minted (fail-safe matching:
// only these refuse to open as plaintext when their sealer is absent).
var knownSchemes = map[string]bool{"dv1": true, "tk1": true}

// --- The deployment-envelope sealer (the default when PROBECTL_ENVELOPE_KEY
// is configured): one master KEK for the whole deployment — the pre-S-T6
// baseline, still per-value enveloped. Scheme "dv1". ---

// EnvelopeSealer seals under the deployment master via envelope encryption.
type EnvelopeSealer struct {
	env *crypto.Envelope
}

// NewEnvelopeSealer builds the deployment-wide sealer from the base64 KEK.
func NewEnvelopeSealer(keyID, kekB64 string) (*EnvelopeSealer, error) {
	kp, err := crypto.NewStaticKeyProviderFromBase64(keyID, kekB64)
	if err != nil {
		return nil, err
	}
	return &EnvelopeSealer{env: crypto.NewEnvelope(kp)}, nil
}

// Scheme implements Sealer.
func (*EnvelopeSealer) Scheme() string { return "dv1" }

// Seal envelope-encrypts plaintext (AAD binds tenant + caller context).
func (s *EnvelopeSealer) Seal(ctx context.Context, tenantID string, plaintext, aad []byte) (string, error) {
	sealed, err := s.env.Seal(ctx, plaintext, bindAAD(tenantID, aad))
	if err != nil {
		return "", err
	}
	return "dv1:" + sealed.KeyID + ":" +
		base64.RawStdEncoding.EncodeToString(sealed.WrappedDEK) + ":" +
		base64.RawStdEncoding.EncodeToString(sealed.Ciphertext), nil
}

// Open reverses Seal.
func (s *EnvelopeSealer) Open(ctx context.Context, tenantID string, stored string, aad []byte) ([]byte, error) {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "dv1" {
		return nil, fmt.Errorf("tenantcrypto: malformed dv1 value")
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: malformed dv1 dek")
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("tenantcrypto: malformed dv1 ciphertext")
	}
	return s.env.Open(ctx, crypto.Sealed{KeyID: parts[1], WrappedDEK: wrapped, Ciphertext: ct}, bindAAD(tenantID, aad))
}

// bindAAD binds the tenant identity into the AEAD so a sealed value cannot
// be replayed into another tenant's row.
func bindAAD(tenantID string, aad []byte) []byte {
	return append([]byte("tenant:"+tenantID+":"), aad...)
}

// BindAAD is the exported binding (ee/tenantkeys uses the same construction
// so cross-tenant replay fails regardless of which sealer minted the value).
func BindAAD(tenantID string, aad []byte) []byte { return bindAAD(tenantID, aad) }

// --- The key-management surface contract (S-T6): core DTOs so the /v1
// security routes stay core while the keyring lives in ee/. ---

// KeyInfo is one key version's PUBLIC state (material never crosses).
type KeyInfo struct {
	Version     int    `json:"version"`
	Mode        string `json:"mode"`  // managed | byok
	State       string `json:"state"` // active | retired | destroyed
	CreatedAt   string `json:"created_at"`
	RetiredAt   string `json:"retired_at,omitempty"`
	DestroyedAt string `json:"destroyed_at,omitempty"`
}

// KeyManager manages a tenant's key chain (implemented by ee/tenantkeys;
// installed at the attach seam; absent = the surface hides).
type KeyManager interface {
	KeyStatus(ctx context.Context, tenantID string) ([]KeyInfo, error)
	RotateKey(ctx context.Context, tenantID, mode, byokRef string) (KeyInfo, error)
}
