// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package license implements probectl's offline edition gating (S-T0): an
// Ed25519-signed license file activates commercial feature sets, verified
// with pure local math against build-time-baked public keys — never a
// phone-home (CLAUDE.md §7 guardrail 2; the editions decisions, §2).
//
// The doctrine, enforced here and checked by the editions CI gate:
//
//   - ONE feature→tier table (this package; nowhere else). Tier checks
//     outside this package's API are a review-blocking defect.
//   - Gating happens only at the main.go Build* seams: a missing entitlement
//     behaves exactly like a disabled feature flag.
//   - No license file = Community: the full core, forever (default-open).
//   - A present-but-invalid license is a STARTUP ERROR (you configured a
//     license; it being forged or corrupt deserves a loud stop) — but an
//     EXPIRED license is never an error: 30 days of grace, then commercial
//     features degrade READ-ONLY. Expired ≠ broken observability.
//
// This package lives in core deliberately (the S-T0 Edition line): the
// verification path must be auditable by anyone, which is what makes
// "no-phone-home licensing" a checkable claim instead of a promise.
package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Tier names an edition.
type Tier string

// The editions (the rate card's code-gated tiers; Starter/Pro differ only in
// entitlements, not code, so they do not appear here).
const (
	TierCommunity  Tier = "community"
	TierEnterprise Tier = "enterprise"
	TierProvider   Tier = "provider"
)

// Feature is one license-gated capability.
type Feature string

// The gated features (ratified mapping, June 2026).
const (
	// Enterprise.
	FeatureFIPS        Feature = "fips" // distribution-gated build artifact
	FeatureBYOK        Feature = "byok"
	FeatureGovernance  Feature = "governance"
	FeatureRemediation Feature = "remediation"
	FeatureHASupport   Feature = "ha_support"
	// Provider / MSP.
	FeatureProviderPlane   Feature = "provider_plane"
	FeatureSiloedIsolation Feature = "siloed_isolation"
	FeatureMetering        Feature = "metering"
	FeatureWhiteLabel      Feature = "white_label"
)

// tierFeatures is THE feature→tier table — the only one in the codebase.
// Deliberately core (free): per-tenant export/deletion (S-T5), fairness
// enforcement (S-T7), support-bundle generation (S-EE4) — they never appear
// here because they are not gated.
var tierFeatures = map[Tier][]Feature{
	TierEnterprise: {FeatureFIPS, FeatureBYOK, FeatureGovernance, FeatureRemediation, FeatureHASupport},
	TierProvider:   {FeatureProviderPlane, FeatureSiloedIsolation, FeatureMetering, FeatureWhiteLabel},
}

// TierFeatures returns a tier's feature set (copy).
func TierFeatures(t Tier) []Feature {
	return append([]Feature(nil), tierFeatures[t]...)
}

// AllFeatures returns every gated feature in stable (tier, declaration) order.
func AllFeatures() []Feature {
	out := append([]Feature(nil), tierFeatures[TierEnterprise]...)
	return append(out, tierFeatures[TierProvider]...)
}

// FeatureTier returns the tier that grants f by default.
func FeatureTier(f Feature) Tier {
	for t, fs := range tierFeatures {
		for _, g := range fs {
			if g == f {
				return t
			}
		}
	}
	return TierCommunity
}

// Claims is the signed license payload (the wire contract).
type Claims struct {
	V          int       `json:"v"`
	ID         string    `json:"id"`
	Customer   string    `json:"customer"`
	Tier       Tier      `json:"tier"`
	Features   []Feature `json:"features,omitempty"`    // explicit extras beyond the tier set (bespoke deals)
	TenantBand int       `json:"tenant_band,omitempty"` // provider tiers: licensed tenant count; 0 = unlimited
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// File is the on-disk shape: the EXACT payload bytes (base64) plus a
// detached Ed25519 signature over those bytes — no canonicalization games.
type File struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// GracePeriod is how long an expired license keeps full function (with a
// banner) before commercial features degrade read-only.
const GracePeriod = 30 * 24 * time.Hour

// State is the license lifecycle state.
type State string

// States.
const (
	StateCommunity State = "community" // no license — the free core
	StateActive    State = "active"
	StateGrace     State = "grace"     // expired ≤ GracePeriod: full function + banner
	StateReadOnly  State = "read_only" // expired > GracePeriod: commercial features stop accepting writes
)

// Mode is a feature's effective enforcement mode.
type Mode string

// Modes.
const (
	ModeEnabled  Mode = "enabled"
	ModeReadOnly Mode = "read_only"
	ModeOff      Mode = "off"
)

// Manager answers tier/feature questions for one loaded license (or the
// Community default). It is immutable after construction.
type Manager struct {
	claims *Claims
	clock  func() time.Time
}

// Community returns the unlicensed manager: every gated feature off.
func Community() *Manager { return &Manager{clock: time.Now} }

// Verify checks a license file's signature against the trusted public keys
// (PEM, tried in order — supports key rotation) and validates the claims.
// Used by Load and by the probectl-license CLI.
func Verify(raw []byte, trustedPubPEMs [][]byte) (*Claims, error) {
	if len(trustedPubPEMs) == 0 {
		return nil, fmt.Errorf("license: no trusted license keys are baked into this build")
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("license: malformed license file: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return nil, fmt.Errorf("license: malformed payload encoding: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return nil, fmt.Errorf("license: malformed signature encoding: %w", err)
	}
	verified := false
	for _, pub := range trustedPubPEMs {
		ok, err := crypto.VerifyEd25519(pub, payload, sig)
		if err == nil && ok {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("license: signature verification failed (forged, corrupted, or signed by an untrusted key)")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("license: malformed claims: %w", err)
	}
	if c.V != 1 {
		return nil, fmt.Errorf("license: unsupported license version %d", c.V)
	}
	if c.Tier != TierEnterprise && c.Tier != TierProvider {
		return nil, fmt.Errorf("license: unknown tier %q", c.Tier)
	}
	if c.ExpiresAt.IsZero() || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return nil, fmt.Errorf("license: invalid validity window")
	}
	return &c, nil
}

// Load reads and verifies the license at path. path == "" means Community
// (nil error — default-open). A configured-but-missing or invalid file is a
// startup ERROR (fail closed on configuration); an EXPIRED license loads
// fine and degrades per the grace ladder.
func Load(path string, trustedPubPEMs [][]byte) (*Manager, error) {
	if path == "" {
		return Community(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("license: read %s: %w", path, err)
	}
	claims, err := Verify(raw, trustedPubPEMs)
	if err != nil {
		return nil, err
	}
	return &Manager{claims: claims, clock: time.Now}, nil
}

// Sign serializes claims, signs the exact payload bytes with the PEM private
// key, and returns the license-file JSON. Used by the probectl-license CLI
// and by tests; signing requires the private key only the issuer holds.
func Sign(c Claims, privPEM []byte) ([]byte, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("license: marshal claims: %w", err)
	}
	sig, err := crypto.SignEd25519(privPEM, payload)
	if err != nil {
		return nil, fmt.Errorf("license: sign: %w", err)
	}
	f := File{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.MarshalIndent(f, "", "  ")
}

// State reports the lifecycle state at the manager's clock.
func (m *Manager) State() State {
	if m == nil || m.claims == nil {
		return StateCommunity
	}
	now := m.clock()
	switch {
	case now.Before(m.claims.ExpiresAt):
		return StateActive
	case now.Before(m.claims.ExpiresAt.Add(GracePeriod)):
		return StateGrace
	default:
		return StateReadOnly
	}
}

// Tier returns the licensed tier (Community when unlicensed).
func (m *Manager) Tier() Tier {
	if m == nil || m.claims == nil {
		return TierCommunity
	}
	return m.claims.Tier
}

// granted reports whether the license grants f at all (tier set or explicit
// extras) — independent of expiry.
func (m *Manager) granted(f Feature) bool {
	if m == nil || m.claims == nil {
		return false
	}
	for _, g := range tierFeatures[m.claims.Tier] {
		if g == f {
			return true
		}
	}
	for _, g := range m.claims.Features {
		if g == f {
			return true
		}
	}
	return false
}

// Mode returns f's effective enforcement mode: off (not licensed), enabled
// (active or in grace), or read_only (expired past grace — existing function
// keeps serving reads; writes/new-config are refused by the feature).
func (m *Manager) Mode(f Feature) Mode {
	if !m.granted(f) {
		return ModeOff
	}
	if m.State() == StateReadOnly {
		return ModeReadOnly
	}
	return ModeEnabled
}

// Has reports whether f is licensed at all (enabled OR read-only). Use Mode
// for write-path enforcement; use Has at the Build* seams so a read-only
// feature still constructs and serves its read paths.
func (m *Manager) Has(f Feature) bool { return m.Mode(f) != ModeOff }

// TenantBand returns the licensed tenant band (0 = unlimited / n-a).
func (m *Manager) TenantBand() int {
	if m == nil || m.claims == nil {
		return 0
	}
	return m.claims.TenantBand
}

// FeatureInfo is one row of the Editions view.
type FeatureInfo struct {
	Name        Feature `json:"name"`
	DisplayName string  `json:"display_name"`
	Tier        Tier    `json:"tier"`
	Licensed    bool    `json:"licensed"`
	Mode        Mode    `json:"mode"`
}

// Info is the Admin → Editions payload — the one place tiers appear when
// unlicensed (the hidden-unlicensed UX, ratified).
type Info struct {
	Tier       Tier          `json:"tier"`
	State      State         `json:"state"`
	Customer   string        `json:"customer,omitempty"`
	LicenseID  string        `json:"license_id,omitempty"`
	ExpiresAt  *time.Time    `json:"expires_at,omitempty"`
	ReadOnlyAt *time.Time    `json:"read_only_at,omitempty"` // when grace ends
	TenantBand int           `json:"tenant_band,omitempty"`
	Features   []FeatureInfo `json:"features"`
}

// Info renders the editions view.
func (m *Manager) Info() Info {
	info := Info{Tier: m.Tier(), State: m.State(), Features: []FeatureInfo{}}
	if m != nil && m.claims != nil {
		info.Customer = m.claims.Customer
		info.LicenseID = m.claims.ID
		exp := m.claims.ExpiresAt
		ro := exp.Add(GracePeriod)
		info.ExpiresAt = &exp
		info.ReadOnlyAt = &ro
		info.TenantBand = m.claims.TenantBand
	}
	for _, f := range AllFeatures() {
		info.Features = append(info.Features, FeatureInfo{
			Name: f, DisplayName: FeatureDisplayName(f), Tier: FeatureTier(f), Licensed: m.granted(f), Mode: m.Mode(f),
		})
	}
	return info
}

// FeatureDisplayName is presentation-only; signed license files and Build* seams
// continue to use the stable feature key.
func FeatureDisplayName(f Feature) string {
	switch f {
	case FeatureHASupport:
		return "HA support/SLA"
	default:
		return string(f)
	}
}
