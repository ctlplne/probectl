// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//   - No license file = Core: the full core, forever (default-open).
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
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/usage"
)

// Tier names an edition.
type Tier string

// The editions. Core is the unlicensed default; Enterprise and MSP are the
// only issuable tiers.
const (
	TierCore       Tier = "core"
	TierEnterprise Tier = "enterprise"
	TierMSP        Tier = "msp"

	// legacyTierProvider is accepted only while verifying already-signed v1
	// development licenses. New licenses are always issued as TierMSP.
	legacyTierProvider  Tier = "provider"
	maxLicenseFileBytes      = 1 << 20
)

// PricingModel is descriptive commercial metadata. It never grants a feature
// and therefore cannot become a second license-gating table.
type PricingModel string

// Pricing models carried by commercial licenses.
const (
	PricingModelFlat        PricingModel = "flat"
	PricingModelConsumption PricingModel = "consumption"
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
	// Enterprise isolation and MSP resale operations.
	FeatureProviderPlane   Feature = "provider_plane"
	FeatureSiloedIsolation Feature = "siloed_isolation"
	FeatureMetering        Feature = "metering"
)

// tierFeatures is THE feature→tier table — the only one in the codebase.
// Deliberately core (free): per-tenant export/deletion (S-T5), fairness
// enforcement (S-T7), support-bundle generation (S-EE4) — they never appear
// here because they are not gated.
var tierFeatures = map[Tier][]Feature{
	TierCore: {},
	TierEnterprise: {
		FeatureFIPS, FeatureBYOK, FeatureGovernance, FeatureRemediation,
		FeatureHASupport, FeatureSiloedIsolation,
	},
	TierMSP: {
		FeatureFIPS, FeatureBYOK, FeatureGovernance, FeatureRemediation,
		FeatureHASupport, FeatureSiloedIsolation, FeatureProviderPlane,
		FeatureMetering,
	},
}

// TierFeatures returns a tier's feature set (copy).
func TierFeatures(t Tier) []Feature {
	return append([]Feature(nil), tierFeatures[t]...)
}

// AllFeatures returns every gated feature once, in stable minimum-tier order.
func AllFeatures() []Feature {
	out := append([]Feature(nil), tierFeatures[TierEnterprise]...)
	seen := make(map[Feature]bool, len(out))
	for _, f := range out {
		seen[f] = true
	}
	for _, f := range tierFeatures[TierMSP] {
		if !seen[f] {
			out = append(out, f)
		}
	}
	return out
}

// FeatureTier returns the minimum tier that grants f by default.
func FeatureTier(f Feature) Tier {
	for _, t := range []Tier{TierEnterprise, TierMSP} {
		fs := tierFeatures[t]
		for _, g := range fs {
			if g == f {
				return t
			}
		}
	}
	return TierCore
}

// DefaultPricingModel returns the commercial model implied by a tier. The
// value is informational: feature grants continue to come only from
// tierFeatures.
func DefaultPricingModel(t Tier) PricingModel {
	switch t {
	case TierEnterprise:
		return PricingModelFlat
	case TierMSP, legacyTierProvider:
		return PricingModelConsumption
	default:
		return ""
	}
}

// Claims is the signed license payload (the wire contract).
type Claims struct {
	V            int          `json:"v"`
	ID           string       `json:"id"`
	Customer     string       `json:"customer"`
	Tier         Tier         `json:"tier"`
	PricingModel PricingModel `json:"pricing_model,omitempty"`
	Features     []Feature    `json:"features,omitempty"`    // explicit extras beyond the tier set (bespoke deals)
	TenantBand   int          `json:"tenant_band,omitempty"` // MSP tenant count; 0 = unlimited
	IssuedAt     time.Time    `json:"issued_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
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

// ErrReadOnly is returned by commercial mutation adapters after an entitled
// license has aged past its grace period. Read/decrypt paths and telemetry do
// not use this error and remain available.
var ErrReadOnly = errors.New("license: commercial features are read-only after expiry; existing reads and telemetry continue")

// WriteCapability is the one dynamic commercial-write decision installed at
// the ee Build/attach seam. Enabled evaluates the license clock on every call,
// so a running process transitions from active/grace to read-only without a
// restart. A nil capability fails closed.
type WriteCapability func() bool

// Enabled reports whether a commercial mutation may proceed.
func (c WriteCapability) Enabled() bool { return c != nil && c() }

// Manager answers tier/feature questions for one loaded license (or the
// Core default). It is immutable after construction.
type Manager struct {
	claims *Claims
	clock  func() time.Time
}

// Community returns the unlicensed Core manager: every gated feature off.
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
	// Compatibility is applied only after signature verification: the signed
	// bytes stay untouched, while callers receive the current tier vocabulary.
	if c.Tier == legacyTierProvider {
		c.Tier = TierMSP
	}
	if c.Tier != TierEnterprise && c.Tier != TierMSP {
		return nil, fmt.Errorf("license: unknown tier %q", c.Tier)
	}
	if c.PricingModel == "" {
		c.PricingModel = DefaultPricingModel(c.Tier)
	}
	if c.PricingModel != PricingModelFlat && c.PricingModel != PricingModelConsumption {
		return nil, fmt.Errorf("license: unknown pricing model %q", c.PricingModel)
	}
	if c.Tier != TierMSP {
		for _, f := range c.Features {
			if FeatureTier(f) == TierMSP {
				return nil, fmt.Errorf("license: feature %q is MSP-only", f)
			}
		}
	}
	if c.ExpiresAt.IsZero() || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return nil, fmt.Errorf("license: invalid validity window")
	}
	return &c, nil
}

// Load reads and verifies the license at path. path == "" means Core
// (nil error — default-open). A configured-but-missing or invalid file is a
// startup ERROR (fail closed on configuration); an EXPIRED license loads
// fine and degrades per the grace ladder.
func Load(path string, trustedPubPEMs [][]byte) (*Manager, error) {
	if path == "" {
		return Community(), nil
	}
	raw, err := readLicenseFile(path)
	if err != nil {
		return nil, fmt.Errorf("license: read %s: %w", path, err)
	}
	claims, err := Verify(raw, trustedPubPEMs)
	if err != nil {
		return nil, err
	}
	return &Manager{claims: claims, clock: time.Now}, nil
}

func readLicenseFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxLicenseFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maxLicenseFileBytes {
		return nil, fmt.Errorf("license file exceeds %d-byte limit", maxLicenseFileBytes)
	}
	return raw, nil
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

// Tier returns the licensed tier (Core when unlicensed).
func (m *Manager) Tier() Tier {
	if m == nil || m.claims == nil {
		return TierCore
	}
	return m.claims.Tier
}

// PricingModel returns descriptive pricing metadata. It never participates in
// feature enforcement; absent v1 values are inferred from the tier.
func (m *Manager) PricingModel() PricingModel {
	if m == nil || m.claims == nil {
		return ""
	}
	if m.claims.PricingModel != "" {
		return m.claims.PricingModel
	}
	return DefaultPricingModel(m.claims.Tier)
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

// WriteCapability returns the dynamic commercial-write decision for the ee
// attach seam. Feature entitlement remains decided by the seam's Has checks;
// this capability only applies the shared lifecycle rule to features that were
// attached. Active and grace permit writes, while community and read-only fail
// closed.
func (m *Manager) WriteCapability() WriteCapability {
	return func() bool {
		switch m.State() {
		case StateActive, StateGrace:
			return true
		default:
			return false
		}
	}
}

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
	Tier         Tier          `json:"tier"`
	PricingModel PricingModel  `json:"pricing_model,omitempty"`
	State        State         `json:"state"`
	Customer     string        `json:"customer,omitempty"`
	LicenseID    string        `json:"license_id,omitempty"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty"`
	ReadOnlyAt   *time.Time    `json:"read_only_at,omitempty"` // when grace ends
	TenantBand   int           `json:"tenant_band,omitempty"`
	Meters       []string      `json:"meters,omitempty"`
	Features     []FeatureInfo `json:"features"`
}

// Info renders the editions view.
func (m *Manager) Info() Info {
	info := Info{Tier: m.Tier(), PricingModel: m.PricingModel(), State: m.State(), Features: []FeatureInfo{}}
	if m != nil && m.claims != nil {
		info.Customer = m.claims.Customer
		info.LicenseID = m.claims.ID
		exp := m.claims.ExpiresAt
		ro := exp.Add(GracePeriod)
		info.ExpiresAt = &exp
		info.ReadOnlyAt = &ro
		info.TenantBand = m.claims.TenantBand
		if m.claims.Tier == TierMSP {
			info.Meters = usage.Meters()
		}
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
