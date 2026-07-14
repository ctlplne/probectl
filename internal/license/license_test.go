// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package license

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

func testKeypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func testClaims(tier Tier, expires time.Time) Claims {
	return Claims{
		V: 1, ID: "lic_test_001", Customer: "Acme Corp", Tier: tier,
		IssuedAt: expires.Add(-365 * 24 * time.Hour), ExpiresAt: expires,
	}
}

func managerAt(t *testing.T, c Claims, priv, pub []byte, now time.Time) *Manager {
	t.Helper()
	raw, err := Sign(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(raw, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{claims: claims, clock: func() time.Time { return now }}
}

// --- the verify table (signature + claims validation, fail closed) ---

func TestVerifyTable(t *testing.T) {
	priv, pub := testKeypair(t)
	_, otherPub := testKeypair(t)
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	good, err := Sign(testClaims(TierEnterprise, now.Add(24*time.Hour)), priv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		raw     []byte
		trusted [][]byte
		wantErr string
	}{
		{"valid", good, [][]byte{pub}, ""},
		{"valid with rotation (second key matches)", good, [][]byte{otherPub, pub}, ""},
		{"no trusted keys baked", good, nil, "no trusted license keys"},
		{"untrusted signer", good, [][]byte{otherPub}, "verification failed"},
		{"garbage file", []byte("not json"), [][]byte{pub}, "malformed license file"},
		{"tampered payload", tamperPayload(t, good), [][]byte{pub}, "verification failed"},
		{"tampered signature", tamperSignature(t, good), [][]byte{pub}, "verification failed"},
	}
	for _, tc := range tests {
		_, err := Verify(tc.raw, tc.trusted)
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: error = %v, want contains %q", tc.name, err, tc.wantErr)
		}
	}

	// Claims-level rejections (signed correctly, invalid content).
	for name, c := range map[string]Claims{
		"wrong version":         {V: 2, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"unknown tier":          {V: 1, Tier: "platinum", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"core is not issuable":  {V: 1, Tier: TierCore, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"unknown pricing model": {V: 1, Tier: TierEnterprise, PricingModel: "auction", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"MSP feature on enterprise": {
			V: 1, Tier: TierEnterprise, Features: []Feature{FeatureProviderPlane}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		},
		"inverted window": {V: 1, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(-time.Hour)},
	} {
		raw, err := Sign(c, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(raw, [][]byte{pub}); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestVerifyLegacyProviderV1AsMSP(t *testing.T) {
	priv, pub := testKeypair(t)
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	legacy := testClaims(legacyTierProvider, now.Add(time.Hour))

	raw, err := Sign(legacy, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(raw, [][]byte{pub})
	if err != nil {
		t.Fatalf("existing signed v1 provider license must keep verifying: %v", err)
	}
	if c.Tier != TierMSP || c.PricingModel != PricingModelConsumption {
		t.Fatalf("legacy claims normalize to msp/consumption: %+v", c)
	}
}

func tamperPayload(t *testing.T, raw []byte) []byte {
	t.Helper()
	s := string(raw)
	// Claims payloads carry "Acme Corp" base64-encoded; flip one payload char.
	i := strings.Index(s, `"payload": "`) + len(`"payload": "`)
	b := []byte(s)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return b
}

func tamperSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	s := string(raw)
	i := strings.Index(s, `"signature": "`) + len(`"signature": "`)
	b := []byte(s)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return b
}

// --- the grace → read-only ladder (the ratified expiry posture) ---

func TestStateLadderAndDegrade(t *testing.T) {
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	c := testClaims(TierMSP, expires)

	tests := []struct {
		name      string
		now       time.Time
		wantState State
		wantMode  Mode // for provider_plane
	}{
		{"active", expires.Add(-time.Hour), StateActive, ModeEnabled},
		{"grace day 1", expires.Add(24 * time.Hour), StateGrace, ModeEnabled},
		{"grace day 29", expires.Add(29 * 24 * time.Hour), StateGrace, ModeEnabled},
		{"read-only day 31", expires.Add(31 * 24 * time.Hour), StateReadOnly, ModeReadOnly},
	}
	for _, tc := range tests {
		m := managerAt(t, c, priv, pub, tc.now)
		if got := m.State(); got != tc.wantState {
			t.Errorf("%s: state = %s want %s", tc.name, got, tc.wantState)
		}
		if got := m.Mode(FeatureProviderPlane); got != tc.wantMode {
			t.Errorf("%s: mode = %s want %s", tc.name, got, tc.wantMode)
		}
		// Read-only is still licensed: Has stays true so read paths keep
		// serving (expired ≠ broken observability).
		if !m.Has(FeatureProviderPlane) {
			t.Errorf("%s: Has must remain true while licensed", tc.name)
		}
		// MSP inherits the Enterprise feature set in every state.
		if m.Mode(FeatureFIPS) != tc.wantMode {
			t.Errorf("%s: inherited enterprise feature mode = %s want %s", tc.name, m.Mode(FeatureFIPS), tc.wantMode)
		}
	}
}

// --- tier mapping + inheritance ---

func TestTierTableAndExtras(t *testing.T) {
	// Table integrity: MSP is a strict superset of Enterprise, while the two
	// resale-only capabilities never leak into Enterprise.
	enterprise := map[Feature]bool{}
	for _, f := range TierFeatures(TierEnterprise) {
		enterprise[f] = true
	}
	msp := map[Feature]bool{}
	for _, f := range TierFeatures(TierMSP) {
		msp[f] = true
	}
	for f := range enterprise {
		if !msp[f] {
			t.Errorf("MSP must inherit Enterprise feature %s", f)
		}
	}
	if enterprise[FeatureProviderPlane] || enterprise[FeatureMetering] {
		t.Fatal("Enterprise must not expose provider_plane or metering")
	}
	if !msp[FeatureProviderPlane] || !msp[FeatureMetering] {
		t.Fatal("MSP must expose provider_plane and metering")
	}
	if len(AllFeatures()) != len(msp) {
		t.Fatalf("AllFeatures() = %d features, MSP table has %d", len(AllFeatures()), len(msp))
	}
	if FeatureTier(FeatureBYOK) != TierEnterprise || FeatureTier(FeatureProviderPlane) != TierMSP {
		t.Fatal("minimum feature tiers are wrong")
	}

	// An enterprise license grants every self-hosted ee feature, but never the
	// MSP resale plane.
	priv, pub := testKeypair(t)
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	ent := managerAt(t, testClaims(TierEnterprise, now.Add(time.Hour)), priv, pub, now)
	if !ent.Has(FeatureBYOK) || !ent.Has(FeatureSiloedIsolation) || ent.Has(FeatureProviderPlane) || ent.Has(FeatureMetering) {
		t.Fatal("enterprise grant wrong")
	}
	if ent.PricingModel() != PricingModelFlat || len(ent.Info().Meters) != 0 {
		t.Fatalf("enterprise pricing metadata wrong: %+v", ent.Info())
	}

	// MSP automatically receives the complete Enterprise set plus its resale
	// plane and consumption meters.
	c := testClaims(TierMSP, now.Add(time.Hour))
	c.TenantBand = 25
	mspManager := managerAt(t, c, priv, pub, now)
	if !mspManager.Has(FeatureProviderPlane) || !mspManager.Has(FeatureBYOK) || !mspManager.Has(FeatureRemediation) {
		t.Fatal("msp superset grant wrong")
	}
	if mspManager.TenantBand() != 25 {
		t.Fatalf("tenant band = %d want 25", mspManager.TenantBand())
	}
}

// --- community defaults (default-open) + Load semantics ---

func TestCommunityAndLoad(t *testing.T) {
	m := Community()
	if m.Tier() != TierCore || m.State() != StateCommunity {
		t.Fatal("core defaults wrong")
	}
	for _, f := range AllFeatures() {
		if m.Has(f) || m.Mode(f) != ModeOff {
			t.Fatalf("community must have %s off", f)
		}
	}
	info := m.Info()
	if info.Tier != TierCore || info.PricingModel != "" || len(info.Features) != len(AllFeatures()) {
		t.Fatalf("core info wrong: %+v", info)
	}

	// Empty path = Community, nil error (default-open).
	if m, err := Load("", nil); err != nil || m.Tier() != TierCore {
		t.Fatalf("Load(\"\") = %v, %v", m.Tier(), err)
	}
	// Configured-but-missing = startup error (fail closed on config).
	if _, err := Load("/does/not/exist.json", nil); err == nil {
		t.Fatal("missing configured license must error")
	}
	// A valid file round-trips through Load.
	priv, pub := testKeypair(t)
	raw, err := Sign(testClaims(TierEnterprise, time.Now().Add(time.Hour)), priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "probectl-license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	lm, err := Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	if lm.Tier() != TierEnterprise || !lm.Has(FeatureGovernance) {
		t.Fatal("loaded license wrong")
	}
	// The same file against a build with no baked keys fails loudly.
	if _, err := Load(path, nil); err == nil || !strings.Contains(err.Error(), "no trusted license keys") {
		t.Fatalf("keyless build must reject a configured license, got %v", err)
	}
}

// --- the editions view ---

func TestInfoRendersLicenseTruth(t *testing.T) {
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	c := testClaims(TierMSP, expires)
	c.TenantBand = 100
	m := managerAt(t, c, priv, pub, expires.Add(-time.Hour))

	info := m.Info()
	if info.Tier != TierMSP || info.PricingModel != PricingModelConsumption || info.State != StateActive || info.Customer != "Acme Corp" {
		t.Fatalf("info header wrong: %+v", info)
	}
	if len(info.Meters) != len(usage.Meters()) {
		t.Fatalf("MSP meter vocabulary missing: %v", info.Meters)
	}
	if info.ExpiresAt == nil || !info.ExpiresAt.Equal(expires) {
		t.Fatal("expiry missing")
	}
	if info.ReadOnlyAt == nil || !info.ReadOnlyAt.Equal(expires.Add(GracePeriod)) {
		t.Fatal("read-only horizon missing")
	}
	var sawProvider, sawEnterprise bool
	var sawHAClarified bool
	for _, f := range info.Features {
		if f.Name == FeatureProviderPlane && f.Licensed && f.Mode == ModeEnabled {
			sawProvider = true
		}
		if f.Name == FeatureFIPS && f.Licensed && f.Mode == ModeEnabled && f.Tier == TierEnterprise {
			sawEnterprise = true
		}
		if f.Name == FeatureHASupport && f.DisplayName == "HA support/SLA" {
			sawHAClarified = true
		}
	}
	if !sawProvider || !sawEnterprise || !sawHAClarified {
		t.Fatalf("feature rows wrong: %+v", info.Features)
	}
}

func TestTrustedKeysParsesLdflagsPayload(t *testing.T) {
	old := builtinPubKeysB64
	defer func() { builtinPubKeysB64 = old }()

	builtinPubKeysB64 = ""
	if TrustedKeys() != nil {
		t.Fatal("empty bake must yield no keys")
	}
	_, pub1 := testKeypair(t)
	_, pub2 := testKeypair(t)
	builtinPubKeysB64 = base64.StdEncoding.EncodeToString(pub1) + "," + base64.StdEncoding.EncodeToString(pub2)
	keys := TrustedKeys()
	if len(keys) != 2 || string(keys[0]) != string(pub1) || string(keys[1]) != string(pub2) {
		t.Fatalf("rotation bake parsed wrong: %d keys", len(keys))
	}
}
