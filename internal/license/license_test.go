// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package license

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/usage"
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

func TestLoadBoundsLicenseFile(t *testing.T) {
	const maxBytes = 1 << 20

	priv, pub := testKeypair(t)
	raw, err := Sign(
		testClaims(TierEnterprise, time.Now().Add(24*time.Hour)),
		priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > maxBytes {
		t.Fatalf("signed test license is %d bytes, exceeds boundary fixture", len(raw))
	}

	exact := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), maxBytes-len(raw))...)
	tests := []struct {
		name    string
		body    []byte
		wantErr string
	}{
		{name: "exact limit", body: exact},
		{
			name:    "one byte over",
			body:    append(append([]byte(nil), exact...), ' '),
			wantErr: "license file exceeds 1048576-byte limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "license.json")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path, [][]byte{pub})
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Load exact-limit license: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Load oversized license error = %v, want %q", err, tc.wantErr)
			}
		})
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

func TestLicenseReadOnlyMutationCapabilityTransitionsWithoutRestart(t *testing.T) {
	expires := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	now := expires.Add(-time.Hour)
	claims := testClaims(TierEnterprise, expires)
	m := &Manager{claims: &claims, clock: func() time.Time { return now }}

	// Capture the capability once, exactly as the ee attach seam does. Moving
	// the clock must change the answer without rebuilding that capability.
	writes := m.WriteCapability()
	if !writes.Enabled() {
		t.Fatal("active license must permit attached commercial writes")
	}
	now = expires.Add(GracePeriod - time.Second)
	if !writes.Enabled() {
		t.Fatal("grace license must continue permitting attached commercial writes")
	}

	now = expires.Add(GracePeriod)
	if writes.Enabled() {
		t.Fatal("read-only license must deny attached commercial writes")
	}
	for _, feature := range []Feature{FeatureBYOK, FeatureRemediation} {
		if !m.Has(feature) || m.Mode(feature) != ModeReadOnly {
			t.Fatalf("%s must stay attached/readable in read-only mode: has=%v mode=%s",
				feature, m.Has(feature), m.Mode(feature))
		}
	}

	if Community().WriteCapability().Enabled() {
		t.Fatal("community manager must fail closed for commercial writes")
	}
	var nilCapability WriteCapability
	if nilCapability.Enabled() {
		t.Fatal("nil write capability must fail closed")
	}
}

// --- tier mapping + inheritance ---

func TestTierTableAndExtras(t *testing.T) {
	// Table integrity: MSP is a strict superset of Enterprise, while the two
	// resale-only capabilities never leak into Enterprise.
	enterprise := map[Feature]bool{}
	for _, f := range featuresForTier(TierEnterprise) {
		enterprise[f] = true
	}
	msp := map[Feature]bool{}
	for _, f := range featuresForTier(TierMSP) {
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

	// DPR-190: the baseline is whatever trusted_keys/*.pub this tree SHIPS, not
	// zero. This test used to assert that an empty bake yields no keys at all,
	// which was true only while the directory was empty — so it failed the
	// moment the product finally shipped the anchor it must ship, and the
	// failure looked like a regression in key parsing rather than what it was.
	builtinPubKeysB64 = ""
	embedded := TrustedKeys()

	_, pub1 := testKeypair(t)
	_, pub2 := testKeypair(t)
	builtinPubKeysB64 = base64.StdEncoding.EncodeToString(pub1) + "," + base64.StdEncoding.EncodeToString(pub2)
	keys := TrustedKeys()
	if len(keys) != len(embedded)+2 {
		t.Fatalf("rotation bake parsed wrong: %d keys with %d embedded", len(keys), len(embedded))
	}
	// Link-time keys come after the embedded ones, in the order they were baked.
	if string(keys[len(keys)-2]) != string(pub1) || string(keys[len(keys)-1]) != string(pub2) {
		t.Fatal("baked keys must follow the embedded anchors, in bake order")
	}
	for i, want := range embedded {
		if string(keys[i]) != string(want) {
			t.Fatalf("embedded anchor %d changed when a bake was added", i)
		}
	}
}
