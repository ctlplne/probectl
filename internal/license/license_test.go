// SPDX-License-Identifier: LicenseRef-probectl-TBD

package license

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
		"wrong version":             {V: 2, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"unknown tier":              {V: 1, Tier: "platinum", IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"community is not issuable": {V: 1, Tier: TierCommunity, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		"inverted window":           {V: 1, Tier: TierEnterprise, IssuedAt: now, ExpiresAt: now.Add(-time.Hour)},
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
	c := testClaims(TierProvider, expires)

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
		// A feature outside the tier stays off in every state.
		if m.Mode(FeatureFIPS) != ModeOff {
			t.Errorf("%s: unlicensed feature must be off", tc.name)
		}
	}
}

// --- tier mapping + explicit extras ---

func TestTierTableAndExtras(t *testing.T) {
	// Table integrity: every feature belongs to exactly one tier.
	seen := map[Feature]Tier{}
	for _, tier := range []Tier{TierEnterprise, TierProvider} {
		for _, f := range TierFeatures(tier) {
			if prev, dup := seen[f]; dup {
				t.Fatalf("feature %s in both %s and %s", f, prev, tier)
			}
			seen[f] = tier
		}
	}
	if len(AllFeatures()) != len(seen) {
		t.Fatalf("AllFeatures() = %d features, table has %d", len(AllFeatures()), len(seen))
	}
	for f, tier := range seen {
		if FeatureTier(f) != tier {
			t.Errorf("FeatureTier(%s) = %s want %s", f, FeatureTier(f), tier)
		}
	}

	// An enterprise license grants enterprise features, not provider ones.
	priv, pub := testKeypair(t)
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	ent := managerAt(t, testClaims(TierEnterprise, now.Add(time.Hour)), priv, pub, now)
	if !ent.Has(FeatureBYOK) || ent.Has(FeatureWhiteLabel) {
		t.Fatal("enterprise grant wrong")
	}

	// A bespoke deal: provider + explicit byok extra.
	c := testClaims(TierProvider, now.Add(time.Hour))
	c.Features = []Feature{FeatureBYOK}
	c.TenantBand = 25
	prov := managerAt(t, c, priv, pub, now)
	if !prov.Has(FeatureProviderPlane) || !prov.Has(FeatureBYOK) || prov.Has(FeatureRemediation) {
		t.Fatal("explicit-extras grant wrong")
	}
	if prov.TenantBand() != 25 {
		t.Fatalf("tenant band = %d want 25", prov.TenantBand())
	}
}

// --- community defaults (default-open) + Load semantics ---

func TestCommunityAndLoad(t *testing.T) {
	m := Community()
	if m.Tier() != TierCommunity || m.State() != StateCommunity {
		t.Fatal("community defaults wrong")
	}
	for _, f := range AllFeatures() {
		if m.Has(f) || m.Mode(f) != ModeOff {
			t.Fatalf("community must have %s off", f)
		}
	}
	info := m.Info()
	if info.Tier != TierCommunity || len(info.Features) != len(AllFeatures()) {
		t.Fatalf("community info wrong: %+v", info)
	}

	// Empty path = Community, nil error (default-open).
	if m, err := Load("", nil); err != nil || m.Tier() != TierCommunity {
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
	c := testClaims(TierProvider, expires)
	c.TenantBand = 100
	m := managerAt(t, c, priv, pub, expires.Add(-time.Hour))

	info := m.Info()
	if info.Tier != TierProvider || info.State != StateActive || info.Customer != "Acme Corp" {
		t.Fatalf("info header wrong: %+v", info)
	}
	if info.ExpiresAt == nil || !info.ExpiresAt.Equal(expires) {
		t.Fatal("expiry missing")
	}
	if info.ReadOnlyAt == nil || !info.ReadOnlyAt.Equal(expires.Add(GracePeriod)) {
		t.Fatal("read-only horizon missing")
	}
	var sawLicensed, sawUnlicensed bool
	var sawHAClarified bool
	for _, f := range info.Features {
		if f.Name == FeatureProviderPlane && f.Licensed && f.Mode == ModeEnabled {
			sawLicensed = true
		}
		if f.Name == FeatureFIPS && !f.Licensed && f.Mode == ModeOff {
			sawUnlicensed = true
		}
		if f.Name == FeatureHASupport && f.DisplayName == "HA support/SLA" {
			sawHAClarified = true
		}
	}
	if !sawLicensed || !sawUnlicensed || !sawHAClarified {
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
