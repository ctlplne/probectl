// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
)

func TestBuildLicenseGating(t *testing.T) {
	// Unconfigured = Community, never an error (default-open).
	m, err := BuildLicense(&config.Config{}, intelTestLog())
	if err != nil || m.Tier() != license.TierCore {
		t.Fatalf("unconfigured: tier=%v err=%v", m.Tier(), err)
	}
	// Configured-but-missing fails startup (fail closed on configuration).
	if _, err := BuildLicense(&config.Config{LicenseFile: "/does/not/exist.json"}, intelTestLog()); err == nil {
		t.Fatal("missing configured license must fail startup")
	}
	// A configured file in a build with no baked keys fails loudly (this dev
	// build bakes none — the trust anchor is a release-time decision).
	path := filepath.Join(t.TempDir(), "license.json")
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_x", Customer: "Acme", Tier: license.TierEnterprise,
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildLicense(&config.Config{LicenseFile: path}, intelTestLog()); err == nil {
		t.Fatal("a license against a keyless build must fail startup, loudly")
	}
}

// The Editions endpoint — the ONE place tiers appear when unlicensed.
func TestEditionsEndpoint(t *testing.T) {
	// Community truth (no license attached).
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/editions")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var info license.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Tier != license.TierCore || info.State != license.StateCommunity {
		t.Fatalf("community truth wrong: %+v", info)
	}
	if len(info.Features) != len(license.AllFeatures()) {
		t.Fatalf("the full feature table must render: %d", len(info.Features))
	}
	for _, f := range info.Features {
		if f.Licensed || f.Mode != license.ModeOff {
			t.Fatalf("community must show %s unlicensed/off", f.Name)
		}
	}

	// Licensed truth: an MSP license renders its inherited grants, consumption
	// metadata, meter vocabulary, band, and expiry horizon.
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_msp_1", Customer: "Reseller GmbH", Tier: license.TierMSP,
		TenantBand: 25, IssuedAt: time.Now().UTC(), ExpiresAt: expires,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	srv = testServer(fakePinger{}).WithLicense(m)
	rec = do(srv, http.MethodGet, "/v1/editions")
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Tier != license.TierMSP || info.PricingModel != license.PricingModelConsumption || info.State != license.StateActive ||
		info.Customer != "Reseller GmbH" || info.TenantBand != 25 {
		t.Fatalf("licensed truth wrong: %+v", info)
	}
	if len(info.Meters) != 6 {
		t.Fatalf("MSP meters missing: %v", info.Meters)
	}
	if info.ExpiresAt == nil || !info.ExpiresAt.Equal(expires) || info.ReadOnlyAt == nil {
		t.Fatal("expiry horizon missing")
	}
	var providerOn, fipsOn, haClarified bool
	for _, f := range info.Features {
		if f.Name == license.FeatureProviderPlane && f.Licensed && f.Mode == license.ModeEnabled {
			providerOn = true
		}
		if f.Name == license.FeatureFIPS && f.Licensed {
			fipsOn = true
		}
		if f.Name == license.FeatureHASupport && f.DisplayName == "HA support/SLA" {
			haClarified = true
		}
	}
	if !providerOn || !fipsOn || !haClarified {
		t.Fatalf("feature rows wrong: %+v", info.Features)
	}
}
