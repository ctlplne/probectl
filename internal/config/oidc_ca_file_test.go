// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestOIDCCAFileFailsClosed pins the private-CA knob for the deployment IdP: a
// valid PEM bundle loads, while a missing or certificate-less bundle refuses
// startup rather than leaving every login to fail later with an opaque TLS error.
func TestOIDCCAFileFailsClosed(t *testing.T) {
	with := func(caFile string) map[string]string {
		return map[string]string{
			"PROBECTL_OIDC_ISSUER":  "https://dex.probectl.svc.cluster.local:5556/dex",
			"PROBECTL_OIDC_CA_FILE": caFile,
		}
	}
	dir := t.TempDir()

	if _, err := Load(envFunc(with(filepath.Join(dir, "missing.pem")))); err == nil ||
		!strings.Contains(err.Error(), "PROBECTL_OIDC_CA_FILE") {
		t.Errorf("a missing CA bundle must refuse startup, got %v", err)
	}

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(envFunc(with(empty))); err == nil ||
		!strings.Contains(err.Error(), "PROBECTL_OIDC_CA_FILE") {
		t.Errorf("a certificate-less CA bundle must refuse startup, got %v", err)
	}

	ca, err := crypto.GenerateCA("probectl-test-idp-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "idp-ca.pem")
	if err := os.WriteFile(good, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(envFunc(with(good)))
	if err != nil {
		t.Fatalf("a valid CA bundle was rejected: %v", err)
	}
	if cfg.OIDCCAFile != good {
		t.Errorf("OIDCCAFile = %q, want %q", cfg.OIDCCAFile, good)
	}
}
