// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

func TestSetupSecretsAndEnvelopeRequiresKeyUnlessExplicitDev(t *testing.T) {
	clearSecretBackendEnv(t)

	t.Run("keyless without dev escape hatch fails closed", func(t *testing.T) {
		tenantcrypto.Reset()
		t.Cleanup(tenantcrypto.Reset)

		_, _, err := setupSecretsAndEnvelope(&config.Config{RequireAtRestEncryption: false})
		if err == nil {
			t.Fatal("setupSecretsAndEnvelope unexpectedly allowed implicit keyless plaintext")
		}
		if !strings.Contains(err.Error(), "PROBECTL_ALLOW_KEYLESS_DEV=true") {
			t.Fatalf("error must name the explicit dev escape hatch, got %v", err)
		}
	})

	t.Run("explicit keyless dev mode is passthrough", func(t *testing.T) {
		tenantcrypto.Reset()
		t.Cleanup(tenantcrypto.Reset)

		_, generated, err := setupSecretsAndEnvelope(&config.Config{AllowKeylessDev: true, RequireAtRestEncryption: true})
		if err != nil {
			t.Fatalf("setup explicit dev keyless: %v", err)
		}
		if generated {
			t.Fatal("keyless dev mode must not generate a hidden envelope key")
		}
		stored, err := tenantcrypto.Seal(context.Background(), "tenant-a", []byte("sekret"), []byte("test"))
		if err != nil {
			t.Fatalf("seal in keyless dev: %v", err)
		}
		if stored != "sekret" {
			t.Fatalf("keyless dev should be plaintext passthrough, got %q", stored)
		}
	})

	t.Run("configured envelope key installs a real sealer", func(t *testing.T) {
		tenantcrypto.Reset()
		t.Cleanup(tenantcrypto.Reset)

		kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		_, _, err := setupSecretsAndEnvelope(&config.Config{EnvelopeKey: kek, EnvelopeKeyID: "test", RequireAtRestEncryption: true})
		if err != nil {
			t.Fatalf("setup envelope key: %v", err)
		}
		stored, err := tenantcrypto.Seal(context.Background(), "tenant-a", []byte("sekret"), []byte("test"))
		if err != nil {
			t.Fatalf("seal with envelope key: %v", err)
		}
		if stored == "sekret" || !strings.HasPrefix(stored, "dv1:") {
			t.Fatalf("configured key must store ciphertext with dv1 scheme, got %q", stored)
		}
	})
}

func clearSecretBackendEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PROBECTL_SECRETS_VAULT_ADDR",
		"PROBECTL_SECRETS_VAULT_TOKEN",
		"PROBECTL_SECRETS_VAULT_ROLE_ID",
		"PROBECTL_SECRETS_VAULT_SECRET_ID",
		"PROBECTL_SECRETS_VAULT_NAMESPACE",
		"PROBECTL_SECRETS_CYBERARK_URL",
		"PROBECTL_SECRETS_CYBERARK_APP_ID",
		"PROBECTL_SECRETS_CYBERARK_CERT_FILE",
		"PROBECTL_SECRETS_CYBERARK_KEY_FILE",
		"PROBECTL_SECRETS_CYBERARK_CA_FILE",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AZURE_TENANT_ID",
		"AZURE_CLIENT_ID",
		"AZURE_CLIENT_SECRET",
		"GOOGLE_APPLICATION_CREDENTIALS",
	} {
		t.Setenv(k, "")
	}
}
