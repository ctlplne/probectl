// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
)

const irInstallTenant = "88929fbe-28e5-4f0a-898e-6c4302c55e57"

func irPublicKeyPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	crypto.Zeroize(privatePEM)
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	return publicPEM, writer.KeyID()
}

// TestIRKeyInstallPlacesTheKeyWhereTheSealerLooks (DPR-036): a PEM piped on
// stdin becomes PROBECTL_IR_PUBLIC_KEY_DIR/<tenant>.pem, readable by the
// runtime user, and the resolver the break-glass transaction uses resolves it.
func TestIRKeyInstallPlacesTheKeyWhereTheSealerLooks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ir-keys")
	publicPEM, keyID := irPublicKeyPEM(t)
	env := func(k string) string {
		if k == "PROBECTL_IR_PUBLIC_KEY_DIR" {
			return dir
		}
		return ""
	}
	var out bytes.Buffer
	if err := irKeyInstall([]string{irInstallTenant}, bytes.NewReader(publicPEM), env, &out); err != nil {
		t.Fatalf("install: %v", err)
	}
	target := filepath.Join(dir, irInstallTenant+".pem")
	if !strings.Contains(out.String(), "path="+target) || !strings.Contains(out.String(), "key_id="+keyID) {
		t.Fatalf("stdout = %q", out.String())
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %04o, want 0644 (public material the runtime uid must read)", info.Mode().Perm())
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, publicPEM) {
		t.Fatal("installed PEM differs from stdin")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("keyring holds %d entries, want only the installed key (no temp files)", len(entries))
	}
	resolver, err := audit.NewLocalIRPublicKeyResolver(dir)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.WrapProviderForTenant(t.Context(), irInstallTenant)
	if err != nil {
		t.Fatalf("the sealer's resolver must find the installed key: %v", err)
	}
	if provider.KeyID() != keyID {
		t.Fatalf("resolved key id %q, want %q", provider.KeyID(), keyID)
	}
}

func TestIRKeyInstallRefusesBadInputAndSilentRotation(t *testing.T) {
	dir := t.TempDir()
	publicPEM, keyID := irPublicKeyPEM(t)
	noEnv := func(string) string { return "" }
	target := filepath.Join(dir, irInstallTenant+".pem")

	cases := []struct {
		name  string
		args  []string
		stdin []byte
		want  string
	}{
		{"usage", nil, publicPEM, "usage:"},
		{"tenant id", []string{"acme", "-dir", dir}, publicPEM, "canonical UUID"},
		{"no directory", []string{irInstallTenant}, publicPEM, "PROBECTL_IR_PUBLIC_KEY_DIR"},
		{"relative directory", []string{irInstallTenant, "-dir", "relative/keys"}, publicPEM, "absolute"},
		{"empty stdin", []string{irInstallTenant, "-dir", dir}, nil, "stdin is empty"},
		{"not a key", []string{irInstallTenant, "-dir", dir}, []byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"), "not a usable IR public key"},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		err := irKeyInstall(tc.args, bytes.NewReader(tc.stdin), noEnv, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if _, statErr := os.Stat(target); statErr == nil {
			t.Fatalf("%s: a refused install must not leave a key behind", tc.name)
		}
	}

	var out bytes.Buffer
	if err := irKeyInstall([]string{irInstallTenant, "-dir", dir}, bytes.NewReader(publicPEM), noEnv, &out); err != nil {
		t.Fatal(err)
	}
	rotated, rotatedID := irPublicKeyPEM(t)
	err := irKeyInstall([]string{irInstallTenant, "-dir", dir}, bytes.NewReader(rotated), noEnv, &out)
	if err == nil || !strings.Contains(err.Error(), "-replace") {
		t.Fatalf("second install without -replace: err = %v, want a rotation hint", err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, publicPEM) {
		t.Fatal("a refused overwrite must leave the existing key untouched")
	}
	out.Reset()
	if err := irKeyInstall([]string{irInstallTenant, "-dir", dir, "-replace"}, bytes.NewReader(rotated), noEnv, &out); err != nil {
		t.Fatalf("rotation with -replace: %v", err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, rotated) {
		t.Fatal("-replace must install the new key")
	}
	if !strings.Contains(out.String(), "key_id="+rotatedID) || !strings.Contains(out.String(), "replaced_key_id="+keyID) {
		t.Fatalf("rotation stdout = %q", out.String())
	}
}

func TestIRKeyInstallIsAnEarlyNoDatabaseCommand(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = []string{"probectl-control", "ir-key-install"}
	handled, err := dispatchEarlyCommand("ir-key-install")
	if !handled {
		t.Fatal("ir-key-install must be handled before any database or config is loaded")
	}
	if err == nil || !strings.Contains(err.Error(), "usage: probectl-control ir-key-install") {
		t.Fatalf("err = %v, want the usage error", err)
	}
	_, err = dispatchEarlyCommand("no-such-command")
	if err == nil || !strings.Contains(err.Error(), "ir-key-install") {
		t.Fatalf("the unknown-command usage must list ir-key-install: %v", err)
	}
}
