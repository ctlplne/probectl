// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
)

const cliIRTenantA = "00000000-0000-0000-0000-0000000000a1"

func TestAuditSealPrivateKeyCreatesUsableEncryptedVersion(t *testing.T) {
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zeroize(privatePEM)
	inputDir := t.TempDir()
	if err := os.Chmod(inputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(inputDir, "tenant-private.pem")
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	unlockBytes := bytes.Repeat([]byte{0x35}, crypto.KeySize)
	unlockPath := filepath.Join(inputDir, "artifact-unlock.b64")
	if err := os.WriteFile(
		unlockPath,
		[]byte(base64.StdEncoding.EncodeToString(unlockBytes)+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	outputDir := t.TempDir()
	if err := os.Chmod(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCLI(
		[]string{
			"audit", "seal-private-key", cliIRTenantA,
			"--private-key-file", privatePath,
			"--unlock-key-file", unlockPath,
			"--unlock-key-id", "operator-ir-unlock-v1",
			"--output-dir", outputDir,
		},
		func(string) string { return "" },
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	filename, err := audit.IRPrivateKeyArtifactFilename(
		cliIRTenantA,
		writer.KeyID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(outputDir, filename)
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(artifact, []byte("PRIVATE KEY")) ||
		bytes.Contains(artifact, privatePEM) {
		t.Fatal("sealed CLI artifact contains plaintext private-key material")
	}
	if !strings.Contains(stdout.String(), artifactPath) ||
		!strings.Contains(stdout.String(), writer.KeyID()) {
		t.Fatalf("stdout=%q", stdout.String())
	}
	unlock, err := crypto.NewStaticKeyProvider(
		"operator-ir-unlock-v1",
		unlockBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := audit.NewLocalIRPrivateKeyResolver(outputDir, unlock)
	if err != nil {
		t.Fatal(err)
	}
	opened, cleanup, err := resolver.OpenProviderForTenant(
		t.Context(),
		cliIRTenantA,
		writer.KeyID(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if opened.KeyID() != writer.KeyID() {
		cleanup()
		t.Fatalf("opened key ID = %q, want %q", opened.KeyID(), writer.KeyID())
	}
	cleanup()
}

// TestAuditIRKeygenMintsAKeyringEntryAndSealableEscrow (DPR-036): the public
// half lands as <tenant>.pem (the keyring contract the break-glass sealer
// reads), the private half is owner-only escrow that `seal-private-key`
// accepts unchanged, both halves share one key ID, and a re-run never
// overwrites either file.
func TestAuditIRKeygenMintsAKeyringEntryAndSealableEscrow(t *testing.T) {
	publicDir := t.TempDir()
	escrowDir := t.TempDir()
	if err := os.Chmod(escrowDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(escrowDir, "acme-ir-private.pem")
	env := func(string) string { return "" }
	var stdout, stderr bytes.Buffer
	code := runCLI(
		[]string{
			"audit", "ir-keygen", cliIRTenantA,
			"--public-key-dir", publicDir,
			"--private-key-file", privatePath,
		},
		env, &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	publicPath := filepath.Join(publicDir, cliIRTenantA+".pem")
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("public key must be written as <tenant>.pem: %v", err)
	}
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatalf("public half must be the resolver's RSA-OAEP wrap key: %v", err)
	}
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := crypto.NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		t.Fatalf("private half must be a PKCS#8 RSA key: %v", err)
	}
	if opener.KeyID() != writer.KeyID() {
		t.Fatalf("key ids differ: private %q public %q", opener.KeyID(), writer.KeyID())
	}
	if info, _ := os.Stat(privatePath); info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %04o, want 0600", info.Mode().Perm())
	}
	if info, _ := os.Stat(publicPath); info.Mode().Perm() != 0o644 {
		t.Fatalf("public key mode = %04o, want 0644", info.Mode().Perm())
	}
	want := "public=" + publicPath + " private=" + privatePath + " key_id=" + writer.KeyID()
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if !strings.Contains(stderr.String(), "ir-key-install "+cliIRTenantA) ||
		!strings.Contains(stderr.String(), "seal-private-key "+cliIRTenantA) {
		t.Fatalf("stderr must name the next two steps: %q", stderr.String())
	}

	// A second run must not silently rotate either half.
	stdout.Reset()
	stderr.Reset()
	code = runCLI(
		[]string{
			"audit", "ir-keygen", cliIRTenantA,
			"--public-key-dir", publicDir,
			"--private-key-file", privatePath,
		},
		env, &stdout, &stderr,
	)
	if code == 0 {
		t.Fatal("re-running keygen must refuse to overwrite an existing key")
	}
	if again, _ := os.ReadFile(privatePath); !bytes.Equal(again, privatePEM) {
		t.Fatal("refused re-run must leave the private key untouched")
	}

	// The documented next step accepts the escrow file unchanged.
	unlockBytes := bytes.Repeat([]byte{0x41}, crypto.KeySize)
	unlockPath := filepath.Join(escrowDir, "unlock.b64")
	if err := os.WriteFile(unlockPath, []byte(base64.StdEncoding.EncodeToString(unlockBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	sealedDir := t.TempDir()
	if err := os.Chmod(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = runCLI(
		[]string{
			"audit", "seal-private-key", cliIRTenantA,
			"--private-key-file", privatePath,
			"--unlock-key-file", unlockPath,
			"--unlock-key-id", "operator-ir-unlock-v1",
			"--output-dir", sealedDir,
		},
		env, &stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("seal-private-key on keygen output: exit=%d stderr=%s", code, stderr.String())
	}
	filename, err := audit.IRPrivateKeyArtifactFilename(cliIRTenantA, writer.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sealedDir, filename)); err != nil {
		t.Fatalf("sealed artifact for the keygen key id must exist: %v", err)
	}
}

func TestAuditIRKeygenRejectsUnsafeArguments(t *testing.T) {
	publicDir := t.TempDir()
	escrowDir := t.TempDir()
	if err := os.Chmod(escrowDir, 0o700); err != nil {
		t.Fatal(err)
	}
	groupReadable := t.TempDir()
	if err := os.Chmod(groupReadable, 0o750); err != nil {
		t.Fatal(err)
	}
	env := func(string) string { return "" }
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no tenant", []string{"audit", "ir-keygen"}, "missing <tenant-id>"},
		{"bad tenant", []string{"audit", "ir-keygen", "acme", "--public-key-dir", publicDir, "--private-key-file", filepath.Join(escrowDir, "k.pem")}, "canonical UUID"},
		{"missing flags", []string{"audit", "ir-keygen", cliIRTenantA}, "is required"},
		{"relative public dir", []string{"audit", "ir-keygen", cliIRTenantA, "--public-key-dir", "keys", "--private-key-file", filepath.Join(escrowDir, "k.pem")}, "--public-key-dir"},
		{"shared escrow dir", []string{"audit", "ir-keygen", cliIRTenantA, "--public-key-dir", publicDir, "--private-key-file", filepath.Join(groupReadable, "k.pem")}, "owner-only"},
	}
	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		if code := runCLI(tc.args, env, &stdout, &stderr); code != 2 {
			t.Fatalf("%s: exit=%d stderr=%s", tc.name, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), tc.want) {
			t.Fatalf("%s: stderr = %q, want %q", tc.name, stderr.String(), tc.want)
		}
	}
	if entries, _ := os.ReadDir(publicDir); len(entries) != 0 {
		t.Fatal("refused runs must not write a public key")
	}
}
