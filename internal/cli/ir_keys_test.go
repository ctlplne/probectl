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
