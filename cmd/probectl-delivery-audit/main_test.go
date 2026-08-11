// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/deliveryaudit"
)

func TestCLISealVerifyAndLintFailedReceipt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	artifactPath := filepath.Join(root, "failure.txt")
	if err := os.WriteFile(artifactPath, []byte("live UI failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	draft := deliveryaudit.Receipt{
		Schema:       deliveryaudit.ReceiptSchema,
		ReceiptID:    "failed-cli-test",
		Item:         "CL-002",
		CapabilityID: "test-capability",
		Status:       deliveryaudit.OutcomeFailed,
		StartedAt:    now,
		CompletedAt:  now.Add(time.Minute),
		Artifacts:    []deliveryaudit.Artifact{{Path: "failure.txt", Kind: deliveryaudit.ArtifactOther}},
		FailureReasons: []string{
			"rendered UI failed",
		},
	}
	draftData, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	draftPath := filepath.Join(root, "draft.json")
	if err := os.WriteFile(draftPath, draftData, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "signer.pem")
	receiptPath := filepath.Join(root, "receipt.json")
	stdout, stderr, code := runCommand(
		"seal", "--draft", draftPath, "--artifacts", root,
		"--key", keyPath, "--out", receiptPath,
	)
	if code != 0 {
		t.Fatalf("seal code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, `"signing_key_generated":true`) || !strings.Contains(stdout, `"status":"FAILED"`) {
		t.Fatalf("seal output = %s", stdout)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("signing key mode = %04o, want 0600", got)
	}

	stdout, stderr, code = runCommand("verify", "--receipt", receiptPath, "--artifacts", root)
	if code != 0 || !strings.Contains(stdout, `"cryptographic_status":"SIGNATURE_VALID_UNTRUSTED"`) {
		t.Fatalf("plain verify code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	stdout, stderr, code = runCommand("lint", "--receipt", receiptPath, "--artifacts", root)
	if code != 1 || !strings.Contains(stdout, `"code":"status-failed"`) {
		t.Fatalf("lint code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}

	privatePEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := probcrypto.PublicPEMFromPrivate(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "signer.pub")
	if err := os.WriteFile(publicPath, publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCommand(
		"verify", "--receipt", receiptPath, "--artifacts", root,
		"--trusted-public-key", publicPath,
	)
	if code != 0 || !strings.Contains(stdout, `"cryptographic_status":"SIGNATURE_VALID_TRUSTED"`) {
		t.Fatalf("trusted verify code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	_, wrongPublicPEM, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(root, "wrong.pub")
	if err := os.WriteFile(wrongPath, wrongPublicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runCommand(
		"verify", "--receipt", receiptPath, "--artifacts", root,
		"--trusted-public-key", wrongPath,
	)
	if code != 1 || !strings.Contains(stdout, `"code":"untrusted-signer"`) {
		t.Fatalf("wrong-signer verify code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	stdout, stderr, code = runCommand(
		"verify", "--receipt", receiptPath, "--artifacts", root,
		"--trusted-public-key", publicPath, "--require-current", "--repo", root,
	)
	if code != 1 || !strings.Contains(stdout, `"promotion_status":"FAILED"`) {
		t.Fatalf("FAILED current verify code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
}

func TestCLICertsAndSelfTest(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCommand("selftest")
	if code != 0 || !strings.Contains(stdout, `"diagnostic":"fixture-only"`) {
		t.Fatalf("selftest code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	out := filepath.Join(t.TempDir(), "certs")
	stdout, stderr, code = runCommand("certs", "--out", out, "--ttl", "2h")
	if code != 0 {
		t.Fatalf("certs code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	if strings.Contains(stdout, "tls.key") || !strings.Contains(stdout, `"name":"kafka"`) {
		t.Fatalf("certs public output = %s", stdout)
	}
	keyData, err := os.ReadFile(filepath.Join(out, "kafka", "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(keyData, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("Kafka key is not PKCS#8: %s", keyData)
	}
}

func runCommand(args ...string) (stdout, stderr string, code int) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}
