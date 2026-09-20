// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

func TestSealVerifyAndTampering(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealWithSource(receipt, root, testSourceRoot(t), privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(envelope, root)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Receipt.Status != OutcomeVerified || len(verified.Receipt.Artifacts) != len(receipt.Artifacts) {
		t.Fatalf("verified receipt = %#v", verified.Receipt)
	}

	var decoded Envelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Receipt = bytes.Replace(decoded.Receipt, []byte(`"CL-002"`), []byte(`"CL-999"`), 1)
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, root); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered receipt error = %v, want signature failure", err)
	}

	if err := os.WriteFile(filepath.Join(root, "cli.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(envelope, root); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered artifact error = %v, want mismatch", err)
	}
}

func TestSignedFailedReceiptRemainsVerifiableButNonPromotable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Status = OutcomeFailed
	receipt.FailureReasons = []string{"rendered UI returned an error"}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealWithSource(receipt, root, testSourceRoot(t), privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(envelope, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := diagnosticCodes(Lint(verified.Receipt)); !slicesEqual(got, []string{"status-failed"}) {
		t.Fatalf("FAILED lint codes = %v", got)
	}
	status, _, err := CurrentStatus(verified, "does-not-need-to-be-a-repo", TrustPolicy{})
	if err != nil || status != StatusFailed {
		t.Fatalf("CurrentStatus(FAILED) = %s, %v", status, err)
	}
}

func TestSignerTrustIsAlwaysOutOfBand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, publicPEM, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealWithSource(receipt, root, testSourceRoot(t), privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(envelope, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignerTrust(verified, TrustPolicy{}); !errors.Is(err, ErrTrustRequired) {
		t.Fatalf("empty trust error = %v, want ErrTrustRequired", err)
	}
	_, wrongPublicPEM, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignerTrust(verified, TrustPolicy{PublicKeyPEM: wrongPublicPEM}); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("wrong signer error = %v, want ErrUntrustedSigner", err)
	}
	if err := VerifySignerTrust(verified, TrustPolicy{PublicKeyPEM: publicPEM}); err != nil {
		t.Fatalf("trusted key rejected: %v", err)
	}
	if err := VerifySignerTrust(verified, TrustPolicy{Fingerprint: verified.Envelope.Signing.Fingerprint}); err != nil {
		t.Fatalf("trusted fingerprint rejected: %v", err)
	}
	status, diagnostics, err := CurrentStatus(verified, root, TrustPolicy{})
	if err != nil || status != StatusSignatureValidUntrusted || len(diagnostics) != 1 || diagnostics[0].Code != "untrusted-signer" {
		t.Fatalf("untrusted CurrentStatus = %s, %v, %v", status, diagnostics, err)
	}
	status, diagnostics, err = CurrentStatus(verified, root, TrustPolicy{PublicKeyPEM: wrongPublicPEM})
	if err != nil || status != StatusNonPromotable || len(diagnostics) != 1 || diagnostics[0].Code != "untrusted-signer" {
		t.Fatalf("wrong-signer CurrentStatus = %s, %v, %v", status, diagnostics, err)
	}
}

func TestCurrentStatusRequiresCleanExactCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := filepath.Join(t.TempDir(), "source")
	clone := exec.Command("git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "clone", "-q", "--no-hardlinks", testSourceRoot(t), repo)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("clone source: %v: %s", err, output)
	}
	runGit(t, repo, "config", "user.email", "audit@example.invalid")
	runGit(t, repo, "config", "user.name", "Audit Test")
	runGit(t, repo, "config", "gc.auto", "0")
	runGit(t, repo, "config", "maintenance.auto", "false")
	t.Cleanup(func() {
		_ = exec.Command("git", "-C", repo, "maintenance", "stop").Run()
		_ = os.RemoveAll(repo)
	})
	// The shared worktree can contain the CLI/completeness changes under test
	// before they are committed. Mirror only the production analyzer inputs so
	// the temporary exact checkout matches the code executing this test.
	for _, relative := range []string{
		"internal/cli/cli.go", "internal/cli/generic.go", "internal/cli/surfaces.go", "internal/cli/types.go",
		"internal/completeness/cli_dispatch.go",
		"scripts/run_completeness_audit.sh", "scripts/completeness_audit_browser.mjs",
		"docs/quality/delivery-audit-review-protocols.json",
		// DPR-255: capabilities.yaml is the registry the validator RUNS against —
		// the most production of the analyzer inputs — and it was the one missing
		// here. refreshSourceBoundSelfTestArtifacts digests it from the working
		// tree while CurrentStatus re-verifies against this clone, so any
		// uncommitted registry edit failed with reachability-source-mismatch and
		// made `make test` red for a change that was correct.
		"capabilities.yaml",
	} {
		data, err := os.ReadFile(filepath.Join(testSourceRoot(t), filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(repo, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, repo, "add", "internal/cli", "internal/completeness/cli_dispatch.go", "scripts", "docs/quality/delivery-audit-review-protocols.json", "capabilities.yaml")
	diff := exec.Command("git", "-C", repo, "diff", "--cached", "--quiet")
	if err := diff.Run(); err != nil {
		runGit(t, repo, "commit", "-qm", "test: mirror validator inputs")
	}
	state, err := readRepositoryState(repo)
	if err != nil {
		t.Fatal(err)
	}

	artifactRoot := t.TempDir()
	receipt, err := newSelfTestReceipt(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Source.GitSHA = state.GitSHA
	receipt.Source.TreeSHA = state.TreeSHA
	receipt.Build.ControlCommit = state.GitSHA
	receipt.Build.CLICommit = state.GitSHA
	refreshSourceBoundSelfTestArtifacts(t, artifactRoot, receipt)
	privatePEM, publicPEM, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealWithSource(receipt, artifactRoot, repo, privatePEM)
	if err != nil {
		t.Fatalf("%v; diagnostics=%v", err, LintWithArtifactsAtSource(receipt, artifactRoot, repo))
	}
	verified, err := Verify(envelope, artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustPolicy{PublicKeyPEM: publicPEM}
	status, diagnostics, err := CurrentStatus(verified, repo, trust)
	if err != nil || status != StatusVerifiedCurrent || len(diagnostics) != 0 {
		t.Fatalf("clean status = %s, %v, %v", status, diagnostics, err)
	}

	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, _, err = CurrentStatus(verified, repo, trust)
	if err != nil || status != StatusCurrentCheckoutDirty {
		t.Fatalf("dirty status = %s, %v", status, err)
	}
	if err := os.Remove(filepath.Join(repo, "untracked.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "audit-stale.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "audit-stale.txt")
	runGit(t, repo, "commit", "-qm", "second")
	status, _, err = CurrentStatus(verified, repo, trust)
	if err != nil || status != StatusStaleSHA {
		t.Fatalf("stale status = %s, %v", status, err)
	}
}

// DPR-255: before capabilities.yaml was mirrored into the exact checkout above,
// the ONLY thing exercising reachability-source-mismatch was a developer with an
// uncommitted registry edit — which is to say, an accident. Mirroring it would
// have left the guard unexercised, so this is the deliberate negative: an
// artifact bound to one registry, re-verified against a tree carrying a
// different one, must be refused. The mutation keeps the YAML valid so the
// mismatch is the ONLY thing that can fail.
func TestReachabilityArtifactBoundToADifferentRegistryIsRefused(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := testSourceRoot(t)
	registry, err := readSourceFile(root, reachabilityRegistryPath, 4<<20)
	if err != nil {
		t.Fatal(err)
	}

	artifactRoot := t.TempDir()
	receipt, err := newSelfTestReceipt(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	// Bind the artifact to a registry that differs from the source tree's by one
	// comment line: same capabilities, same validator verdict, different bytes.
	altered := append(append([]byte(nil), registry...), []byte("\n# DPR-255 digest-divergence probe\n")...)
	if digestBytes(altered) == digestBytes(registry) {
		t.Fatal("the probe did not change the registry digest")
	}
	writeTestJSON(t, filepath.Join(artifactRoot, "reachability.json"), reachabilityArtifact(receipt, digestBytes(altered)))

	diagnostics := lintReachabilitySource(receipt, reachabilityArtifact(receipt, digestBytes(altered)), root)
	var codes []string
	for _, diagnostic := range diagnostics {
		codes = append(codes, diagnostic.Code)
	}
	found := false
	for _, code := range codes {
		if code == "reachability-source-mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("an artifact bound to a different capabilities.yaml was accepted; diagnostics = %v", codes)
	}

	// And the control: the same artifact bound to the tree's own registry must
	// NOT raise the mismatch, or this test would pass for the wrong reason.
	for _, diagnostic := range lintReachabilitySource(receipt, reachabilityArtifact(receipt, digestBytes(registry)), root) {
		if diagnostic.Code == "reachability-source-mismatch" {
			t.Fatalf("the tree's own registry raised a source mismatch: %v", diagnostic)
		}
	}
}

func TestArtifactBoundsRejectTraversalAndSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Artifacts[0].Path = "../outside"
	if _, _, err := bindArtifactSnapshot(receipt, root); err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("traversal error = %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	receipt.Artifacts[0].Path = "linked"
	if _, _, err := bindArtifactSnapshot(receipt, root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestDecodeReceiptRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schema":"probectl.delivery-audit-receipt/v1","unknown":true}`)
	if _, err := DecodeReceipt(raw); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeReceipt error = %v", err)
	}
}

func TestSelfTest(t *testing.T) {
	t.Parallel()
	if err := SelfTest(); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testSourceRoot(t *testing.T) string {
	t.Helper()
	root, err := findSelfTestSourceRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func refreshSourceBoundSelfTestArtifacts(t *testing.T, artifactRoot string, receipt Receipt) {
	t.Helper()
	root := testSourceRoot(t)
	registry, err := readSourceFile(root, reachabilityRegistryPath, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, filepath.Join(artifactRoot, "reachability.json"), reachabilityArtifact(receipt, digestBytes(registry)))
	var stack StackInventoryArtifact
	stackData, err := os.ReadFile(filepath.Join(artifactRoot, "stack.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(stackData, &stack); err != nil {
		t.Fatal(err)
	}
	stack.Source = receipt.Source
	control := stack.Services["control"]
	control.Version = receipt.Source.GitSHA
	stack.Services["control"] = control
	writeTestJSON(t, filepath.Join(artifactRoot, "stack.json"), stack)
	var product ProductPipelineArtifact
	productData, err := os.ReadFile(filepath.Join(artifactRoot, filepath.FromSlash(receipt.Stores.ProductPipelineArtifact)))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(productData, &product); err != nil {
		t.Fatal(err)
	}
	product.SourceGitSHA = receipt.Source.GitSHA
	product.SourceTreeSHA = receipt.Source.TreeSHA
	writeTestJSON(t, filepath.Join(artifactRoot, filepath.FromSlash(receipt.Stores.ProductPipelineArtifact)), product)
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
