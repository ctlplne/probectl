// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
)

// writeBundle signs an auditor bundle and returns the file path plus the
// signer's fingerprint (what an operator would publish out of band and an
// auditor would pin with --expected-fingerprint).
func writeBundle(t *testing.T, sections []compliance.SectionInput) (string, string) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	m, att, err := compliance.BuildAuditorBundle(compliance.AuditorInput{
		TenantID: "t1", CreatedAt: time.Unix(1700000000, 0),
		Deployment: compliance.DeploymentIdentity{Version: "0.6.0", Commit: "abc1234", FIPSMode: true},
		Sections:   sections,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, err := compliance.SignAuditorBundle(m, att, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var pkg compliance.AuditorPackage
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, pkg.Signing.Fingerprint
}

func allVerified() []compliance.SectionInput {
	out := make([]compliance.SectionInput, 0, len(compliance.AuditorSectionKinds))
	for _, k := range compliance.AuditorSectionKinds {
		out = append(out, compliance.SectionInput{Kind: k, Status: compliance.StatusVerified,
			Content: map[string]any{"kind": k}})
	}
	return out
}

// The verification must run with no server and no credentials: an auditor who
// has to ask the producing server whether its export is genuine has verified
// nothing.
func TestVerifyBundleWorksOfflineAndPrintsTheCaveats(t *testing.T) {
	path, fp := writeBundle(t, allVerified())
	var out, errb bytes.Buffer
	// A deliberately unreachable endpoint: if the command touched the network
	// this would fail rather than pass. Pinning the signer fingerprint is what
	// makes the verdict VERIFIED (authenticity), not just integrity.
	cfg := Config{BaseURL: "https://127.0.0.1:1", Token: ""}
	if code := cmdVerifyBundle(cfg, []string{"--expected-fingerprint", fp, path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{"VERIFIED", "probectl-auditor-bundle/v1", "isolation-posture", "FIPS module active"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "not a legal opinion") {
		t.Error("the interpretation caveat must be printed, not just carried")
	}
}

// AI-05: VerifyAuditorBundle checks the signature against the key EMBEDDED in
// the bundle, so a bundle re-signed with an attacker's own key passes integrity.
// Without a pinned --expected-fingerprint the command must NOT print VERIFIED
// and must exit non-zero, so a forged bundle is never mistaken for an
// operator-authenticated one.
func TestVerifyBundleUnpinnedIsNotAuthenticated(t *testing.T) {
	path, fp := writeBundle(t, allVerified())

	// Unpinned: integrity holds but the signer is not authenticated. The
	// verdict is the FIRST line (section status lines legitimately contain the
	// word "VERIFIED", so we check the verdict line specifically).
	var out, errb bytes.Buffer
	code := cmdVerifyBundle(Config{}, []string{path}, &out, &errb)
	if code == 0 {
		t.Fatalf("unpinned verify exited 0 (treated as trusted): %s", out.String())
	}
	verdict := strings.SplitN(out.String(), "\n", 2)[0]
	if !strings.HasPrefix(verdict, "INTEGRITY-ONLY") {
		t.Fatalf("unpinned verdict line should be INTEGRITY-ONLY, got %q", verdict)
	}

	// A pin that does not match the signer is rejected.
	out.Reset()
	errb.Reset()
	if code := cmdVerifyBundle(Config{}, []string{"--expected-fingerprint", "sha256:deadbeef", path}, &out, &errb); code != 1 {
		t.Fatalf("mismatched pin should exit 1, got %d", code)
	}
	if !strings.Contains(errb.String(), "NOT VERIFIED") {
		t.Fatalf("mismatched pin must say NOT VERIFIED: %s", errb.String())
	}

	// The correct pin authenticates it (verdict line is VERIFIED).
	out.Reset()
	errb.Reset()
	code = cmdVerifyBundle(Config{}, []string{"--expected-fingerprint", fp, path}, &out, &errb)
	verdict = strings.SplitN(out.String(), "\n", 2)[0]
	if code != 0 || !strings.HasPrefix(verdict, "VERIFIED") {
		t.Fatalf("correct pin should verify: code=%d verdict=%q", code, verdict)
	}
}

// A tampered bundle must exit non-zero, or a script cannot tell the difference.
func TestVerifyBundleFailsLoudlyOnTampering(t *testing.T) {
	path, _ := writeBundle(t, allVerified())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"version":"0.6.0"`, `"version":"9.9.9"`, 1)
	if tampered == string(raw) {
		t.Fatal("test did not modify the bundle")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cmdVerifyBundle(Config{}, []string{path}, &out, &errb); code == 0 {
		t.Fatal("a tampered bundle must not verify")
	}
	if !strings.Contains(errb.String(), "NOT VERIFIED") {
		t.Errorf("the failure must say so plainly: %s", errb.String())
	}
}

// An ungathered control must be visible in the output, not merely absent.
func TestVerifyBundleShowsUngatheredSections(t *testing.T) {
	sections := allVerified()
	sections[4] = compliance.SectionInput{Kind: compliance.SectionDeletion,
		Status: compliance.StatusUnavailable, Reason: "no subject erasure has been requested"}
	path, fp := writeBundle(t, sections)
	var out, errb bytes.Buffer
	if code := cmdVerifyBundle(Config{}, []string{"--expected-fingerprint", fp, path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	if !strings.Contains(s, "UNAVAILABLE") || !strings.Contains(s, "no subject erasure has been requested") {
		t.Errorf("an ungathered section must be shown with its reason:\n%s", s)
	}
	if !strings.Contains(s, "NOT VERIFIED") {
		t.Errorf("the caveat naming ungathered sections must be printed:\n%s", s)
	}
}
