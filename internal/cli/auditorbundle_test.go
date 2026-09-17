// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
)

func writeBundle(t *testing.T, sections []compliance.SectionInput) string {
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
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
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
	path := writeBundle(t, allVerified())
	var out, errb bytes.Buffer
	// A deliberately unreachable endpoint: if the command touched the network
	// this would fail rather than pass.
	cfg := Config{BaseURL: "https://127.0.0.1:1", Token: ""}
	if code := cmdVerifyBundle(cfg, []string{path}, &out, &errb); code != 0 {
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

// A tampered bundle must exit non-zero, or a script cannot tell the difference.
func TestVerifyBundleFailsLoudlyOnTampering(t *testing.T) {
	path := writeBundle(t, allVerified())
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
	path := writeBundle(t, sections)
	var out, errb bytes.Buffer
	if code := cmdVerifyBundle(Config{}, []string{path}, &out, &errb); code != 0 {
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
