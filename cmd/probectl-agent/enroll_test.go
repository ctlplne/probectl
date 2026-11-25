// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/agent"
)

// DPR-021: a rotation verifies the control plane with the same trust the
// enrollment captured (server-ca.pem) unless the operator names a bundle;
// only a directory without one falls back to the agent-CA bundle.
func TestRotationTrustFilePrefersCapturedServerTrust(t *testing.T) {
	dir := t.TempDir()
	if got, want := rotationTrustFile(dir, "/etc/probectl/control-ca.crt"), "/etc/probectl/control-ca.crt"; got != want {
		t.Fatalf("explicit --ca-file: got %q, want %q", got, want)
	}
	if got, want := rotationTrustFile(dir, ""), filepath.Join(dir, agent.IdentityCAFile); got != want {
		t.Fatalf("no server-ca.pem: got %q, want the agent-CA bundle %q", got, want)
	}
	if err := os.WriteFile(filepath.Join(dir, agent.IdentityServerCAFile), []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := rotationTrustFile(dir, ""), filepath.Join(dir, agent.IdentityServerCAFile); got != want {
		t.Fatalf("server-ca.pem present: got %q, want %q", got, want)
	}
}

func TestEnrollReadsBoundedStdinToken(t *testing.T) {
	token := "pjt_" + strings.Repeat("a", 64)
	if got, err := agent.ReadEnrollmentToken(strings.NewReader(token + "\r\n")); err != nil || got != token {
		t.Fatal("the command did not accept a single minted token", err)
	}
	for _, input := range []string{"", "pjt_fixture", token + "\n" + token, strings.Repeat("x", 129)} {
		got, err := agent.ReadEnrollmentToken(strings.NewReader(input))
		if got != "" || err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("invalid stdin was accepted or included its token")
		}
	}
	if err := runEnroll([]string{"--token-stdin", "--token", token}); err == nil || strings.Contains(err.Error(), token) {
		t.Fatal("conflicting token inputs were accepted or included their token")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, agent.IdentityCertFile), []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEnroll([]string{"--if-needed", "--expected-tenant", "00000000-0000-4000-8000-000000000001",
		"--dir", dir, "--token-stdin"}); err == nil || !strings.Contains(err.Error(), "existing identity") {
		t.Fatal("a partial identity was not refused before token input", err)
	}
}
