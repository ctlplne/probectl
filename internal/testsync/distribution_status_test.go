// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestVerifyExportedEntryPoint exercises the agent-facing Verify (PLAT-13): the
// exported verification contract the (not-yet-shipped) agent pull loop will use
// must accept a correctly-signed, newer bundle and refuse a tampered one.
func TestVerifyExportedEntryPoint(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(Bundle{TenantID: "t-a", Epoch: 100, Tests: []Test{
		{ID: "x", Type: "icmp", Target: "10.0.0.1", IntervalSeconds: 30, TimeoutSeconds: 5},
	}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, pub, 50); err != nil {
		t.Fatalf("Verify rejected a valid newer bundle: %v", err)
	}
	tampered := append([]byte(nil), signed...)
	for i := range tampered {
		if tampered[i] == 'x' {
			tampered[i] = 'y'
			break
		}
	}
	if _, err := Verify(tampered, pub, 50); err == nil {
		t.Fatal("Verify accepted a tampered bundle")
	}
}

// TestAgentSideBundlePullNotYetWired enforces the ING-20 claim-accuracy fix.
// The package doc and the handleTestBundle comment now state that the agent-side
// PULL loop is NOT yet shipped — the signed bundle is served but no shipped
// agent fetches or applies it, so tests reach agents via their own config. That
// statement is only honest while no agent binary consumes this package. If the
// pull loop is ever wired (an agent importing internal/testsync), this test
// fails, forcing the docs (package doc, handler comment, D-28/PLAT-13) to be
// updated to describe the now-automatic delivery.
func TestAgentSideBundlePullNotYetWired(t *testing.T) {
	const importPath = "github.com/ctlplne/probectl/internal/testsync"
	for _, dir := range []string{"../../cmd/probectl-agent", "../../cmd/probectl-endpoint", "../../internal/agent"} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("expected agent tree at %s: %v", dir, err)
		}
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), importPath) {
				t.Errorf("ING-20: %s imports %s — the agent-side central-test PULL loop is now wired, "+
					"but the docs (internal/testsync package doc, handleTestBundle comment) and D-28/PLAT-13 "+
					"still say it is not shipped. Update them to describe the automatic delivery.", p, importPath)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}
