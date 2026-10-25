// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPair(t *testing.T, ca *CA, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	csr, key, err := CreateCSR(cn)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := ca.SignCSR(csr, AgentSPIFFEID("33333333-3333-4333-8333-333333333333", "77777777-7777-4777-8777-777777777777"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// R3: every step at which an install can stop — a kill, a power loss, a full
// disk — leaves an identity that loads as one pair: the old unit or the new
// one, never a certificate with another unit's (or an empty) key. Covered for
// both the plain-file layout (adoption) and the versioned one.
func TestInstallIdentityNeverTearsThePair(t *testing.T) {
	ca, err := GenerateCA("r3", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, oldKey := testPair(t, ca, "old")
	newCert, newKey := testPair(t, ca, "new")
	steps := []string{"wrote:ca.pem", "wrote:cert.pem", "wrote:key.pem", "before-swap", "after-swap",
		"adopt-before-link", "linked:ca.pem", "linked:cert.pem", "linked:key.pem"}
	for _, layout := range []string{"plain files", "versioned"} {
		for _, step := range steps {
			t.Run(layout+"/"+step, func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "identity")
				cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				if layout == "plain files" {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					_ = os.WriteFile(cert, oldCert, 0o600)
					_ = os.WriteFile(key, oldKey, 0o600)
				} else if err := InstallIdentity(cert, key, oldCert, oldKey, nil); err != nil {
					t.Fatal(err)
				}
				crash := errors.New("crash")
				hit := false
				identityFault = func(s string) error {
					if s == step {
						hit = true
						return crash
					}
					return nil
				}
				err := InstallIdentity(cert, key, newCert, newKey, map[string][]byte{"ca.pem": ca.CertPEM()})
				identityFault = nil
				if hit && !errors.Is(err, crash) {
					t.Fatalf("the fault at %s did not stop the install: %v", step, err)
				}
				if err := VerifyIdentityPair(cert, key); err != nil {
					t.Fatalf("stopped at %s: the identity is torn: %v", step, err)
				}
				got, _ := os.ReadFile(cert)
				if !bytes.Equal(got, oldCert) && !bytes.Equal(got, newCert) {
					t.Fatalf("stopped at %s: the certificate is neither unit's", step)
				}
				// The next install completes from whatever the crash left.
				if err := InstallIdentity(cert, key, newCert, newKey, nil); err != nil {
					t.Fatal(err)
				}
				if got, _ := os.ReadFile(cert); !bytes.Equal(got, newCert) || VerifyIdentityPair(cert, key) != nil {
					t.Fatalf("recovery install after %s did not land the new unit", step)
				}
			})
		}
	}
}

func TestInstallIdentityRefusesAMismatchedPairAndPrunes(t *testing.T) {
	ca, err := GenerateCA("r3", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certA, keyA := testPair(t, ca, "a")
	_, keyB := testPair(t, ca, "b")
	dir := filepath.Join(t.TempDir(), "identity")
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := InstallIdentity(cert, key, certA, keyB, nil); err == nil {
		t.Fatal("a certificate with another key was installed")
	}
	if _, err := os.Stat(cert); !os.IsNotExist(err) {
		t.Fatal("a refused install wrote files")
	}
	for i := 0; i < 4; i++ {
		c, k := testPair(t, ca, "n")
		if err := InstallIdentity(cert, key, c, k, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := InstallIdentity(cert, key, certA, keyA, nil); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	versions := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "v-") {
			versions++
		}
	}
	if versions != 2 {
		t.Fatalf("kept %d versions, want the current and the previous", versions)
	}
	if fi, err := os.Lstat(key); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("key.pem is not the fixed link into current: %v", err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
}
