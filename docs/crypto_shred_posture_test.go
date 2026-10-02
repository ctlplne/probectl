// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCryptoShredPostureDistinguishesManagedFromBYOK guards CRY-03.
//
// The crypto-shred promise ("destroy the key and the backup becomes unreadable")
// is TRUE only for BYOK, where probectl never holds the key material and a
// backup carries only a reference. It is FALSE for the default MANAGED mode:
// ee/tenantkeys seals each per-tenant KEK under the deployment master
// (PROBECTL_ENVELOPE_KEY) and DestroyAll only nulls the wrapped KEK in the LIVE
// tenant_keys row. The deployment master is deployment-wide and survives tenant
// offboarding, so a pre-offboard backup — which still contains the wrapped KEK —
// restored beside the live master decrypts the "destroyed" tenant's values.
//
// This gate FAILS if any doc reintroduces the false blanket crypto-shred claim
// for managed-mode backups, or drops the honest managed-vs-BYOK distinction.
func TestCryptoShredPostureDistinguishesManagedFromBYOK(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}

	byok := read("byok.md")
	offboard := read(filepath.Join("runbooks", "tenant-offboarding.md"))
	pkgDoc := read(filepath.Join("..", "ee", "tenantkeys", "tenantkeys.go"))
	normalized := strings.Join(strings.Fields(byok+"\n"+offboard+"\n"+pkgDoc), " ")

	// Blanket claims that are false for managed mode (the deployment master
	// still decrypts a pre-offboard backup). None of these may describe a key
	// destroy that is reachable in managed mode.
	for _, banned := range []string{
		"destroy the key, and any sealed data that ever lingers in a backup becomes permanently unreadable",
		"escaped into a backup window is now permanently unreadable",
		"destroying the only key is equivalent to shredding every copy of the data at once",
		"so any ciphertext (including in still-live backups) is permanently unreadable",
		"but you hold the only key",
		"including backups within their TTL",
	} {
		if strings.Contains(normalized, banned) {
			t.Fatalf("CRY-03: crypto-shred docs reintroduce the false blanket claim %q — managed-mode backups are NOT crypto-shredded (the deployment master survives offboarding and still decrypts a pre-offboard backup)", banned)
		}
	}

	// The honest guarantee must be stated: in managed mode the deployment master
	// survives offboarding, a pre-offboard backup restored beside it still
	// decrypts, and managed offboarding leans on verifiable deletion.
	for _, want := range []string{
		"survives offboarding",
		"restored beside the live deployment master",
		"verifiable deletion",
	} {
		if !strings.Contains(normalized, want) {
			t.Fatalf("CRY-03: crypto-shred docs are missing the honest managed-mode caveat %q", want)
		}
	}
}
