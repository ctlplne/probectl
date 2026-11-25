// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestWindowsSVIDRecordReplacesWholePairsAndRefusesAnotherTenant(t *testing.T) {
	ca, err := crypto.GenerateCA("Windows SVID fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	owner := "11111111-1111-4111-8111-111111111111"
	sibling := "22222222-2222-4222-8222-222222222222"
	deviceID := "33333333-3333-4333-8333-333333333333"
	issue := func(tenant string) EnrollmentMaterial {
		t.Helper()
		cert, key, err := ca.IssueClientCert(deviceID, crypto.AgentSPIFFEID(tenant, deviceID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return EnrollmentMaterial{Certificate: cert, PrivateKey: key, IssuerCA: ca.CertPEM(), ServerCA: ca.CertPEM()}
	}
	directory := filepath.Join(t.TempDir(), "device")
	store := NewWindowsEnrollmentStore(directory)
	unlock, err := store.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if second, err := store.Lock(); err == nil {
		second()
		t.Fatal("a second writer acquired the Windows identity lock")
	}
	initial := issue(owner)
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directory, IdentityKeyFile)); !os.IsNotExist(err) {
		t.Fatal("Windows enrollment created a separate key file")
	}
	foreign := issue(sibling)
	if err := store.Save(foreign); err == nil {
		t.Fatal("a sibling tenant replaced the stored identity")
	}
	renewal := issue(owner)
	if err := store.Save(renewal); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || !bytes.Equal(got.Certificate, renewal.Certificate) || !bytes.Equal(got.PrivateKey, renewal.PrivateKey) {
		t.Fatal("the replacement record did not contain one coherent renewed pair", err)
	}
	siblingStore := NewWindowsEnrollmentStore(filepath.Join(t.TempDir(), "other-device"))
	if err := siblingStore.Save(foreign); err != nil {
		t.Fatal(err)
	}
	got, err = siblingStore.Load()
	if err != nil || !bytes.Equal(got.Certificate, foreign.Certificate) {
		t.Fatal("the sibling's separate record was affected by the rotation", err)
	}
	unsafeStore := NewWindowsEnrollmentStore(t.TempDir())
	if err := os.WriteFile(filepath.Join(unsafeStore.directory, "endpoint-identity.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := unsafeStore.Load(); err == nil {
		t.Fatal("record with inherited permissions was accepted")
	}
}
