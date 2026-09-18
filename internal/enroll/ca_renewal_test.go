// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DPR-177: renewal only helps if the deployment keeps trusting the chain its
// agents are already on. An agent holding a leaf signed by the SUPERSEDED
// intermediate must still verify — rotation is how it moves to the new one —
// and the superseded certificate must stop counting once it expires.
func TestRenewalOverlapKeepsExistingLeavesVerifiableUntilTheOldCAExpires(t *testing.T) {
	root, err := crypto.GenerateRootCA("test root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldInter, err := root.IssueIntermediate("old issuing", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newInter, err := root.IssueIntermediate("new issuing", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const tenant, agent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	leafPEM, _, err := oldInter.IssueClientCert(agent, crypto.AgentSPIFFEID(tenant, agent), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	verify := func(includePrevious bool, at time.Time) error {
		roots, inters := x509.NewCertPool(), x509.NewCertPool()
		if !roots.AppendCertsFromPEM(root.CertPEM()) {
			t.Fatal("root bundle unreadable")
		}
		inters.AddCert(newInter.Cert())
		if includePrevious {
			inters.AddCert(oldInter.Cert())
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inters, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		return err
	}

	now := time.Now()
	if err := verify(false, now); err == nil {
		t.Fatal("without the superseded intermediate the existing leaf verifies anyway — the test proves nothing")
	}
	if err := verify(true, now); err != nil {
		t.Fatalf("an agent holding a leaf from the superseded intermediate cannot verify during the overlap: %v", err)
	}
	// And the overlap is not forever: once the old intermediate is past its own
	// NotAfter, a leaf it signed no longer verifies even if the certificate is
	// still sitting in the pool.
	if err := verify(true, oldInter.Cert().NotAfter.Add(time.Minute)); err == nil {
		t.Fatal("a leaf signed by an EXPIRED intermediate still verified — the overlap must end with the certificate")
	}
}

// loadPreviousIntermediate is the gate that keeps an expired certificate out of
// the verification pool in the first place.
func TestLoadPreviousIntermediateDropsAnExpiredCertificate(t *testing.T) {
	root, err := crypto.GenerateRootCA("test root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.IssueIntermediate("issuing", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(inter.CertPEM())
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().Before(cert.NotAfter) {
		t.Fatal("fixture intermediate is already expired")
	}
	if time.Now().Add(2 * time.Hour).Before(cert.NotAfter) {
		t.Fatal("fixture intermediate outlives the window this test needs")
	}
}
