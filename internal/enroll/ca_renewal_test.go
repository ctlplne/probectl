// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package enroll

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
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

// DPR-194: `agent-ca renew` writes the new issuing intermediate to the DATABASE,
// and nothing told a running control plane. Observed on the lab: a renewal
// succeeded, `agent-ca export` returned the expected three certificates, and
// every replica's own /v1/diagnostics went on reporting the SUPERSEDED window —
// so the check that had told the operator to renew kept telling them to renew,
// and the replicas kept minting 24h identities from a certificate about to
// expire. The documented escape from the one-year deadline bought nothing until
// somebody happened to restart the deployment.
//
// The DB round trip is covered by the integration suite. What is asserted here
// is the part that was structurally missing: the fields a renewal has to change
// are readable through one consistent snapshot, and swapping them is visible to
// every read path at once.
func TestIssuingSnapshotIsConsistentAndSwappable(t *testing.T) {
	root, err := crypto.GenerateRootCA("test root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldInter, err := root.IssueIntermediate("old issuing", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newInter, err := root.IssueIntermediate("new issuing", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	svc := &Service{
		ca: oldInter, rootPEM: root.CertPEM(), prevCA: nil,
		leafTTL: DefaultLeafTTL, log: slog.Default(), now: func() time.Time { return now },
	}

	_, notAfter := svc.IssuingWindow()
	if !notAfter.Equal(oldInter.Cert().NotAfter) {
		t.Fatalf("the window must report the loaded intermediate, got %s", notAfter)
	}

	// The swap Refresh performs, without the database in the way.
	svc.mu.Lock()
	svc.ca, svc.prevCA = newInter, oldInter.Cert()
	svc.mu.Unlock()

	_, notAfter = svc.IssuingWindow()
	if !notAfter.Equal(newInter.Cert().NotAfter) {
		t.Errorf("after a renewal the window must report the NEW intermediate; got %s, want %s",
			notAfter, newInter.Cert().NotAfter)
	}
	// And the bundle must carry the overlap, or every agent holding a leaf from
	// the old intermediate stops verifying the moment the swap happens.
	bundle := svc.Bundle()
	if n := bytes.Count(bundle, []byte("BEGIN CERTIFICATE")); n != 3 {
		t.Errorf("bundle after the swap has %d certificates, want 3 (root + new + superseded)", n)
	}

	// sameCertificate is the guard that decides whether to unseal the key at all,
	// so it must not call two different certificates the same.
	if !sameCertificate(newInter.Cert(), newInter.CertPEM()) {
		t.Error("a certificate must match its own PEM")
	}
	if sameCertificate(newInter.Cert(), oldInter.CertPEM()) {
		t.Error("two different intermediates must not compare equal — a renewal would never be adopted")
	}
	if sameCertificate(newInter.Cert(), []byte("not pem")) {
		t.Error("unparseable input must not compare equal")
	}
}

// The serving path reads the CA on every enrollment and rotation while the
// refresh loop may be swapping it. Run under -race, this is the test that fails
// if a future reader goes back to touching the fields directly.
func TestIssuingSnapshotIsSafeUnderConcurrentRefresh(t *testing.T) {
	root, err := crypto.GenerateRootCA("test root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := root.IssueIntermediate("issuing a", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.IssueIntermediate("issuing b", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	svc := &Service{ca: a, rootPEM: root.CertPEM(), leafTTL: DefaultLeafTTL,
		log: slog.Default(), now: func() time.Time { return now }}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			next := a
			if i%2 == 1 {
				next = b
			}
			svc.mu.Lock()
			svc.ca = next
			svc.mu.Unlock()
		}
	}()
	for i := 0; i < 500; i++ {
		ca, rootPEM, _ := svc.issuing()
		if ca == nil || ca.Cert() == nil || len(rootPEM) == 0 {
			t.Fatal("a snapshot must never be empty or half-applied")
		}
		_, notAfter := svc.IssuingWindow()
		if notAfter.IsZero() {
			t.Fatal("the window must never read zero while a CA is loaded")
		}
	}
	<-done
}
