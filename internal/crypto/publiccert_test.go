// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestInspectPublicCertificatePEM(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA("delivery-audit-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := ca.IssueServerCert("control", []string{"control", "127.0.0.1"}, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	caInfo, err := InspectPublicCertificatePEM(ca.CertPEM())
	if err != nil {
		t.Fatal(err)
	}
	if !caInfo.IsCA || len(caInfo.FingerprintSHA256) != 64 {
		t.Fatalf("CA metadata = %+v, want CA and SHA-256 fingerprint", caInfo)
	}

	leafInfo, err := InspectPublicCertificatePEM(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if leafInfo.IsCA || !slices.Equal(leafInfo.Hosts, []string{"control", "127.0.0.1"}) {
		t.Fatalf("leaf metadata = %+v", leafInfo)
	}
	if leafInfo.NotAfter.Before(leafInfo.NotBefore) {
		t.Fatalf("leaf validity is inverted: %s..%s", leafInfo.NotBefore, leafInfo.NotAfter)
	}
}

func TestVerifyPublicCertificateIssuedByPEM(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA("delivery-audit-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := ca.IssueServerCert("control", []string{"control"}, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicCertificateIssuedByPEM(leaf, ca.CertPEM()); err != nil {
		t.Fatalf("valid issuer rejected: %v", err)
	}

	otherCA, err := GenerateCA("other", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicCertificateIssuedByPEM(leaf, otherCA.CertPEM()); err == nil || !strings.Contains(err.Error(), "verify certificate issuer") {
		t.Fatalf("wrong issuer error = %v", err)
	}
	if err := VerifyPublicCertificateIssuedByPEM(leaf, leaf); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("leaf-as-issuer error = %v", err)
	}
}

func TestInspectPublicCertificatePEMRejectsAmbiguousInput(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA("delivery-audit-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		nil,
		[]byte("not PEM"),
		append(append([]byte(nil), ca.CertPEM()...), ca.CertPEM()...),
		append(append([]byte(nil), ca.CertPEM()...), []byte("trailing")...),
	} {
		if _, err := InspectPublicCertificatePEM(input); err == nil {
			t.Fatalf("InspectPublicCertificatePEM(%q) succeeded", input)
		}
	}
}
