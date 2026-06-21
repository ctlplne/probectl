// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestFIPSEvidenceDocumentsValidatedModuleBoundary(t *testing.T) {
	b, err := os.ReadFile("compliance/fips-evidence.md")
	if err != nil {
		t.Fatalf("read compliance/fips-evidence.md: %v", err)
	}
	doc := string(b)
	flatDoc := strings.Join(strings.Fields(doc), " ")
	flatDoc = strings.NewReplacer("**", "", "`", "", "> ", "", ">", "").Replace(flatDoc)

	for _, want := range []string{
		"Evidence date: 2026-06-21",
		"https://go.dev/doc/security/fips140",
		"https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247",
		"https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=19371",
		"Go Cryptographic Module",
		"v1.0.0",
		"CMVP Certificate #5247",
		"CAVP Certificate A6650",
		"status Active",
		"initial validation date 2026-04-27",
		"sunset date 2031-04-26",
		"probectl's FIPS artifact builds against and operates the FIPS 140-3-validated Go Cryptographic Module v1.0.0 (CMVP #5247)",
		"probectl does not have a separate CMVP certificate for the whole product",
		"it does not replace customer/acquirer compliance review, deployment hardening, or any future certification-grade STIG/CIS package",
		"scripts/check_crypto_imports.sh",
		"internal/crypto/fips.go",
		"internal/crypto/selftest.go",
		"make build-fips",
		"make fips-gate",
		"GOFIPS140=v1.0.0",
		"-tags probectl_fips",
	} {
		if !strings.Contains(flatDoc, want) {
			t.Fatalf("compliance/fips-evidence.md missing required evidence term %q", want)
		}
	}
}

func TestFIPSEvidenceIsLinkedFromOperatorDocs(t *testing.T) {
	for _, path := range []string{
		"hardening.md",
		"compliance/control-evidence.md",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(b), "docs/compliance/fips-evidence.md") &&
			!strings.Contains(string(b), "compliance/fips-evidence.md") {
			t.Fatalf("%s must link to the FIPS evidence snapshot", path)
		}
	}
}
