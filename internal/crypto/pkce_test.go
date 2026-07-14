// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"regexp"
	"testing"
)

func TestPKCEChallengeS256RFC7636Vector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := PKCEChallengeS256(verifier); got != want {
		t.Fatalf("S256 challenge = %q, want RFC 7636 vector %q", got, want)
	}
}

func TestNewPKCEVerifierConformsToRFC7636(t *testing.T) {
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("verifier length = %d, want 43..128", len(verifier))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9._~-]+$`).MatchString(verifier) {
		t.Fatalf("verifier contains a non-RFC7636 character: %q", verifier)
	}
}
