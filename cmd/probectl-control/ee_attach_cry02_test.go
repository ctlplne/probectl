// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !probectl_core

package main

import (
	"os"
	"strings"
	"testing"
)

// CRY-02: the deployment master that wraps managed/BYOK tenant KEKs must be
// built with the opener keyring (PROBECTL_ENVELOPE_OPENER_KEYS), not the
// openerless static provider. Without it, a documented PROBECTL_ENVELOPE_KEY
// rotation permanently bricks every managed tenant's sealed data. This guards
// the attach wiring that the behavioral ee/tenantkeys test exercises.
func TestEEAttachWiresByokOpenerKeyring(t *testing.T) {
	src, err := os.ReadFile("ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{
		"func byokMaster(cfg *config.Config)",
		"NewStaticKeyProviderFromBase64Keyring",
		"parseEnvelopeOpenerKeys(cfg.EnvelopeOpenerKeys)",
		"byokMaster(cfg)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("ee_attach.go must build the byok master with the opener keyring (CRY-02): missing %q", want)
		}
	}
	// The openerless provider must NOT be how the byok master is built.
	if strings.Contains(text, "crypto.NewStaticKeyProviderFromBase64(cfg.EnvelopeKeyID, cfg.EnvelopeKey)") {
		t.Fatal("ee_attach.go still builds the byok master with the openerless provider (CRY-02 regression)")
	}
}
