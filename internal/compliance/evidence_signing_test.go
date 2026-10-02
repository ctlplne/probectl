// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// AI-04: the evidence export's hash chain is self-recomputable, so an editor can
// alter a field, recompute the WHOLE chain, and the chain-only check accepts the
// result. The signature closes that hole: SignEvidence seals the exact bytes, and
// VerifySignedEvidence rejects the edited-and-re-chained document because the
// detached signature no longer covers it.
func TestSignedEvidenceRejectsEditedAndRechainedDocument(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	e := testEngine(t)
	e.clock = func() time.Time { return cT }
	e.Observe("t1", FlowObs{Src: "10.20.1.5", Dst: "10.10.2.9", DstPort: 443, Source: "flow", At: cT})

	ev, err := e.Export("t1")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(ev.Records) == 0 {
		t.Fatal("no records to seal")
	}

	signed, err := SignEvidence(ev, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// The honest, signed document verifies, and the private key never travels.
	if _, err := VerifySignedEvidence(signed); err != nil {
		t.Fatalf("honest signed evidence must verify: %v", err)
	}
	if strings.Contains(string(signed), "PRIVATE KEY") {
		t.Fatal("the signed export must not carry a private key")
	}

	// THE ATTACK: edit a field, then recompute the entire hash chain so it is
	// internally consistent again.
	tampered := ev
	tampered.Records = append([]EvidenceRecord(nil), ev.Records...)
	tampered.Records[0].Result.Violations = 0 // "clean up" the violation
	prev := evidenceGenesis
	for i := range tampered.Records {
		h, herr := recordHash(tampered.Records[i].Seq, tampered.Records[i].Result, prev)
		if herr != nil {
			t.Fatalf("recompute chain: %v", herr)
		}
		tampered.Records[i].PrevHash = prev
		tampered.Records[i].Hash = h
		prev = h
	}
	tampered.ChainHead = prev

	// The chain-only check is fooled — which is exactly the AI-04 weakness.
	if err := VerifyEvidence(tampered); err != nil {
		t.Fatalf("precondition: a recomputed chain must pass the chain-only check: %v", err)
	}

	// Re-pack the edited evidence under the ORIGINAL signature and verify: the
	// signature does NOT, because it was computed over the original bytes.
	var pkg SignedEvidence
	if err := json.Unmarshal(signed, &pkg); err != nil {
		t.Fatalf("decode signed envelope: %v", err)
	}
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("encode tampered evidence: %v", err)
	}
	pkg.Evidence = raw
	forged, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("re-pack forged envelope: %v", err)
	}
	if _, err := VerifySignedEvidence(forged); err == nil {
		t.Fatal("AI-04: an edited, re-chained evidence document still verified")
	}
}
