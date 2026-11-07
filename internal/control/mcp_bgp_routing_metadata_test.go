// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/store"
)

func TestBGPRoutingMCPMetadataKeepsStoredIDsAndFullUntrustedRedaction(t *testing.T) {
	const id = "40000000-0000-4004-8000-abcdefabcdef"
	secret := "fixture-private-" + strings.Repeat("x", 20)
	input := store.BGPRoutingBindingConfiguration{CollectorAgentID: "password=" + secret, SourceRef: "sender/" + id, ContextID: id, RouterID: id,
		Manifest: &store.BGPRoutingBindingManifest{Epoch: id, AssignedAt: time.Now().UTC(), Bindings: []store.BGPRoutingBinding{{ID: id, ContextID: id, RouterID: id, Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{1, 2}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1}}}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalBGPRoutingMCPConfiguration(raw)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, id)
	var got store.BGPRoutingBindingConfiguration
	if err := json.Unmarshal([]byte(redacted), &got); err != nil {
		t.Fatal(err)
	}
	if got.ContextID != id || got.RouterID != id || got.Manifest == nil || got.Manifest.Epoch != id || len(got.Manifest.Bindings) != 1 || got.Manifest.Bindings[0].ID != id || got.Manifest.Bindings[0].ContextID != id || got.Manifest.Bindings[0].RouterID != id {
		t.Fatal("native routing redaction changed canonical stored metadata identity")
	}
	if strings.Contains(got.CollectorAgentID, secret) || strings.Contains(got.SourceRef, id) || !strings.Contains(got.CollectorAgentID, "[secret:") || !strings.Contains(got.SourceRef, "[pan:") {
		t.Fatal("native routing metadata weakened sender/text redaction")
	}
	if got.Manifest.Bindings[0].Distinguisher != "ffffffffffffffff" || len(got.Manifest.Bindings[0].Families) != 2 || got.Manifest.Bindings[0].SourceFormat != store.BGPRoutingSourceFRRLocRIBV1 {
		t.Fatal("native routing metadata lost complete supported protocol fields")
	}
}
