// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestVerdictExportRedactsAgentLabelsWithoutChangingOriginalCitations(t *testing.T) {
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	label := "alice@example.test 203.0.113.9 owned-tenant OWNED-TENANT"
	citation := incident.VerdictCitation{ContextID: "context", EntityID: "entity", EvidenceID: "original", Digest: strings.Repeat("a", 64), AgentID: label}
	input := incident.FaultVerdict{Hypotheses: []incident.VerdictHypothesis{{For: []incident.VerdictCitation{citation}, Against: []incident.VerdictCitation{citation}}}}
	output, err := redactIncidentVerdict(input, ai.RedactionPolicy{MaskIPs: true, MaskPII: true, TokenKey: key}, "owned-tenant")
	if err != nil {
		t.Fatal(err)
	}
	for _, citations := range [][]incident.VerdictCitation{output.Hypotheses[0].For, output.Hypotheses[0].Against} {
		got := citations[0]
		if strings.Contains(strings.ToLower(got.AgentID), "owned-tenant") || strings.Contains(got.AgentID, "alice@example.test") || strings.Contains(got.AgentID, "203.0.113.9") {
			t.Fatal("signed verdict retained a private agent label")
		}
		got.AgentID = label
		if got != citation {
			t.Fatal("redaction changed original structural citations or digest")
		}
	}
	if input.Hypotheses[0].For[0].AgentID != label || input.Hypotheses[0].Against[0].AgentID != label {
		t.Fatal("redaction modified the caller's source verdict")
	}
}
