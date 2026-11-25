// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestIncidentDraftUsesOnlyVerifiedFacts(t *testing.T) {
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	trusted := evidence.DigestAlgorithm + ":" + hex.EncodeToString(crypto.Hash(public))
	from := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	to := from.Add(time.Minute)
	incidentData := incident.Incident{ID: "incident-a", Title: "Service degradation", StartedAt: from, LastSeenAt: to, Status: incident.StatusOpen, SignalCount: 1,
		Signals: []incident.Signal{{Plane: "network", Kind: "test.failure", Title: "Probe timed out", OccurredAt: from}}}
	carrier := incident.CarrierPack{
		ContractVersion: incident.CarrierContractVersion, IncidentID: incidentData.ID, GeneratedAt: to, From: from, To: to,
		Summary: "One lane measured packet counts", Interpretation: "Timing alone does not establish a cause",
		Coverage: incident.CarrierCoverage{Measurements: "observed_originals", Traces: "unavailable", Routing: "unavailable", Handoffs: "unavailable", Missing: []string{"independent_agent_traceroutes"}},
		Vantages: []incident.CarrierVantage{{ContextID: "c", EntityID: "r", TestID: "probe-a", Measurements: change.EffectTestPeriod{
			From: from, To: to, Observations: []change.EffectTestObservation{{ObservedAt: from, Available: true, Packets: &change.EffectPackets{Transmitted: "3", Replies: "2", Lost: "1"}}},
		}}},
	}
	for _, kind := range []evidence.DraftKind{evidence.DraftCarrier, evidence.DraftReview, evidence.DraftExecutive} {
		t.Run(string(kind), func(t *testing.T) {
			input := evidence.BuildInput{TenantID: "tenant-a", Incident: incidentData, CreatedAt: to}
			if kind == evidence.DraftCarrier {
				input.Carrier = &carrier
			}
			manifest, attachments, err := evidence.Build(input)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := evidence.Sign(manifest, attachments, private)
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range [][3]string{
				{"tenant-b", incidentData.ID, trusted},
				{"tenant-a", "incident-b", trusted},
				{"tenant-a", incidentData.ID, evidence.DigestAlgorithm + ":" + hex.EncodeToString(crypto.Hash([]byte("unrelated signer")))},
			} {
				if _, err := evidence.OpenDraftSource(wire, expected[0], expected[1], expected[2]); !errors.Is(err, evidence.ErrDraftSource) {
					t.Fatalf("unbound source accepted: %v", err)
				}
			}
			source, err := evidence.OpenDraftSource(wire, "tenant-a", incidentData.ID, trusted)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := source.Plan(kind)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := plan.Render([]int{len(plan.Choices()) + 1}); !errors.Is(err, evidence.ErrDraftClaim) {
				t.Fatalf("unproven model claim accepted: %v", err)
			}
			draft, err := plan.Render(nil)
			if err != nil || draft.Kind != kind || draft.PackageID != manifest.PackageID {
				t.Fatalf("wrong draft binding: %+v, %v", draft, err)
			}
			assertNativeIncidentDraft(t, draft, wire, incidentData.ID, trusted)
			var sentences []string
			for _, section := range draft.Sections {
				for _, sentence := range section.Sentences {
					if len(sentence.Citations) == 0 {
						t.Fatalf("uncited sentence: %q", sentence.Text)
					}
					for _, cite := range sentence.Citations {
						if raw, ok := source.Resolve(cite); !ok || !json.Valid(raw) {
							t.Fatalf("unresolved citation %+v in %q", cite, sentence.Text)
						}
					}
					sentences = append(sentences, sentence.Text)
				}
			}
			all := strings.Join(sentences, "\n")
			if kind == evidence.DraftCarrier {
				if !strings.Contains(all, "3 packets sent and received 2 in reply") || !strings.Contains(all, "independent_agent_traceroutes") || strings.Contains(all, "Probe timed out") {
					t.Fatalf("carrier draft changed the measurements or source selection: %s", all)
				}
				narrow, err := plan.Render([]int{1})
				if err != nil {
					t.Fatal(err)
				}
				coverage := map[string]bool{}
				for _, section := range narrow.Sections {
					for _, sentence := range section.Sentences {
						for _, cite := range sentence.Citations {
							raw, ok := source.Resolve(cite)
							if !ok {
								t.Fatalf("mandatory citation no longer resolves: %+v", cite)
							}
							coverage[cite.Pointer] = sentence.State == evidence.StateUnknown &&
								strings.Contains(sentence.Text, strings.Trim(string(raw), `"`))
						}
					}
				}
				if !coverage["/interpretation"] || !coverage["/coverage/missing/0"] {
					t.Fatal("a narrow selection suppressed an original carrier limitation")
				}
			} else if !strings.Contains(all, `"Probe timed out"`) {
				t.Fatalf("incident draft omitted the signed probe observation: %s", all)
			}
		})
	}
}

func assertNativeIncidentDraft(t *testing.T, draft evidence.IncidentDraft, wire []byte, id, trusted string) {
	t.Helper()
	calls := 0
	backend := func(_ context.Context, actor *auth.Principal, input IncidentDraftCommand, _ ai.RedactionPolicy) (SignedIncidentDraft, error) {
		calls++
		if actor.TenantID != "tenant-a" || input.IncidentID != id || input.Kind != draft.Kind {
			t.Fatal("draft dispatch changed the tenant or request")
		}
		return NewSignedIncidentDraft(draft, "builtin", false, wire, actor.TenantID, id, trusted)
	}
	server := newTestServer(&fakeBackend{}, testGate(), WithIncidentDraftBackend(backend, json.RawMessage(`{"type":"object"}`)))
	actor := principal("tenant-a", permIncidentRead, permAIQuery)
	actor.UserID = "operator"
	params := map[string]any{"name": "incident_draft", "arguments": IncidentDraftCommand{IncidentID: id, Kind: draft.Kind}}
	response := handle(t, server, actor, 1, "tools/call", params)
	payload := resultOf(t, response)
	report, err := json.Marshal(payload["structuredContent"])
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		evidence.IncidentDraft
		SignedSource string `json:"evidence_package"`
	}
	if err := json.Unmarshal(report, &result); err != nil || calls != 1 || payload["isError"] == true || result.PackageID != draft.PackageID {
		t.Fatalf("native draft did not return its own signed package: %v", err)
	}
	signed, err := base64.StdEncoding.DecodeString(result.SignedSource)
	if err != nil || !bytes.Equal(signed, wire) {
		t.Fatal("native draft changed the signed source")
	}
	expected, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(result.IncidentDraft)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatal("native draft changed the signed evidence references or draft content")
	}
	delete(actor.Permissions, permAIQuery)
	refusal := handle(t, server, actor, 2, "tools/call", params)
	if code, _ := errCode(refusal); code != codeForbidden || calls != 1 {
		t.Fatal("native draft reached the signer after ai.query was withdrawn")
	}
}
