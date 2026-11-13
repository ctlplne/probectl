// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestSignedVerdictRetainsEveryHypothesisAndTenantBinding(t *testing.T) {
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	value := incident.FaultVerdict{ContractVersion: "probectl.incident-verdict.v1", Preview: true, IncidentID: "owned-incident", EvaluatedAt: at, From: at.Add(-time.Minute), To: at, Domain: incident.FaultYourNetwork, Confidence: "direct", Reason: "original_unplanned_local_interface_down"}
	for _, domain := range []incident.FaultDomain{incident.FaultYourNetwork, incident.FaultCarrier, incident.FaultWiderInternet, incident.FaultRemoteService} {
		h := incident.VerdictHypothesis{Domain: domain, Confidence: "insufficient", For: []incident.VerdictCitation{}, Against: []incident.VerdictCitation{}, Missing: []string{"unavailable_original_coverage"}}
		if domain == incident.FaultYourNetwork {
			h.Confidence = "direct"
			h.For = append(h.For, incident.VerdictCitation{ContextID: "owned-context", EntityID: "owned-interface", EvidenceID: "original-evidence", AgentID: "source", Digest: strings.Repeat("a", 64), ObservedAt: at.Add(-time.Second), Reason: "original_admin_up_oper_down_local_interface"})
		}
		value.Hypotheses = append(value.Hypotheses, h)
	}
	priorScope := ""
	for _, tenant := range []string{"tenant-red", "tenant-blue"} {
		manifest, attachments, err := Build(BuildInput{TenantID: tenant, Incident: incident.Incident{ID: value.IncidentID}, CreatedAt: at, Conclusion: "A model guess with no signal evidence", Grounded: true, Verdict: &value})
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Evidence) != 1 || manifest.Evidence[0].Kind != "incident.fault_domain" || len(attachments) != 1 {
			t.Fatal("verdict attachment was omitted")
		}
		for _, statement := range manifest.Statements {
			if statement.ID == "conclusion" && (statement.Class != "unknown" || len(statement.EvidenceIDs) != 0) {
				t.Fatal("later verdict laundered an uncited model conclusion")
			}
			if statement.ID == "incident-fault-domain" && statement.Class != "inference" {
				t.Fatal("classification was presented as a raw fact")
			}
		}
		raw, err := Sign(manifest, attachments, key)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := Verify(raw)
		if err != nil {
			t.Fatal(err)
		}
		if verified.TenantScopeDigest == priorScope || strings.Contains(string(raw), tenant) {
			t.Fatal("signed verdict lost tenant binding or exposed raw tenant identity")
		}
		priorScope = verified.TenantScopeDigest
		var pkg Package
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatal(err)
		}
		var retained incident.FaultVerdict
		if err := json.Unmarshal(pkg.Attachments[0].Content, &retained); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(retained, value) {
			t.Fatal("signed verdict changed original hypotheses/citations or missing coverage")
		}
		retained.Hypotheses[3].Missing[0] = "pretended_verified_coverage"
		pkg.Attachments[0].Content, err = json.Marshal(retained)
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := json.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(mutated); err == nil {
			t.Fatal("last-hypothesis mutation escaped offline verification")
		}
	}
	value.Domain, value.Confidence = incident.FaultUnknown, "insufficient"
	manifest, _, err := Build(BuildInput{TenantID: "tenant-red", Incident: incident.Incident{ID: value.IncidentID}, CreatedAt: at, Verdict: &value})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range manifest.Statements {
		if statement.ID == "incident-fault-domain" && statement.Class != "unknown" {
			t.Fatal("signature turned unknown into a definite inference")
		}
	}
	value.IncidentID = "foreign-incident"
	if _, _, err := Build(BuildInput{TenantID: "tenant-red", Incident: incident.Incident{ID: "owned-incident"}, CreatedAt: at, Verdict: &value}); err == nil {
		t.Fatal("foreign incident verdict entered package")
	}
}

func TestSignedVerdictRoutingContextKeepsIdentityAndOriginalFaultWindow(t *testing.T) {
	at := time.Now().UTC()
	from := at.Add(-time.Minute)
	value := incident.FaultVerdict{ContractVersion: "probectl.incident-verdict.v1", Preview: true, IncidentID: "owned-incident", EvaluatedAt: at, From: from, To: at, Domain: incident.FaultWiderInternet, Confidence: "corroborated", Reason: "original_external_routing_errors"}
	for _, domain := range []incident.FaultDomain{incident.FaultYourNetwork, incident.FaultCarrier, incident.FaultWiderInternet, incident.FaultRemoteService} {
		h := incident.VerdictHypothesis{Domain: domain, Confidence: "insufficient", For: []incident.VerdictCitation{}, Against: []incident.VerdictCitation{}, Missing: []string{}}
		if domain == incident.FaultWiderInternet {
			h.Confidence = "corroborated"
			h.For = []incident.VerdictCitation{
				{ContextID: "owned-context", EntityID: "owned-router", EvidenceID: "original-error", AgentID: "agent", Digest: strings.Repeat("a", 64), ObservedAt: from.Add(time.Second), Reason: "original_routing_error"},
				{ContextID: "owned-context", EntityID: "owned-router", SourceKind: "router_bgp", AgentID: "listener", Digest: strings.Repeat("b", 64), ObservedAt: from.Add(-time.Second), Reason: "original_selected_route_context", Routing: &incident.VerdictRoutingReference{ViewID: "aee337be-624f-440c-9be9-be3e2c19f7c5", GenerationID: "bc646676-f577-4818-8b9a-59f9fa9f71ad", Sequence: "9223372036854775807", OriginASN: 4294967295, AddressesRedacted: true}},
			}
		}
		value.Hypotheses = append(value.Hypotheses, h)
	}
	if _, _, err := Build(BuildInput{TenantID: "tenant-red", Incident: incident.Incident{ID: value.IncidentID}, CreatedAt: at, Verdict: &value}); err != nil {
		t.Fatal("older original context or redacted routing identity was lost", err)
	}
	for _, which := range []int{0, 1} {
		broken := value
		broken.Hypotheses = append([]incident.VerdictHypothesis(nil), value.Hypotheses...)
		broken.Hypotheses[2].For = append([]incident.VerdictCitation(nil), value.Hypotheses[2].For...)
		if which == 0 {
			broken.Hypotheses[2].For[0].ObservedAt = from.Add(-time.Nanosecond)
		} else {
			broken.Hypotheses[2].For[1].ObservedAt = at
		}
		if _, _, err := Build(BuildInput{TenantID: "tenant-red", Incident: incident.Incident{ID: value.IncidentID}, CreatedAt: at, Verdict: &broken}); err == nil {
			t.Fatal("context exception admitted a fault outside the original window or a future routing context")
		}
	}
}
