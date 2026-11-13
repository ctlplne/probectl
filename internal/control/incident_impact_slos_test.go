// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestIncidentSLOInputsUseProducerSelectorsOriginalFailuresAndTenant(t *testing.T) {
	testID, contextID, entityID, evidenceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, tenant := range []string{"red", "blue"} {
		source := store.IncidentConfiguredTest{TenantID: tenant, ContextID: contextID, EntityID: entityID, TestID: testID, AgentID: "own-agent", Type: "http", Target: "https://reader:credential@example.test/check"}
		source.Definition = testspec.ExecutableDefinition{ID: testID, Type: source.Type, Target: source.Target, IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{}}
		digest, err := testspec.DefinitionHash(source.Definition)
		if err != nil {
			t.Fatal(err)
		}
		failed := incident.ImpactTestObservation{EvidenceID: evidenceID, Status: "failed"}
		test := incident.ImpactTest{ContextID: contextID, EntityID: entityID, TestID: testID, AgentID: source.AgentID, Type: source.Type, DefinitionDigest: digest,
			Current:  incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{failed, failed, {EvidenceID: uuid.NewString(), Status: "unknown"}, {EvidenceID: uuid.NewString(), Status: "successful", Packets: &incident.ImpactTestPackets{Lost: "2"}}}},
			Previous: incident.ImpactTestPeriod{Observations: []incident.ImpactTestObservation{}}}
		definition := slo.SLO{TenantID: tenant, Name: "checkout-availability", Service: "checkout", CanaryType: "http", Target: "https://REDACTED:REDACTED@example.test/check", Objective: 0.999, Window: 30 * 24 * time.Hour}
		byID, wrongTarget, wrongType := definition, definition, definition
		byID.Name, byID.Target, byID.TestID = "named-test-objective", "", testID
		wrongTarget.Name, wrongTarget.Target, wrongTarget.TestID = "wrong-result-selector", "https://other.example.test/", testID
		wrongType.Name, wrongType.CanaryType = "wrong-canary-type", "tcp"
		definitions := []slo.SLO{definition, byID, wrongTarget, wrongType}
		values, err := summarizeIncidentSLOs(t.Context(), tenant, definitions, []store.IncidentConfiguredTest{source}, []incident.ImpactTest{test}, 1<<20)
		if err != nil || len(values) != 2 {
			t.Fatal("SLO selector confused a definition URL with the producer identity", values, err)
		}
		for _, value := range values {
			if value.Current.FailedInputs != 1 || value.Previous.FailedInputs != 0 || len(value.Current.Sources) != 1 || len(value.Current.Sources[0].EvidenceIDs) != 1 || value.Current.Sources[0].EvidenceIDs[0] != evidenceID || value.ObjectiveRatio != "0.999" || len(value.DefinitionDigest) != 64 || value.Basis != "observed_failed_sli_inputs_only_not_a_rolling_budget_verdict" {
				t.Fatal("unknown IO, partial echo loss, replay or configuration became a failed SLO input", value)
			}
		}
		body, err := json.Marshal(values)
		if err != nil || strings.Contains(string(body), "credential") || strings.Contains(string(body), "reader:") {
			t.Fatal("secret-bearing executable selectors escaped into citations", string(body), err)
		}
		native, err := marshalNativeIncidentImpact(incident.ImpactResponse{IncidentID: uuid.NewString(), SLOs: values})
		if err != nil {
			t.Fatal("an arbitrary OpenSLO name was forced into UUID identity", err)
		}
		native = []byte(ai.RedactTextForTenant(string(native), ai.DefaultRedaction, tenant))
		var decoded incident.ImpactResponse
		if err := json.Unmarshal(native, &decoded); err != nil || len(decoded.SLOs) != 2 || decoded.SLOs[0].ObjectiveRatio != "0.999" || decoded.SLOs[0].Current.Sources[0].TestID != testID || decoded.SLOs[0].Current.Sources[0].EvidenceIDs[0] != evidenceID {
			t.Fatal("native projection damaged objective math or canonical failed-input citations", string(native), err)
		}
		foreign := definition
		foreign.TenantID = "foreign"
		if result, err := summarizeIncidentSLOs(t.Context(), tenant, []slo.SLO{foreign}, []store.IncidentConfiguredTest{source}, []incident.ImpactTest{test}, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || result != nil {
			t.Fatal("foreign SLO supplied impact", result, err)
		}
		changed := source
		changed.Definition.Target = "https://changed.example.test/"
		if result, err := summarizeIncidentSLOs(t.Context(), tenant, definitions, []store.IncidentConfiguredTest{changed}, []incident.ImpactTest{test}, 1<<20); !errors.Is(err, entity.ErrConflictingEvidence) || result != nil {
			t.Fatal("an old outcome borrowed a changed executable definition", result, err)
		}
	}
	for _, value := range []string{"", "0", "1", "01", "-0.1", "NaN", "0.5@example.test"} {
		if _, err := json.Marshal(nativeIncidentSLORatio(value)); err == nil {
			t.Fatal("invalid text entered the numeric privacy bypass", value)
		}
	}
}
