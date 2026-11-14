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

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestChangeEffectsNativeKeepsExactOriginalMetricsAndRedactsFreeText(t *testing.T) {
	const id = "40000000-0000-4004-8000-123456789012"
	ratio := "9007199254740993/7"
	period := change.EffectTestPeriod{
		LossRatio: &ratio, Packets: &change.EffectPackets{Transmitted: "9007199254740993", Replies: "0", Lost: "9007199254740993"},
		Latency:      &change.EffectLatency{Samples: "1", SumNanos: "9007199254740993", MinimumNanos: "9007199254740993", MaximumNanos: "9007199254740993", MeanNanos: ratio, TimingSource: "application_monotonic"},
		Observations: []change.EffectTestObservation{{EvidenceID: id, ObservationID: id, CaptureDigest: strings.Repeat("a1", 32), RoundTrips: &change.EffectOriginalRoundTrips{Nanos: []string{"9007199254740993", "0"}, ExecutionNanos: "9007199254740994"}}},
	}
	value := changeEffectsResponse{ContractVersion: "probectl.change-effects.v1", Original: change.Event{ID: id, TenantID: id, Source: "generic", Title: "owner@example.test"},
		Before: incident.ImpactPeriod{Captures: []incident.ImpactCaptureCitation{}}, After: incident.ImpactPeriod{Captures: []incident.ImpactCaptureCitation{}}, Members: []incident.ImpactMember{},
		Tests: []change.EffectTest{{ContextID: id, EntityID: id, TestID: id, AgentID: "owner@example.test", Before: period, After: period}}}
	body, err := marshalNativeChangeEffects(value)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(body), ai.DefaultRedaction, id)
	var actual changeEffectsResponse
	if err := json.Unmarshal([]byte(redacted), &actual); err != nil {
		t.Fatal(err)
	}
	if actual.ContractVersion != value.ContractVersion || actual.Original.ID != id || actual.Tests[0].TestID != id || *actual.Tests[0].Before.LossRatio != ratio || actual.Tests[0].Before.Latency.MeanNanos != ratio || actual.Tests[0].Before.Observations[0].RoundTrips.Nanos[0] != "9007199254740993" {
		t.Fatal("native redaction changed an authorized original mathematical value")
	}
	if strings.Contains(redacted, "owner@example.test") {
		t.Fatal("free-form source text obtained structural redaction protection")
	}
	value.Tests[0].Before.Observations[0].RoundTrips.Nanos[0] = "arbitrary@example.test"
	if _, err := marshalNativeChangeEffects(value); err == nil {
		t.Fatal("arbitrary sample text obtained mathematical redaction protection")
	}
	if _, err := nativeChangeEffectRatio("1/0").MarshalJSON(); err == nil {
		t.Fatal("invalid rational obtained structural redaction protection")
	}
}
