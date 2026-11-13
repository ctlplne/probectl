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

	googleuuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestIncidentTestComparisonKeepsOriginalOutcomesUnknownIOAndExactCitations(t *testing.T) {
	from := time.Now().UTC().Truncate(time.Microsecond)
	source := store.IncidentConfiguredTest{TenantID: "own", ContextID: googleuuid.NewString(), EntityID: googleuuid.NewString(), TestID: googleuuid.NewString(), AgentID: "person@example.test", Name: "person@example.test", Type: "icmp"}
	source.Definition = testspec.ExecutableDefinition{ID: source.TestID, Type: "icmp", Target: "192.0.2.1", IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{}}
	application := source
	application.TestID, application.Type = googleuuid.NewString(), "http"
	application.Definition = testspec.ExecutableDefinition{ID: application.TestID, Type: "http", Target: "https://example.test/", IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{}}
	read := func(at time.Time) store.IncidentTestMeasurement {
		return store.IncidentTestMeasurement{TenantID: source.TenantID, ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID, AgentID: source.AgentID, EvidenceID: googleuuid.NewString(), ObservedAt: at, Available: true, Reason: "original_attested_test_observation"}
	}
	good, loss, local, canceled, previous := read(from), read(from.Add(time.Second)), read(from.Add(2*time.Second)), read(from.Add(3*time.Second)), read(from.Add(-7*24*time.Hour))
	good.ICMP = &entity.ICMPMeasurement{Requested: 5, Attempted: 5, Transmitted: 5, Replies: 3, ReadComplete: true}
	loss.ICMP = &entity.ICMPMeasurement{Requested: 5, Attempted: 5, Transmitted: 5, ReadComplete: true}
	local.ICMP = &entity.ICMPMeasurement{Requested: 5, Attempted: 5, Transmitted: 5, IOFailed: true}
	canceled.Outcome = &entity.ProbeOutcome{Canceled: true, Success: true}
	previous.Outcome = &entity.ProbeOutcome{Success: false}
	canceled.TestID, previous.TestID = application.TestID, application.TestID
	reads := []store.IncidentTestMeasurement{good, loss, local, canceled, previous}
	result, err := summarizeIncidentTests(t.Context(), "own", []store.IncidentConfiguredTest{source, application}, reads, from, from.Add(time.Minute), 1<<20)
	if err != nil || len(result) != 2 {
		t.Fatal(result, err)
	}
	current, old := result[0].Current, result[1].Previous
	if current.Successful != 1 || current.Failed != 1 || current.Unknown != 1 || len(current.Observations) != 3 || result[1].Current.Unknown != 1 || result[1].Current.Canceled != 1 || old.Failed != 1 || len(old.Observations) != 1 {
		t.Fatal("original windows, cancellation or incomplete IO became fabricated health", current, old)
	}
	if current.Packets == nil || current.Packets.Transmitted != "10" || current.Packets.Received != "3" || current.Packets.Lost != "7" || old.Packets != nil {
		t.Fatal("only complete ICMP batches may establish packet loss", current.Packets, old.Packets)
	}
	if current.Observations[2].Packets == nil || current.Observations[2].Packets.Lost != "" {
		t.Fatal("an unfinished receive window manufactured packet loss", current.Observations[2])
	}
	// Summation preserves counters beyond JavaScript and uint64 precision.
	period := incident.ImpactTestPeriod{Packets: &incident.ImpactTestPackets{Requested: "18446744073709551615", Transmitted: "18446744073709551615", Received: "0", Lost: "18446744073709551615"}}
	addIncidentTestObservation(&period, incident.ImpactTestObservation{Status: "failed", Packets: &incident.ImpactTestPackets{Requested: "1", Transmitted: "1", Received: "0", Lost: "1"}})
	if period.Packets.Lost != "18446744073709551616" {
		t.Fatal("packet math narrowed the complete population", period.Packets)
	}
	value := incident.ImpactResponse{IncidentID: googleuuid.NewString(), Tests: result}
	encoded, err := marshalNativeIncidentImpact(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(ai.RedactTextForTenant(string(encoded), ai.DefaultRedaction, "own"))
	var decoded incident.ImpactResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil || len(decoded.Tests) != 2 || decoded.Tests[0].TestID != source.TestID || decoded.Tests[0].Current.Observations[0].EvidenceID != good.EvidenceID || decoded.Tests[0].Current.Packets.Lost != "7" || strings.Contains(string(encoded), "person@example.test") {
		t.Fatal("native redaction damaged typed math/citations or disclosed labels", string(encoded), err)
	}
	private, err := redactIncidentImpact(value, ai.DefaultRedaction, "own")
	if err != nil || private.Tests[0].Name == source.Name || private.Tests[0].AgentID == source.AgentID || private.Tests[0].Current.Observations[0].EvidenceID != good.EvidenceID || value.Tests[0].Name != source.Name {
		t.Fatal("signed projection changed the source or failed privacy", private, err)
	}
	foreign := good
	foreign.TenantID = "sibling"
	if out, err := summarizeIncidentTests(t.Context(), "own", []store.IncidentConfiguredTest{source}, []store.IncidentTestMeasurement{foreign}, from, from.Add(time.Minute), 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || out != nil {
		t.Fatal("sibling observations supplied measured impact", out, err)
	}
	if out, err := summarizeIncidentTests(t.Context(), "own", []store.IncidentConfiguredTest{source}, reads, from, from.Add(time.Minute), 4096); !errors.Is(err, flowstore.ErrExplorerBudget) || out != nil {
		t.Fatal("memory refusal returned a measurement prefix", out, err)
	}
}
