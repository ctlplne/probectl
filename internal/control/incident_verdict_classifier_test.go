// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func verdictClassifierFixture() (context.Context, incidentVerdictEvidence) {
	const tenant = "9d15bcbc-38ad-4e2e-973c-4c69623db2be"
	to := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	return tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), incidentVerdictEvidence{
		tenantID: tenant, from: to.Add(-time.Minute), to: to,
	}
}

func verdictHTTPTest(input incidentVerdictEvidence, agent, evidence string, status int) incidentVerdictTest {
	until := time.Now().Add(time.Hour)
	at := input.from.Add(30 * time.Second)
	source := store.IncidentConfiguredTest{TenantID: input.tenantID, SourceGeneration: 1,
		ContextID: "9df966f1-6882-4654-8cd4-7d3cc7898e73", EntityID: "71e9f275-fbf2-4eca-bc75-1fb0e27b8724",
		TestID: "35da0055-52aa-4af8-83c5-01e505ff5aad", AgentID: agent, Type: "http", Target: "https://service.example/api?secret=excluded",
		CurrentSince: input.from.Add(-time.Hour), MeasurementIdentityUntil: &until,
		Definition: testspec.ExecutableDefinition{Type: "http", Target: "https://service.example/api?secret=excluded"}}
	return incidentVerdictTest{source: source, reads: []store.IncidentTestMeasurement{{TenantID: source.TenantID,
		SourceGeneration: source.SourceGeneration, ContextID: source.ContextID, EntityID: source.EntityID, TestID: source.TestID,
		AgentID: agent, EvidenceID: evidence, ObservedAt: at, Available: true, CaptureDigest: [32]byte{1},
		Outcome: &entity.ProbeOutcome{Version: 2, CanaryType: "http", StartedAt: at.Add(-time.Second), CompletedAt: at,
			Success: status >= 200 && status <= 299, HTTPResponse: &entity.ProbeHTTPResponse{StatusCode: status, TLSVerified: true, SameOrigin: true}}}}}
}

func verdictLocalInterface(input incidentVerdictEvidence, oper, admin uint32) incidentVerdictInterface {
	source := store.IncidentInterfaceStateSource{TenantID: input.tenantID, SourceGeneration: 1,
		ContextID: "9df966f1-6882-4654-8cd4-7d3cc7898e73", EntityID: "71399313-d072-4d4b-bb2b-7302a85c87ae",
		AgentID: "device-a", ConfiguredRef: "router-a", IfIndex: 7, Current: true, CurrentSince: input.from.Add(-time.Hour)}
	return incidentVerdictInterface{source: source, direct: true,
		role: interfaceRoleExplanation{Scope: entity.Scope{TenantID: source.TenantID, ContextID: source.ContextID},
			InterfaceID: source.EntityID, Role: interfaceRoleBackbone, SNMPCurrent: true},
		reads: []store.IncidentInterfaceStateMeasurement{{TenantID: source.TenantID, ContextID: source.ContextID,
			EntityID: source.EntityID, AgentID: source.AgentID, ConfiguredRef: source.ConfiguredRef, SourceGeneration: source.SourceGeneration,
			IfIndex: source.IfIndex, EvidenceID: "local-evidence", ObservedAt: input.from.Add(30 * time.Second),
			Available: true, OriginalSenderValid: true, CaptureDigest: [32]byte{2},
			State: &entity.SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}}}}
}

func TestIncidentVerdictOriginalLocalAndRemoteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		fill func(*incidentVerdictEvidence)
		want incident.FaultDomain
	}{
		{"thin", func(*incidentVerdictEvidence) {}, incident.FaultUnknown},
		{"local", func(in *incidentVerdictEvidence) {
			in.interfaces = []incidentVerdictInterface{verdictLocalInterface(*in, 2, 1)}
		}, incident.FaultYourNetwork},
		{"intentional admin down", func(in *incidentVerdictEvidence) {
			in.interfaces = []incidentVerdictInterface{verdictLocalInterface(*in, 2, 2)}
		}, incident.FaultUnknown},
		{"carrier label alone", func(in *incidentVerdictEvidence) {
			item := verdictLocalInterface(*in, 2, 1)
			item.role.Role = interfaceRoleTransit
			in.interfaces = []incidentVerdictInterface{item}
		}, incident.FaultUnknown},
		{"remote", func(in *incidentVerdictEvidence) {
			in.tests = []incidentVerdictTest{verdictHTTPTest(*in, "a", "http-a", 503), verdictHTTPTest(*in, "b", "http-b", 502)}
		}, incident.FaultRemoteService},
		{"one agent is thin", func(in *incidentVerdictEvidence) {
			in.tests = []incidentVerdictTest{verdictHTTPTest(*in, "a", "http-a", 503), verdictHTTPTest(*in, "a", "http-b", 503)}
		}, incident.FaultUnknown},
		{"nonstandard status is not server failure", func(in *incidentVerdictEvidence) {
			in.tests = []incidentVerdictTest{verdictHTTPTest(*in, "a", "http-a", 777), verdictHTTPTest(*in, "b", "http-b", 777)}
		}, incident.FaultUnknown},
		{"competing local and remote", func(in *incidentVerdictEvidence) {
			in.interfaces = []incidentVerdictInterface{verdictLocalInterface(*in, 2, 1)}
			in.tests = []incidentVerdictTest{verdictHTTPTest(*in, "a", "http-a", 503), verdictHTTPTest(*in, "b", "http-b", 503)}
		}, incident.FaultUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, input := verdictClassifierFixture()
			tc.fill(&input)
			got, err := classifyIncidentVerdict(ctx, input, 1<<20)
			if err != nil || got.Domain != tc.want || len(got.Hypotheses) != 4 {
				t.Fatalf("domain=%s want=%s hypotheses=%d error=%v", got.Domain, tc.want, len(got.Hypotheses), err)
			}
			if len(got.Hypotheses[1].Missing) == 0 || len(got.Hypotheses[2].Missing) == 0 {
				t.Fatal("unmeasured carrier/internet planes were hidden")
			}
			if tc.want == incident.FaultRemoteService && len(got.Hypotheses[3].For) != 2 {
				t.Fatal("original HTTP citations were lost", got)
			}
		})
	}
}

func TestIncidentVerdictKeepsOriginalContradictionsAndCoverage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*incidentVerdictEvidence)
	}{
		{"TLS unverified", func(in *incidentVerdictEvidence) { in.tests[1].reads[0].Outcome.HTTPResponse.TLSVerified = false }},
		{"different origin", func(in *incidentVerdictEvidence) {
			in.tests[1].source.Target = "https://elsewhere.example"
			in.tests[1].source.Definition.Target = in.tests[1].source.Target
		}},
		{"cross-origin final", func(in *incidentVerdictEvidence) { in.tests[1].reads[0].Outcome.HTTPResponse.SameOrigin = false }},
		{"canceled", func(in *incidentVerdictEvidence) { in.tests[1].reads[0].Outcome.Canceled = true }},
		{"no temporal overlap", func(in *incidentVerdictEvidence) {
			read := &in.tests[1].reads[0]
			read.ObservedAt = read.ObservedAt.Add(10 * time.Second)
			read.Outcome.StartedAt, read.Outcome.CompletedAt = read.ObservedAt.Add(-time.Second), read.ObservedAt
		}},
		{"original success", func(in *incidentVerdictEvidence) {
			in.tests = append(in.tests, verdictHTTPTest(*in, "c", "http-c", 200))
		}},
		{"duplicate delivery", func(in *incidentVerdictEvidence) { in.tests[1] = in.tests[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, input := verdictClassifierFixture()
			input.tests = []incidentVerdictTest{verdictHTTPTest(input, "a", "http-a", 503), verdictHTTPTest(input, "b", "http-b", 503)}
			tc.change(&input)
			got, err := classifyIncidentVerdict(ctx, input, 1<<20)
			if err != nil || got.Domain != incident.FaultUnknown {
				t.Fatal("thin/contradictory originals became a remote verdict", got, err)
			}
		})
	}
	ctx, input := verdictClassifierFixture()
	item := verdictLocalInterface(input, 2, 1)
	gap := item.reads[0]
	gap.EvidenceID, gap.State, gap.Available = "explicit-gap", nil, false
	item.reads = append(item.reads, gap)
	input.interfaces = []incidentVerdictInterface{item}
	got, err := classifyIncidentVerdict(ctx, input, 1<<20)
	if err != nil || got.Domain != incident.FaultUnknown || len(got.Hypotheses[0].For) != 1 || len(got.Hypotheses[0].Missing) == 0 {
		t.Fatal("an original gap was filled from a previous state", got, err)
	}
}

func TestIncidentVerdictTwoTenantAndSourceIsolation(t *testing.T) {
	for _, change := range []func(*incidentVerdictEvidence){
		func(in *incidentVerdictEvidence) {
			in.tests[1].source.TenantID = "12ba5647-5d1e-44ec-b77f-a9bc10ed3377"
		},
		func(in *incidentVerdictEvidence) {
			in.tests[1].reads[0].TenantID = "12ba5647-5d1e-44ec-b77f-a9bc10ed3377"
		},
		func(in *incidentVerdictEvidence) {
			in.tests[1].reads[0].ContextID = "12ba5647-5d1e-44ec-b77f-a9bc10ed3377"
		},
		func(in *incidentVerdictEvidence) { in.tests[1].reads[0].AgentID = "other-agent" },
		func(in *incidentVerdictEvidence) { in.tests[1].reads[0].SourceGeneration++ },
	} {
		ctx, input := verdictClassifierFixture()
		input.tests = []incidentVerdictTest{verdictHTTPTest(input, "a", "http-a", 503), verdictHTTPTest(input, "b", "http-b", 503)}
		change(&input)
		got, err := classifyIncidentVerdict(ctx, input, 1<<20)
		if !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(got, incident.FaultVerdict{}) {
			t.Fatal("foreign/rebound source disclosed a partial verdict", got, err)
		}
	}
	ctx, input := verdictClassifierFixture()
	input.tests = []incidentVerdictTest{verdictHTTPTest(input, "a", "http-a", 503), verdictHTTPTest(input, "b", "http-b", 503)}
	input.tests[1].reads[0].EvidenceID = "http-a"
	if got, err := classifyIncidentVerdict(ctx, input, 1<<20); err == nil || !reflect.DeepEqual(got, incident.FaultVerdict{}) {
		t.Fatal("one original evidence ID was allowed to change sender", got, err)
	}
}
