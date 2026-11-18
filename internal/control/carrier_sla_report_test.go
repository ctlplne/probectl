// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCarrierSLAReportTemplatesRequireExplicitFinancialSlotsAndExactRevisions(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	definition := &reporting.CarrierSLAReportDefinition{Selections: []reporting.CarrierSLAReportSelection{{AgreementID: id, Version: "9007199254740993"}, {AgreementID: id, Version: "9007199254740993", At: "2026-10-01T00:00:00Z"}}}
	if err := cleanCarrierSLAReportDefinition(&dashboardDefinition{CarrierClaim: definition}); err != nil {
		t.Fatal(err)
	}
	portable := portableCarrierSLAReportDefinition(definition)
	raw, _ := json.Marshal(portable)
	if bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("9007199254740993")) || portable.Selections[0].Slot != portable.Selections[1].Slot {
		t.Fatal("financial identities leaked into portable template", string(raw))
	}
	bindings := []map[string]reporting.CarrierSLAReportAgreementBinding{{"agreement-1": {AgreementID: id, Version: "9007199254740993"}}}
	bound, err := bindCarrierSLAReportManifest(portable, bindings)
	if err != nil || bound.Selections[0] != definition.Selections[0] || bound.Selections[1] != definition.Selections[1] {
		t.Fatal("explicit recorded revision changed", bound, err)
	}
	if _, err := bindCarrierSLAReportManifest(portable, nil); err == nil {
		t.Fatal("missing financial binding inferred")
	}
	bindings[0]["unused"] = bindings[0]["agreement-1"]
	if _, err := bindCarrierSLAReportManifest(portable, bindings); err == nil {
		t.Fatal("unused financial binding accepted")
	}
	for _, invalid := range []dashboardDefinition{{CarrierClaim: definition, ClientReport: &reporting.ClientReportDefinition{}}, {CarrierClaim: definition, Metrics: map[string]string{"invented credit": "10"}}, {CarrierClaim: &reporting.CarrierSLAReportDefinition{Selections: []reporting.CarrierSLAReportSelection{{AgreementID: id, Version: "01"}}}}} {
		if err := cleanCarrierSLAReportDefinition(&invalid); err == nil {
			t.Fatal("ambiguous report source or revision accepted")
		}
	}
}

func TestCarrierSLAReportRequirementsKeepTwoTenantBoundariesAndNoStoredGrant(t *testing.T) {
	a, b := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, tenant := range []string{a, b} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		value := carrierSLAReportRequirement{AgreementID: "33333333-3333-4333-8333-333333333333", Version: "1", CurrentVersion: "1", DefinitionDigest: strings.Repeat("a", 64), Period: flow.CapacityBillingPeriod{From: from, To: from.AddDate(0, 1, 0), Timezone: "UTC", BillingDay: 1}, Tests: []store.ReportTestRequirement{{TenantID: tenant, ContextID: "44444444-4444-4444-8444-444444444444", EntityID: "55555555-5555-4555-8555-555555555555", TestID: "66666666-6666-4666-8666-666666666666", AgentID: "agent", SourceGeneration: 1, ConfigurationDigest: strings.Repeat("b", 64)}}}
		capture := &reportFlowCapture{TenantID: tenant, Claims: []carrierSLAReportRequirement{value}}
		raw, err := marshalReportSourceRequirements(ctx, capture, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parseReportSourceRequirements(ctx, raw, 8<<20)
		if err != nil || len(parsed.Claims) != 1 || parsed.claimCapture != nil || parsed.release != nil || len(parsed.Tables) != 0 {
			t.Fatal("requirements became rows or a grant", err)
		}
		other := a
		if tenant == a {
			other = b
		}
		if _, err := parseReportSourceRequirements(tenancy.WithTenant(t.Context(), tenancy.ID(other)), raw, 8<<20); err == nil {
			t.Fatal("foreign stored source checklist accepted")
		}
		foreign := value
		foreign.Tests = append([]store.ReportTestRequirement{}, value.Tests...)
		foreign.Tests[0].TenantID = other
		if err := validateCarrierSLAReportRequirements(ctx, tenant, []carrierSLAReportRequirement{foreign}, 8<<20); err == nil {
			t.Fatal("nested foreign test requirements accepted")
		}
		capture.Monthly = &clientReportSourceRequirements{}
		if _, err := marshalReportSourceRequirements(ctx, capture, 8<<20); err == nil {
			t.Fatal("mixed source envelope accepted")
		}
	}
}

func TestCarrierSLAReportIncludesCompleteSignedChunksAndExactOriginalTiming(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	server := testServer(fakePinger{})
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	server.evidenceSigningKey = key
	_, _, reads, _ := carrierSLAMeasureFixture(t, tenant)
	reads[0].ICMP.RoundTrips.Nanos[0] = 9007199254740993
	writer := server.newCarrierSLAOriginalWriter(tenant)
	var original bytes.Buffer
	if err := writer.write(ctx, &original, reads[0], 8<<20); err != nil {
		t.Fatal(err)
	}
	var replay bytes.Buffer
	if err := writer.write(ctx, &replay, reads[0], 8<<20); err != nil || !bytes.Equal(replay.Bytes(), original.Bytes()) {
		t.Fatal("cached tenant redaction changed original signed bytes", err)
	}
	foreignOriginal := reads[0]
	foreignOriginal.TenantID = "22222222-2222-4222-8222-222222222222"
	var refused bytes.Buffer
	if err := writer.write(ctx, &refused, foreignOriginal, 8<<20); err == nil || refused.Len() != 0 {
		t.Fatal("cached original writer accepted a sibling row")
	}
	if !bytes.Contains(original.Bytes(), []byte(`"9007199254740993"`)) || bytes.Contains(original.Bytes(), []byte(tenant)) {
		t.Fatal("exact timing or tenant redaction lost", original.String())
	}
	// More than one transfer chunk exercises complete reassembly without a
	// display-page dependency or a single enormous renderer cell.
	body := []byte(`{"measurements":[` + strings.Repeat(original.String()+",", 70) + original.String() + "]}")
	stage, _, err := reporting.StageBody(ctx, tenant, reporting.BodyStageLimitsForBytes(8<<20), func(w io.Writer) error { _, err := w.Write(body); return err })
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	draft := flow.CarrierSLAClaimDraft{GeneratedAt: time.Now().UTC(), Groups: []flow.CarrierSLAClaimGroup{{Period: flow.CapacityBillingPeriod{From: from, To: from.AddDate(0, 1, 0)}}}, HumanReview: true, SubmissionState: "not_submitted"}
	signed, id, err := server.signCarrierSLAReport(ctx, tenant, draft, stage, flowstore.DefaultExplorerBudget())
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Close()
	capture := &reportFlowCapture{TenantID: tenant, claimCapture: &carrierSLAReportCapture{draft: draft, signed: signed, packageID: id}}
	tables, err := carrierSLAReportTables(ctx, capture, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	var complete bytes.Buffer
	if tables[len(tables)-1].ExpectedRows < 2 {
		t.Fatal("fixture did not exercise transfer boundaries")
	}
	if err := tables[len(tables)-1].WalkRows(ctx, func(row []string) error {
		raw, err := base64.StdEncoding.DecodeString(row[5])
		if err != nil {
			return err
		}
		_, err = complete.Write(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	manifest, err := evidence.Verify(complete.Bytes())
	if err != nil || manifest.Profile != "carrier-sla" || manifest.PackageID != id {
		t.Fatal("complete signed report cannot verify offline", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(complete.Bytes(), &pkg); err != nil || len(pkg.Attachments) != 2 || !bytes.Equal(pkg.Attachments[1].Content, body) {
		t.Fatal("originals were shortened or rewritten", err)
	}
	changed := bytes.Replace(complete.Bytes(), []byte("9007199254740993"), []byte("9007199254740994"), 1)
	if _, err := evidence.Verify(changed); err == nil {
		t.Fatal("tampered originals verified")
	}
	foreign := tenancy.WithTenant(t.Context(), "22222222-2222-4222-8222-222222222222")
	if err := tables[len(tables)-1].WalkRows(foreign, func([]string) error { return nil }); err == nil {
		t.Fatal("foreign reader streamed financial evidence")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := tables[len(tables)-1].WalkRows(canceled, func([]string) error { return nil }); err == nil {
		t.Fatal("canceled report stream survived")
	}
}

func TestCarrierSLAReportRedactsOperatorSelectorsWithoutMergingOrRepricing(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	exact := "100000000000000000001/1000000000000000000"
	sourceID := "context:device:" + tenant + "/agent:test"
	input := flow.CarrierSLAClaimDraft{Groups: []flow.CarrierSLAClaimGroup{}}
	for range 2 {
		input.Groups = append(input.Groups, flow.CarrierSLAClaimGroup{Carrier: tenant, Currency: "USD", ExactCredit: &exact, Circuits: []flow.CarrierSLAStatement{{Agreement: flow.CapacityAgreement{TenantID: tenant, Definition: flow.CapacityAgreementDefinition{Name: tenant, UnitPrice: "12345678901234567890.000000000001", SLA: &flow.CarrierSLATerms{Carrier: tenant, CircuitID: tenant, Site: tenant, Sources: []flow.CarrierSLASource{{AgentID: tenant + "/agent", TestID: "test"}}, Rules: []flow.CarrierSLARule{{ID: tenant}}}}}, Sources: []flow.CarrierSLAPopulation{{ID: sourceID, AgentID: tenant + "/agent", Originals: "500001"}}, Credit: flow.CarrierSLACredit{ExactCredit: &exact, Assessments: []flow.CarrierSLAAssessment{{RuleID: tenant, MeasurementID: tenant, Citations: []string{sourceID}, Value: "1/3"}}}}}})
	}
	output, err := testServer(fakePinger{}).publicCarrierSLAClaim(ctx, tenant, input, 8<<20)
	if err != nil || len(output.Groups) != 2 {
		t.Fatal("redaction merged independently selected carrier groups", err)
	}
	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(tenant)) || !bytes.Contains(raw, []byte(exact)) || !bytes.Contains(raw, []byte("500001")) || !bytes.Contains(raw, []byte("12345678901234567890.000000000001")) {
		t.Fatal("tenant identifiers survived or exact financial/original values changed")
	}
	source := output.Groups[0].Circuits[0]
	if source.Sources[0].ID != source.Credit.Assessments[0].Citations[0] || source.Agreement.Definition.SLA.Rules[0].ID != source.Credit.Assessments[0].RuleID {
		t.Fatal("redacted references detached the signed assessments from their sources or terms")
	}
	if input.Groups[0].Carrier != tenant || input.Groups[0].Circuits[0].Sources[0].ID != sourceID {
		t.Fatal("public redaction mutated retained private originals")
	}
}
