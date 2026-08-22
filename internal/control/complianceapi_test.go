// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/config"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const testPolicyYAML = `name: pci-segmentation
zones:
  - name: cde
    cidrs: ["10.10.0.0/16"]
  - name: corp
    cidrs: ["10.20.0.0/16"]
rules:
  - id: corp-to-cde
    from: corp
    to: cde
    bidirectional: true
    frameworks:
      pci-dss: "Req 1.3 — network segmentation of the CDE"
`

func complianceTestEngine(t *testing.T) *compliance.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pci.yaml"), []byte(testPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, on, err := BuildCompliance(&config.Config{ComplianceEnabled: true, CompliancePolicyDir: dir}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildCompliance: on=%v err=%v", on, err)
	}
	return eng
}

func TestBuildComplianceDisabledAndFailClosed(t *testing.T) {
	if _, on, err := BuildCompliance(&config.Config{ComplianceEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	if _, _, err := BuildCompliance(&config.Config{ComplianceEnabled: true, CompliancePolicyDir: "/does/not/exist"}, intelTestLog()); err == nil {
		t.Fatal("missing policy dir must fail startup")
	}
}

// Flow batch with a forbidden conversation → violation verdict + a correlated
// incident (the S46 'Done when', end to end at the consumer).
func TestComplianceConsumerFlagsViolation(t *testing.T) {
	eng := complianceTestEngine(t)
	correlator := incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog())
	cc := NewComplianceConsumer(nil, eng, correlator, intelTestLog())

	batch := &flowv1.FlowBatch{Flows: []*flowv1.FlowRecord{{
		TenantId:           "t1",
		SourceAddress:      "10.20.1.5", // corp
		DestinationAddress: "10.10.2.9", // cde — forbidden
		DestinationPort:    443,
		Bytes:              4096,
		EndUnixNano:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
	}, {
		// Unscoped record: dropped (guardrail 1).
		SourceAddress: "10.20.1.5", DestinationAddress: "10.10.2.9",
	}}}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := cc.handleFlow(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}

	results := eng.Results("t1")
	if len(results) != 1 || results[0].Verdict != compliance.VerdictViolation || results[0].Violations != 1 {
		t.Fatalf("results = %+v", results)
	}
	if results[0].Samples[0].Src != "10.20.1.5" || results[0].Samples[0].Source != "flow" {
		t.Fatalf("evidence sample = %+v", results[0].Samples)
	}
}

func TestComplianceEndpointsAndIsolation(t *testing.T) {
	eng := complianceTestEngine(t)
	tid := tenancy.DefaultTenantID.String()
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	// A violation for the default tenant; another tenant stays clean.
	eng.Observe(tid, compliance.FlowObs{Src: "10.20.1.5", Dst: "10.10.2.9", DstPort: 443, Source: "flow", At: at})
	eng.Observe("other-tenant", compliance.FlowObs{Src: "10.20.9.9", Dst: "10.10.9.9", DstPort: 443, Source: "flow", At: at})

	srv := testServer(fakePinger{}).WithCompliance(eng)
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running  bool                    `json:"compliance_running"`
		Items    []compliance.RuleResult `json:"items"`
		Coverage compliance.Coverage     `json:"coverage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Items) != 1 || resp.Items[0].Verdict != compliance.VerdictViolation {
		t.Fatalf("resp = %+v", resp)
	}
	// TENANT ISOLATION: only the caller's violations/coverage appear.
	if resp.Coverage.Observations != 1 {
		t.Fatalf("cross-tenant observations leaked: %+v", resp.Coverage)
	}
	// Coverage honesty rides the response.
	if !strings.Contains(strings.Join(resp.Coverage.Notes, " "), "not proof") {
		t.Fatalf("coverage notes = %v", resp.Coverage.Notes)
	}

	// Evidence export verifies and carries the framework mapping.
	rec = do(srv, http.MethodGet, "/v1/compliance/evidence")
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence status = %d", rec.Code)
	}
	var ev compliance.Evidence
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil {
		t.Fatal(err)
	}
	if err := compliance.VerifyEvidence(ev); err != nil {
		t.Fatalf("exported evidence failed verification: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "Req 1.3") {
		t.Fatal("PCI mapping missing from evidence")
	}
}

func TestComplianceHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"compliance_running":false`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestComplianceEnabledWithoutPoliciesReturnsArray(t *testing.T) {
	srv := testServer(fakePinger{}).WithCompliance(compliance.NewEngine(nil))
	rec := do(srv, http.MethodGet, "/v1/compliance")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"compliance_running":true`) ||
		!strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("enabled empty response must preserve the array contract: %s", rec.Body.String())
	}
}
