// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ctlplne/probectl/internal/testspec"
	"testing"
)

func TestReportArtifactSourceCaptureVersionsStayTenantBound(t *testing.T) {
	const tenant = "10000000-0000-4000-8000-000000000001"
	for _, version := range []int{1, 2, 3} {
		capture := json.RawMessage(fmt.Sprintf(`{"version":%d,"tenant_id":%q}`, version, tenant))
		if err := reportArtifactSourceCapture(tenant, capture); err != nil {
			t.Fatalf("compatible tenant report receipt version %d refused: %v", version, err)
		}
		if err := reportArtifactSourceCapture("20000000-0000-4000-8000-000000000002", capture); !errors.Is(err, ErrReportArtifactIntegrity) {
			t.Fatalf("version %d source receipt crossed tenant boundary: %v", version, err)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"version":0}`, `{"version":4}`, `{"version":"2"}`, `[]`, `{`,
		fmt.Sprintf(`{"version":2,"tenant_id":%q} {}`, tenant),
		fmt.Sprintf(`{"version":4,"tenant_id":%q}`, tenant),
		fmt.Sprintf(`{"version":0,"tenant_id":%q}`, tenant)} {
		if err := reportArtifactSourceCapture(tenant, json.RawMessage(raw)); !errors.Is(err, ErrReportArtifactIntegrity) {
			t.Fatalf("invalid report receipt accepted: %s: %v", raw, err)
		}
	}
}

func TestClientReportRequirementsOmitExecutableParameters(t *testing.T) {
	source := IncidentConfiguredTest{TenantID: "tenant", ContextID: "context", EntityID: "entity", TestID: "test", AgentID: "agent", SourceGeneration: 1, Name: "private test name", Target: "private target", Definition: testspec.ExecutableDefinition{Params: map[string]string{"credential_reference": "private configuration reference"}}}
	requirements, err := ClientReportTestRequirements([]IncidentConfiguredTest{source})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(requirements)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{source.Name, source.Target, source.Definition.Params["credential_reference"], "credential_reference"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("executable configuration copied to retained report requirements")
		}
	}
	if len(requirements) != 1 || len(requirements[0].ConfigurationDigest) != 64 {
		t.Fatal("source configuration digest missing")
	}
	source.Definition.Params["credential_reference"] = "different private reference"
	changed, err := ClientReportTestRequirements([]IncidentConfiguredTest{source})
	if err != nil {
		t.Fatal(err)
	}
	if changed[0].ConfigurationDigest == requirements[0].ConfigurationDigest {
		t.Fatal("changed executable definition retained old authority digest")
	}
}
