// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func reportRequirementsFixture(tenant string) *reportFlowCapture {
	const contextID = "44444444-4444-4444-8444-444444444444"
	at := time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC)
	return &reportFlowCapture{
		TenantID: tenant, Tables: []reporting.CSVTable{{TenantID: tenant}},
		Inputs:      []reportFlowInput{{ID: "33333333-3333-4333-8333-333333333333", Version: "9007199254740993", Period: "current", TagRevision: "9007199254740993", From: at.Add(-time.Hour), To: at, TagAsOf: at}},
		Permissions: []string{permAIQuery, permFlowRead, permTagsRead}, ContextsCaptured: true,
		Contexts: []reportContextRequirement{{ContextID: contextID, Permissions: []string{permFlowRead, permTagsRead}, Resource: map[string]string{auth.ResourceTenantKey: tenant, "context_id": contextID, "site_id": "55555555-5555-4555-8555-555555555555", "vrf_id": "66666666-6666-4666-8666-666666666666", "site_label": "東京 site", "vrf_label": "private"}}},
	}
}

func TestReportStoredRequirementsPreserveExactIdentityWithoutRowsOrGrants(t *testing.T) {
	tenants := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	for i, tenant := range tenants {
		t.Run(tenant, func(t *testing.T) {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			original := reportRequirementsFixture(tenant)
			raw, err := marshalReportSourceRequirements(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(`"version":"9007199254740993"`)) || bytes.Contains(raw, []byte(`"tables"`)) {
				t.Fatal("stored requirements rounded identity or retained result rows")
			}
			parsed, err := parseReportSourceRequirements(ctx, raw)
			if err != nil || parsed.TenantID != tenant || !reflect.DeepEqual(parsed.Inputs, original.Inputs) || !reflect.DeepEqual(parsed.Contexts, original.Contexts) || !reflect.DeepEqual(parsed.Permissions, original.Permissions) || !parsed.ContextsCaptured || len(parsed.Tables) != 0 || parsed.release != nil {
				t.Fatal("stored requirements changed scope or became a result/admission grant", err)
			}
			original.Contexts[0].Resource["site_label"] = "changed caller memory"
			if parsed.Contexts[0].Resource["site_label"] != "東京 site" {
				t.Fatal("decoded requirements borrowed mutable source memory")
			}
			for _, denied := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID(tenants[1-i]))} {
				if value, err := parseReportSourceRequirements(denied, raw); err == nil || value != nil {
					t.Fatal("stored source requirements escaped bound tenant")
				}
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if value, err := parseReportSourceRequirements(canceled, raw); !errors.Is(err, context.Canceled) || value != nil {
				t.Fatal("canceled reader retained requirements", err)
			}
		})
	}
}

func TestReportStoredRequirementsRefuseIncompleteAmbiguousOrOverBudgetEnvelope(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	raw, err := marshalReportSourceRequirements(ctx, reportRequirementsFixture(tenant))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"version":            func(v map[string]any) { v["version"] = 2 },
		"foreign":            func(v map[string]any) { v["tenant_id"] = "22222222-2222-4222-8222-222222222222" },
		"unknown-credential": func(v map[string]any) { v["credential"] = true },
		"missing-inputs":     func(v map[string]any) { delete(v, "inputs") },
		"missing-grants":     func(v map[string]any) { v["permissions"] = []string{permAIQuery} },
		"write-grant": func(v map[string]any) {
			v["permissions"] = []string{permAIQuery, permFlowRead, permTagsRead, permAgentWrite}
		},
		"uncaptured-context":   func(v map[string]any) { v["contexts_captured"] = false },
		"duplicate-period":     func(v map[string]any) { in := v["inputs"].([]any); v["inputs"] = append(in, in[0]) },
		"missing-current":      func(v map[string]any) { v["inputs"].([]any)[0].(map[string]any)["period"] = "previous" },
		"rounded-version":      func(v map[string]any) { v["inputs"].([]any)[0].(map[string]any)["version"] = float64(9007199254740993) },
		"missing-tag-revision": func(v map[string]any) { delete(v["inputs"].([]any)[0].(map[string]any), "tag_revision") },
		"incomplete-context": func(v map[string]any) {
			delete(v["contexts"].([]any)[0].(map[string]any)["resource"].(map[string]any), "site_label")
		},
		"foreign-context-resource": func(v map[string]any) {
			v["contexts"].([]any)[0].(map[string]any)["resource"].(map[string]any)[auth.ResourceTenantKey] = "22222222-2222-4222-8222-222222222222"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			mutate(value)
			bad, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if decoded, err := parseReportSourceRequirements(ctx, bad); err == nil || decoded != nil {
				t.Fatal("incomplete stored source requirements became readable")
			}
		})
	}
	for _, bad := range [][]byte{nil, append(append([]byte(nil), raw...), []byte(` {}`)...), bytes.Repeat([]byte("x"), store.ReportArtifactSourceEnvelopeMaxBytes+1)} {
		if decoded, err := parseReportSourceRequirements(ctx, bad); err == nil || decoded != nil {
			t.Fatal("malformed, trailing or over-budget requirements accepted")
		}
	}
	for _, label := range []string{strings.Repeat("x", store.ReportArtifactSourceEnvelopeMaxBytes+1), strings.Repeat("<", store.ReportArtifactSourceEnvelopeMaxBytes/2)} {
		value := reportRequirementsFixture(tenant)
		value.Contexts[0].Resource["site_label"] = label
		if encoded, err := marshalReportSourceRequirements(ctx, value); err == nil || encoded != nil {
			t.Fatal("raw or escaped metadata limit yielded a partial envelope")
		}
	}
	foreign := reportRequirementsFixture(tenant)
	foreign.Tables[0].TenantID = "22222222-2222-4222-8222-222222222222"
	if encoded, err := marshalReportSourceRequirements(ctx, foreign); err == nil || encoded != nil {
		t.Fatal("foreign result table produced owned requirements")
	}
}
