// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags(t *testing.T) {
	f, rows, actors, at := newRoleFlowQueryFixture(t)
	// Use the shipped native backend; the mutation wrapper belongs to another
	// proof and is intentionally not a supported report batch implementation.
	f.server.WithFlowStore(rows.Memory).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.pool, 0, audit.TenantRecord))
	captures := map[string]*reportFlowCapture{}
	saved := map[string]flow.SavedQueryView{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permMetricsWrite)
		})
		ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actors[tenant])
		ctx, err := f.server.withFlowViewVocabulary(ctx, actors[tenant])
		if err != nil {
			t.Fatal(err)
		}
		current, err := loadCurrentUserAuthority(ctx, f.pool, tenant, actors[tenant].UserID)
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the exact scheduled-source ceiling, then the same current
		// actor source capture used by both schedules and interactive reports.
		ctx, scheduled, err := current.backgroundContext(ctx, reportBackgroundSourcePermissions())
		if err != nil {
			t.Fatal(err)
		}
		view, err := views.SaveQueryView(ctx, tenant, actors[tenant].UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Canonical role report", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), DataSeries: "raw", GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		saved[tenant] = view
		capture, err := f.server.captureReportFlowSources(ctx, scheduled, []reportFlowSourceRef{{ID: view.ID, Version: view.Version}})
		if err != nil {
			t.Fatal("role-only report could not capture its admitted sources", err)
		}
		t.Cleanup(capture.Close)
		if !capture.ContextSources || !capture.ContextsCaptured || len(capture.Contexts) != 1 || capture.Contexts[0].ContextID != f.contextID || capture.Contexts[0].Resource[auth.ResourceTenantKey] != tenant {
			t.Fatal("role-only report lost complete canonical source context")
		}
		raw, err := marshalReportSourceRequirements(ctx, capture)
		if err != nil {
			t.Fatal("role-only report could not seal complete source requirements", err)
		}
		stored, err := parseReportSourceRequirements(ctx, raw)
		if err != nil || f.server.revalidateReportFlowCapture(ctx, actors[tenant], stored) != nil {
			t.Fatal("current role report source requirements were not readable", err)
		}
		captures[tenant] = stored
	}
	red, blue := f.tenants[0], f.tenants[1]
	socket := httptest.NewTLSServer(f.server.Handler())
	defer socket.Close()
	artifacts := map[string]string{}
	for _, tenant := range f.tenants {
		definition := reporting.DashboardDefinition{FlowSources: []reporting.FlowSourceRef{{ID: saved[tenant].ID, Version: saved[tenant].Version}}, Provenance: []string{"current canonical role source"}, RedactionState: "tenant source policy", CoverageLimitations: []string{"modeled flow rows on current PostgreSQL contexts"}}
		status, body := reportProofJSON(t, socket, f.tokens[tenant], http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{Name: "Canonical role report", Preset: "operator", Definition: definition})
		var dashboard store.DashboardView
		if status != http.StatusCreated || json.Unmarshal(body, &dashboard) != nil {
			t.Fatal("role dashboard was not created through HTTPS", status, string(body))
		}
		status, body = reportProofJSON(t, socket, f.tokens[tenant], http.MethodPost, "/v1/dashboard-reports", reporting.ReportGenerateInput{DashboardID: dashboard.ID, Format: "csv"})
		var artifact reportArtifactView
		if status != http.StatusCreated || json.Unmarshal(body, &artifact) != nil {
			t.Fatal("role report was not generated through HTTPS", status, string(body))
		}
		artifacts[tenant] = artifact.ID
		status, headers, content := requestCapturedReport(t, socket, f.tokens[tenant], artifact.ID)
		if status != http.StatusOK || len(content) == 0 || headers.Get("X-Report-SHA256") != fmt.Sprintf("%x", crypto.Hash(content)) || !bytes.Contains(content, []byte("Canonical role report")) {
			t.Fatal("served role artifact lost complete verified content", status)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			metadata, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, artifact.ID, actors[tenant].UserID)
			if err != nil {
				return err
			}
			requirements, err := parseReportSourceRequirements(ctx, metadata.SourceCapture)
			if err != nil {
				return err
			}
			if metadata.BodyStorage != "chunks" || !requirements.ContextSources || !requirements.ContextsCaptured || len(requirements.Contexts) != 1 || requirements.Contexts[0].ContextID != f.contextID || requirements.Contexts[0].Resource[auth.ResourceTenantKey] != tenant || len(requirements.Inputs) != 1 || requirements.Inputs[0].ID != saved[tenant].ID {
				t.Fatal("served role report did not persist its complete canonical source receipt")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range f.tenants {
		other := red
		if tenant == red {
			other = blue
		}
		if status, _, _ := requestCapturedReport(t, socket, f.tokens[other], artifacts[tenant]); status != http.StatusNotFound {
			t.Fatal("sibling read a role source artifact", status)
		}
	}
	f.in(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny-report-role-source", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"context_id": f.contextID}, Priority: 100})
		return err
	})
	ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(red)), actors[red])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[red], captures[red]); err == nil {
		t.Fatal("report reader reused role source after its context denial")
	}
	ctx = auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(blue)), actors[blue])
	if err := f.server.revalidateReportFlowCapture(ctx, actors[blue], captures[blue]); err != nil {
		t.Fatal("role report context denial crossed tenant", err)
	}
	if status, _, _ := requestCapturedReport(t, socket, f.tokens[red], artifacts[red]); status != http.StatusNotFound {
		t.Fatal("stored role artifact ignored current context denial", status)
	}
	if status, _, _ := requestCapturedReport(t, socket, f.tokens[blue], artifacts[blue]); status != http.StatusOK {
		t.Fatal("unaffected tenant lost its role artifact", status)
	}
	t.Log("real-integration: HTTPS role artifact, sealed canonical source receipt, current app-role Postgres denial and sibling isolation; flow rows and sender metadata modeled")
}
