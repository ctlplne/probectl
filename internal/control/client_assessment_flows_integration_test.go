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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
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
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real application-role PostgreSQL/RLS, metadata authority and complete flow
// query execution. Flow observations are modeled in the existing backend;
// this does not claim physical sender/collection or a complete engagement.
func TestAssessmentFlowSamplesKeepCompleteWindowsAndCurrentTwoTenantAuthority(t *testing.T) {
	f, rows, actors, at := newRoleFlowQueryFixture(t)
	f.server.WithFlowStore(rows.Memory).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	views := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.pool, 0, audit.TenantRecord))
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(private)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	native := newClientReportNativeProof(t, f, socket)
	end := at.Add(time.Microsecond)
	definitions := map[string]dashboardDefinition{}
	refs := map[string]reportFlowSourceRef{}
	captures := map[string]*reportFlowCapture{}
	artifacts := map[string]string{}
	clients := map[string]*sdk.Client{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permIncidentRead, permChangeRead, "topology.read", permMetricsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actors[tenant] = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		query, err := views.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Assessment flow " + tenant, Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 3600}, Plan: flow.QueryPlan{View: "table", DataSeries: "raw", GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		refs[tenant] = reportFlowSourceRef{ID: query.ID, Version: query.Version}
		definitions[tenant] = dashboardDefinition{ClientReport: &reporting.ClientReportDefinition{Timezone: "UTC", Period: "assessment", Assessment: &reporting.ClientReportAssessment{From: end.AddDate(0, 0, -14).Format(time.RFC3339Nano), To: end.Format(time.RFC3339Nano), Preparer: "Example MSP"}, CapacityTargets: []reporting.ClientReportCapacityTarget{}}, FlowSources: []reportFlowSourceRef{refs[tenant]}, RedactionState: "current tenant policy", Provenance: []string{"complete selected sample"}, CoverageLimitations: []string{"modeled flow observations; not continuous collection"}}
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		definition := definitions[tenant]
		if err := cleanDashboardDefinition(&definition); err != nil {
			t.Fatal(err)
		}
		capture, err := f.server.captureConfiguredReportSources(ctx, actors[tenant], definition, time.Now().UTC())
		if err != nil {
			t.Fatal("complete assessment and flow sample capture refused", err)
		}
		t.Cleanup(capture.Close)
		captures[tenant] = capture
		if capture.Monthly == nil || capture.monthlyCapture == nil || len(capture.Inputs) != 1 || !capture.Inputs[0].To.Equal(end) || !capture.Inputs[0].From.Equal(end.Add(-time.Hour)) {
			t.Fatal("flow sample used current wall time or replaced the assessment interval")
		}
		expected, foreign := "300", "900"
		if lane == 1 {
			expected, foreign = foreign, expected
		}
		found := false
		for _, table := range capture.Tables {
			if !strings.HasPrefix(table.ID, refs[tenant].ID+"/") {
				continue
			}
			if err := table.WalkRows(ctx, func(row []string) error {
				for _, cell := range row {
					found = found || cell == expected
					if cell == foreign {
						t.Fatal("assessment sample contained sibling flow values")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		if !found {
			t.Fatal("complete selected source totals were omitted")
		}
		raw, err := marshalReportSourceRequirements(ctx, capture)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := parseReportSourceRequirements(ctx, raw)
		if err != nil || f.server.revalidateReportFlowCapture(ctx, actors[tenant], stored) != nil {
			t.Fatal("retained assessment dropped either current source boundary", err)
		}
		capture.Close()
		foreignDefinition := definition
		foreignDefinition.FlowSources = []reportFlowSourceRef{refs[f.tenants[1-lane]]}
		if out, err := f.server.captureConfiguredReportSources(ctx, actors[tenant], foreignDefinition, time.Now().UTC()); err == nil || out != nil {
			t.Fatal("assessment source presence adopted a sibling's private query")
		}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		clients[tenant] = client
		encoded, err := json.Marshal(definition)
		if err != nil {
			t.Fatal(err)
		}
		var publicDefinition sdk.DashboardDefinition
		if err := json.Unmarshal(encoded, &publicDefinition); err != nil {
			t.Fatal(err)
		}
		create := sdk.DashboardCreateRequest{Name: "Assessment with complete flow sample", Preset: "operator", Definition: publicDefinition}
		view, err := client.CreateDashboard(t.Context(), sdk.CreateDashboardRequest{Body: &create})
		if err != nil {
			t.Fatal("served combined assessment configuration refused", err)
		}
		generate := map[string]any{"dashboard_id": view.Id, "format": "csv"}
		artifact, err := client.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &generate})
		if err != nil {
			t.Fatal("served combined assessment publication refused", err)
		}
		artifacts[tenant] = artifact.Id
		var output bytes.Buffer
		if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}, &output, 64<<20); err != nil {
			t.Fatal(err)
		}
		if err := checkAssessmentFlowSampleCSV(output.Bytes(), f.tenants[1-lane], expected); err != nil {
			t.Fatal(err)
		}
		native.proveAssessmentFlowSample(tenant, f.tenants[1-lane], definition, expected, artifact.Id)
	}
	primary, paired := f.tenants[0], f.tenants[1]
	f.in(primary, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='flow.read'`, primary, f.roles[primary])
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(primary))
	if err := f.server.revalidateReportFlowCapture(ctx, actors[primary], captures[primary]); err == nil {
		t.Fatal("stored monthly requirements bypassed withdrawn flow authority")
	}
	if written, err := clients[primary].DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifacts[primary]}, io.Discard, 64<<20); err == nil || written != 0 {
		t.Fatal("served monthly path bypassed withdrawn flow authority", written, err)
	}
	native.withdrawnSource(primary, paired)
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(paired))
	if err := f.server.revalidateReportFlowCapture(ctx, actors[paired], captures[paired]); err != nil {
		t.Fatal("source withdrawal crossed tenants", err)
	}
	if _, err := clients[paired].DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifacts[paired]}, io.Discard, 64<<20); err != nil {
		t.Fatal("sibling served sample lost authority", err)
	}
	f.in(paired, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='test.read'`, paired, f.roles[paired])
		return err
	})
	if err := f.server.revalidateReportFlowCapture(ctx, actors[paired], captures[paired]); err == nil {
		t.Fatal("stored flow requirements bypassed withdrawn assessment authority")
	}
	if written, err := clients[paired].DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifacts[paired]}, io.Discard, 64<<20); err == nil || written != 0 {
		t.Fatal("served flow path bypassed withdrawn assessment authority", written, err)
	}
	denyAssessmentSampleNative(t, native, paired, primary)
}

func checkAssessmentFlowSampleCSV(body []byte, foreign, expected string) error {
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	details, totals := 0, 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(row) != 4 || row[0] != "detail" && row[0] != "totals" {
			continue
		}
		if row[3] != expected {
			return fmt.Errorf("served flow sample changed exact complete value: %s", row[3])
		}
		if row[0] == "detail" {
			details++
		} else {
			totals++
		}
	}
	if details != 1 || totals != 1 || bytes.Contains(body, []byte(foreign)) {
		return fmt.Errorf("served assessment populations differ: details=%d/1 totals=%d/1", details, totals)
	}
	return nil
}
