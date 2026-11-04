// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual PG current users/grants, saved sources, contexts and tag snapshots;
// source rows are in-process. This is not a sender or four-store release proof.
func TestReportLiveFlowCaptureUsesCurrentOwnedSourcesAndOneBatch(t *testing.T) {
	t.Run("success", testReportLiveFlowCapture)
}

func testReportLiveFlowCapture(t *testing.T) {
	f := newTagImportSubjectFixture(t)
	views := flow.NewPostgresQueryViewStore(f.db.Pool(), 0, audit.TenantRecord)
	f.srv.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.db.Pool(), 0, audit.TenantRecord))
	rows := flowstore.NewMemory()
	f.srv.WithFlowStore(rows)
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency, policy.QueriesPerMin = 1, 10000
	gate := fairness.NewGate(policy, nil)
	f.srv.WithFairness(gate)
	actors := map[string]*auth.Principal{}
	roles := map[string]string{}
	saved := map[string]flow.SavedQueryView{}
	at := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), fn); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range []string{f.a, f.b} {
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "report@"+tenant+".invalid", "Report source owner")
			if err != nil {
				return err
			}
			role, err := (store.Roles{}).Create(ctx, sc, "report-source-owner", "Report source owner", "Current source component")
			if err != nil {
				return err
			}
			roles[tenant] = role.ID
			for _, permission := range []string{permAIQuery, permFlowRead, permTagsRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
				return err
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", user.ID)
			if err != nil {
				return err
			}
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: user.ID, Email: user.Email}, grants)
			_, err = sc.Q.Exec(ctx, `INSERT INTO tenant_tag_assignments(tenant_id,context_id,id,tag_id,target_kind,exporter_agent_id,exporter_source_kind,exporter_source_ref,value,source)
			 VALUES($1,$2,$3,$4,'exporter',$5,'flow_exporter','192.0.2.10',$6,'manual')`, tenant, f.contextID, uuid(t), f.tagID, f.agents[tenant], "OWN-"+tenant)
			return err
		})
		if err := rows.Insert(t.Context(), []flowstore.Row{
			{TenantID: tenant, AgentID: f.agents[tenant], Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, BytesScaled: uint64(100 + lane*800)},
			{TenantID: tenant, AgentID: f.agents[tenant], Exporter: "192.0.2.10", Protocol: "ipfix", TS: at.Add(-2 * time.Minute), BytesScaled: uint64(70 + lane*700)},
		}); err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		ctx, err := f.srv.withFlowViewVocabulary(ctx, actors[tenant])
		if err != nil {
			t.Fatal(err)
		}
		item, err := views.SaveQueryView(ctx, tenant, actors[tenant].UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{
			Name: "Own retained flow", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Comparison: &flow.QueryViewComparison{Mode: "preceding"},
			TagIDs: map[string]string{"tag.role": f.tagID}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"tag.role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		saved[tenant] = item
	}
	var frozen *reportFlowCapture
	for lane, tenant := range []string{f.a, f.b} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		item := saved[tenant]
		capture, err := f.srv.captureReportFlowSources(ctx, actors[tenant], []reportFlowSourceRef{{ID: item.ID, Version: item.Version}})
		if err != nil {
			t.Fatal("live saved-source capture failed", err)
		}
		t.Cleanup(capture.Close)
		if capture.TenantID != tenant || !capture.ContextsCaptured || len(capture.Contexts) != 1 || capture.Contexts[0].ContextID != f.contextID || capture.Contexts[0].Resource[auth.ResourceTenantKey] != tenant {
			t.Fatal("live capture lost its actual authorized tenant/context requirements")
		}
		if len(capture.Inputs) != 2 || capture.Inputs[0].TagRevision == "" || capture.Inputs[0].TagAsOf.IsZero() || capture.Inputs[0].TagRevision != capture.Inputs[1].TagRevision || !capture.Inputs[0].TagAsOf.Equal(capture.Inputs[1].TagAsOf) || !slices.Contains(capture.Permissions, permTagsRead) {
			t.Fatal("source batch lost exact references or its single actual metadata clock")
		}
		for _, expected := range []struct{ period, value string }{{"current", fmt.Sprint(100 + lane*800)}, {"previous", fmt.Sprint(70 + lane*700)}} {
			assertCapturedReportDetail(ctx, t, capture, expected.period, "OWN-"+tenant, expected.value, f.tagID)
		}
		if release, err := gate.BeginQuery(ctx, tenant); !errors.Is(err, fairness.ErrQueryConcurrency) {
			if release != nil {
				release()
			}
			t.Fatal("captured source released fairness before staging/publication", err)
		}
		if tenant == f.a {
			frozen = capture
		}
		capture.Close()
		capture.Close()
		if gate.SnapshotTenant(ctx, tenant).Queries.InFlight != 0 {
			t.Fatal("capture Close leaked its single admission")
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.a))
	item := saved[f.a]
	refs := []reportFlowSourceRef{{ID: item.ID, Version: item.Version}}
	for name, bad := range map[string][]reportFlowSourceRef{
		"foreign":   {{ID: saved[f.b].ID, Version: saved[f.b].Version}},
		"stale":     {{ID: item.ID, Version: "2"}},
		"duplicate": {refs[0], refs[0]},
		"inexact":   {{ID: item.ID, Version: "01"}},
	} {
		t.Run(name, func(t *testing.T) {
			if value, err := f.srv.captureReportFlowSources(ctx, actors[f.a], bad); err == nil || value != nil || gate.SnapshotTenant(ctx, f.a).Queries.InFlight != 0 {
				t.Fatal("failed source reference exposed partial data or leaked admission", err)
			}
		})
	}
	limited := narrowPrincipalToScopes(auth.ClonePrincipal(actors[f.a]), []string{permAIQuery})
	if value, err := f.srv.captureReportFlowSources(ctx, limited, refs); err == nil || value != nil {
		t.Fatal("source capture widened the actual credential ceiling")
	}
	// A metadata edit re-tags history in the next capture, never the old one.
	mutate(f.a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tenant_tag_assignments SET value='CHANGED' WHERE tenant_id=$1 AND context_id=$2 AND tag_id=$3`, f.a, f.contextID, f.tagID)
		return err
	})
	changed, err := f.srv.captureReportFlowSources(ctx, actors[f.a], refs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(changed.Close)
	assertCapturedReportDetail(ctx, t, changed, "current", "CHANGED", "100", f.tagID)
	assertCapturedReportDetail(ctx, t, frozen, "current", "OWN-"+f.a, "100", f.tagID)
	if changed.Inputs[0].TagRevision == frozen.Inputs[0].TagRevision {
		t.Fatal("actual metadata revision did not advance after source edit")
	}
	changed.Close()
	budget := flowstore.DefaultExplorerBudget()
	budget.ReadRows = 2
	if err := flowstore.AttachExplorerBudget(rows, budget); err != nil {
		t.Fatal(err)
	}
	if value, err := f.srv.captureReportFlowSources(ctx, actors[f.a], refs); err == nil || value != nil {
		t.Fatal("report comparison bypassed cumulative source read budget")
	}
	if err := flowstore.AttachExplorerBudget(rows, flowstore.DefaultExplorerBudget()); err != nil {
		t.Fatal(err)
	}
	item = reportFrozenSourceReaderProof(ctx, t, f, actors[f.a], roles[f.a], views, item, frozen)
	refs = []reportFlowSourceRef{{ID: item.ID, Version: item.Version}}
	mutate(f.a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, f.a, roles[f.a], permFlowRead)
		return err
	})
	if value, err := f.srv.captureReportFlowSources(ctx, actors[f.a], refs); err == nil || value != nil || gate.SnapshotTenant(ctx, f.a).Queries.InFlight != 0 {
		t.Fatal("stale caller grants survived current role revocation or leaked admission")
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, actors[f.a], frozen); err == nil {
		t.Fatal("frozen source reader retained revoked current source grants")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if value, err := f.srv.captureReportFlowSources(canceled, actors[f.a], refs); err == nil || value != nil || gate.SnapshotTenant(ctx, f.a).Queries.InFlight != 0 {
		t.Fatal("canceled source capture returned data or leaked admission")
	}
}

func assertCapturedReportDetail(ctx context.Context, t *testing.T, capture *reportFlowCapture, period, tag, counter, tagID string) {
	t.Helper()
	found := false
	for _, table := range capture.Tables {
		if !strings.HasSuffix(table.ID, "/"+period+"/detail") {
			continue
		}
		if table.TenantID != capture.TenantID || table.TagRevision == "" || table.TagAsOf.IsZero() || table.FieldIDs["tag.role"] != tagID {
			t.Fatal("live source projection lost its exact field identity or metadata clock")
		}
		if err := table.WalkRows(ctx, func(row []string) error {
			values := map[string]string{}
			for i, column := range table.Columns {
				values[column.Name] = row[i]
			}
			if values["tag.role"] == tag && values["bytes:total"] == counter {
				found = true
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		encoded, _ := json.Marshal(capture.Inputs)
		t.Fatal("live report source omitted exact own detail", period, tag, counter, string(encoded))
	}
}
