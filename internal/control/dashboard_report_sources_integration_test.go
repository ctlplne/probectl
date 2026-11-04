// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// Actual PG current users/grants, saved sources, contexts and tag snapshots;
// source rows are in-process. This is not a sender or four-store release proof.
func TestReportLiveFlowCaptureUsesCurrentOwnedSourcesAndOneBatch(t *testing.T) {
	t.Run("success", func(t *testing.T) { testReportLiveFlowCapture(t, false) })
}

func TestReportRealFlowCaptureStagesCurrentOwnedSources(t *testing.T) {
	t.Run("success", func(t *testing.T) { testReportLiveFlowCapture(t, true) })
}

func testReportLiveFlowCapture(t *testing.T, realSource bool) {
	f := newTagImportSubjectFixture(t)
	views := flow.NewPostgresQueryViewStore(f.db.Pool(), 0, audit.TenantRecord)
	f.srv.WithFlowQueryViews(views).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.db.Pool(), 0, audit.TenantRecord))
	var rows flowstore.Store = flowstore.NewMemory()
	if realSource {
		endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
		if endpoint == "" {
			testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for real report source proof")
		}
		ch, err := flowstore.NewClickHouse(endpoint, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ch.Close() })
		readerUser, reader := chtest.ProvisionReader(t, endpoint, "fx3_report_reader")
		ch.WithTenantScoping(true).WithReader(reader)
		if err := ch.EnsureReaderRowPolicy(t.Context(), readerUser); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, tenant := range []string{f.a, f.b} {
				if _, err := ch.DeleteTenant(ctx, tenant); err != nil {
					t.Error("owned report source cleanup failed", err)
				}
			}
		})
		rows = ch
	}
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
		current := flowstore.Row{TenantID: tenant, AgentID: f.agents[tenant], Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, StartTS: at.Add(-time.Second),
			SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 12345, DstPort: 443, Transport: "tcp", Sampling: 1, Bytes: uint64(100 + lane*800), BytesScaled: uint64(100 + lane*800), Packets: 1, PacketsScaled: 1}
		if realSource {
			// Untrusted row claims cannot select the foreign agent's context.
			current.AgentID = f.agents[[]string{f.a, f.b}[1-lane]]
		}
		previous := current
		previous.TS, previous.StartTS = at.Add(-2*time.Minute), at.Add(-2*time.Minute-time.Second)
		previous.Bytes, previous.BytesScaled = uint64(70+lane*700), uint64(70+lane*700)
		if err := rows.Insert(t.Context(), []flowstore.Row{current, previous}); err != nil {
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
		if realSource {
			assertCapturedReportCSV(ctx, t, capture)
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

// Independent CSV parsing checks every frozen source section, header, record,
// tenant and metadata identity after the real source capture has completed.
func assertCapturedReportCSV(ctx context.Context, t *testing.T, capture *reportFlowCapture) {
	t.Helper()
	doc := reporting.Document{
		Title: "Real source report", TenantName: "Owned tenant", TenantScope: capture.TenantID,
		AbsoluteFrom: capture.Inputs[0].From, AbsoluteTo: capture.Inputs[0].To,
		GeneratedAt: time.Now().UTC(), GeneratedBy: "CI source proof",
		Provenance:     []string{"real PostgreSQL metadata and ClickHouse query"},
		RedactionState: "authorized metadata only", CoverageLimitations: []string{"directly seeded rows; release senders and bus remain separate proof"},
		Tables: capture.Tables,
	}
	var rendered reporting.CSVReceipt
	stage, receipt, err := reporting.StageBody(ctx, capture.TenantID, reporting.DefaultBodyStageLimits(), func(target io.Writer) error {
		var err error
		rendered, err = reporting.WriteCSV(ctx, target, doc, reporting.DefaultCSVLimits())
		return err
	})
	if err != nil {
		t.Fatal("real source CSV staging failed", err)
	}
	defer func() { _ = stage.Close() }()
	body, err := stage.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	parser := csv.NewReader(body)
	parser.FieldsPerRecord = -1
	records, err := parser.ReadAll()
	if err != nil {
		t.Fatal("real source CSV could not be parsed", err)
	}
	cursor := 0
	for cursor < len(records) && (len(records[cursor]) != 2 || records[cursor][0] != "table_id") {
		cursor++
	}
	var count int64
	for _, table := range capture.Tables {
		if cursor >= len(records) || !slices.Equal(records[cursor], []string{"table_id", table.ID}) {
			t.Fatal("staged real source omitted or reordered a complete section")
		}
		columns := make([]string, len(table.Columns))
		for i, column := range table.Columns {
			columns[i] = column.Name
		}
		metadata := map[string]string{}
		for cursor < len(records) && !slices.Equal(records[cursor], columns) {
			if len(records[cursor]) != 2 {
				t.Fatal("staged real source has malformed section metadata")
			}
			metadata[records[cursor][0]] = records[cursor][1]
			cursor++
		}
		asOf := ""
		if table.TagRevision != "" {
			asOf = table.TagAsOf.UTC().Format(time.RFC3339Nano)
		}
		if cursor >= len(records) || metadata["table_tenant_scope"] != capture.TenantID || metadata["table_tag_revision"] != table.TagRevision || metadata["table_tag_as_of"] != asOf || metadata["table_rows"] != fmt.Sprint(table.ExpectedRows) || metadata["table_absolute_from"] != table.AbsoluteFrom.UTC().Format(time.RFC3339Nano) || metadata["table_absolute_to"] != table.AbsoluteTo.UTC().Format(time.RFC3339Nano) {
			t.Fatal("staged real source lost its exact header, tenant or captured clock")
		}
		for field, id := range table.FieldIDs {
			if metadata["table_field_id:"+field] != id {
				t.Fatal("staged real source lost its immutable field identity")
			}
		}
		cursor++
		if err := table.WalkRows(ctx, func(row []string) error {
			if cursor >= len(records) || !slices.Equal(records[cursor], row) {
				t.Fatal("staged real source lost an exact captured record")
			}
			cursor++
			count++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if cursor != len(records) || count != rendered.TableRows || receipt.Bytes != rendered.Bytes || receipt.SHA256 == "" {
		t.Fatal("staged real source has missing or duplicated records or integrity receipt")
	}
	t.Logf("real PG/ClickHouse source CSV: tenant_sections=%d complete_records=%d bytes=%d", len(capture.Tables), count, receipt.Bytes)
}
