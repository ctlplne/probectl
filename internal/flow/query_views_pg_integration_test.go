// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestQueryViewsPostgresRealScopePersistenceAuditAndLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "view PostgreSQL configuration unavailable")
		return
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "view PostgreSQL unavailable")
		return
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatal(err)
	}
	pool := admin
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal("runtime database configuration invalid")
		}
		t.Cleanup(pool.Close)
	}
	tenants := store.NewTenants(pool)
	red, err := tenants.Create(ctx, fmt.Sprintf("fx1-view-red-%d", time.Now().UnixNano()), "Red")
	if err != nil {
		t.Fatal(err)
	}
	blue, err := tenants.Create(ctx, fmt.Sprintf("fx1-view-blue-%d", time.Now().UnixNano()), "Blue")
	if err != nil {
		t.Fatal(err)
	}
	engine := tenantlife.New(pool, nil, nil, nil, nil, "QA fixture has no backups", nil)
	t.Cleanup(func() {
		for _, tenant := range []*store.Tenant{red, blue} {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			attestation, err := engine.Erase(cleanup, tenant.ID, tenant.Slug, "qa-fixture")
			if err != nil || !attestation.Complete {
				t.Errorf("own fixture erase incomplete: %+v %v", attestation, err)
			}
		}
	})
	st := flow.NewPostgresQueryViewStore(pool, 64<<20, audit.TenantRecord)
	definition := flow.QueryViewDefinition{Name: "Complete native query", Description: "own config", Labels: []string{"core", "edge"}, Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 401 * 24 * 3600}, Comparison: &flow.QueryViewComparison{Mode: "preceding"}, Plan: flow.QueryPlan{View: "matrix", GroupBy: []string{"src_addr", "src_port", "protocol", "exporter", "in_if", "vlan", "dscp", "src_asn"}, MatrixWith: []string{"dst_addr", "dst_port", "transport", "next_hop", "out_if", "net_type", "tcp_flags", "dst_country"}, RowLimit: 350, PageSize: 100, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bps", Calculation: "p99", Role: "secondary"}}, Filter: &flow.QueryFilterGroup{Match: "any", Groups: []flow.QueryFilterGroup{{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryBetween, Values: []string{"1", "65535"}}}}, {Mode: "exclude", Conditions: []flow.QueryPredicate{{Field: "raw_bytes", Op: flow.QueryGreater, Values: []string{"9007199254740993"}}}}}}}}
	definition.Display = &flow.QueryViewDisplay{TimeStyle: "horizon", PercentBasis: "visible", HorizonScale: "lane", TotalOverlay: true, LogMetrics: []string{"bps:p99"}, SyncAxes: true, OneChartPerSeries: true, ChartsPerRow: 4, ChartHeight: "tall"}
	saved, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	withoutAudit := flow.NewPostgresQueryViewStore(pool, 64<<20, nil)
	if _, err := withoutAudit.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{Definition: definition}); err == nil {
		t.Fatal("missing recorder committed view creation")
	}
	unauditedDefinition := definition
	unauditedDefinition.Name = "Unaudited rename"
	if _, err := withoutAudit.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{ID: saved.ID, Version: saved.Version, Definition: unauditedDefinition}); err == nil {
		t.Fatal("missing recorder committed view update")
	}
	unauditedFavorite := true
	if err := withoutAudit.SetQueryViewPreference(ctx, red.ID, "alice", saved.ID, &unauditedFavorite, false); err == nil {
		t.Fatal("missing recorder committed view preference")
	}
	if err := withoutAudit.DeleteQueryView(ctx, red.ID, "alice", saved.ID, saved.Version); err == nil {
		t.Fatal("missing recorder committed view deletion")
	}
	restarted := flow.NewPostgresQueryViewStore(pool, 64<<20, audit.TenantRecord)
	got, err := restarted.GetQueryView(ctx, red.ID, "alice", saved.ID)
	if err != nil || got.Version != "1" || got.Definition.Name != definition.Name || got.Favorite || len(got.Definition.Plan.GroupBy) != 8 || len(got.Definition.Plan.MatrixWith) != 8 || got.Definition.Plan.Filter.Groups[1].Conditions[0].Values[0] != "9007199254740993" {
		t.Fatalf("full query lost on restart: %+v %v", got, err)
	}
	if got.Definition.Display == nil || got.Definition.Display.TimeStyle != "horizon" || got.Definition.Display.PercentBasis != "visible" || got.Definition.Display.HorizonScale != "lane" || !got.Definition.Display.TotalOverlay || !got.Definition.Display.SyncAxes || !got.Definition.Display.OneChartPerSeries || got.Definition.Display.ChartsPerRow != 4 || got.Definition.Display.ChartHeight != "tall" || len(got.Definition.Display.LogMetrics) != 1 {
		t.Fatal("display lost across replica")
	}
	for _, scope := range [][2]string{{red.ID, "bob"}, {blue.ID, "alice"}} {
		if _, err := st.GetQueryView(ctx, scope[0], scope[1], saved.ID); !errors.Is(err, flow.ErrQueryViewNotFound) {
			t.Fatal("scope read escaped", err)
		}
		if _, err := st.SaveQueryView(ctx, scope[0], scope[1], flow.SaveQueryView{ID: saved.ID, Version: saved.Version, Definition: saved.Definition}); !errors.Is(err, flow.ErrQueryViewNotFound) {
			t.Fatal("scope update escaped", err)
		}
		if err := st.DeleteQueryView(ctx, scope[0], scope[1], saved.ID, saved.Version); !errors.Is(err, flow.ErrQueryViewNotFound) {
			t.Fatal("scope delete escaped", err)
		}
	}
	for _, tenant := range []string{red.ID, blue.ID} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var n int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_query_views`).Scan(&n); err != nil {
				return err
			}
			want := 0
			if tenant == red.ID {
				want = 1
			}
			if n != want {
				return fmt.Errorf("predicate-free view count%d expected%d", n, want)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM flow_query_views`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("missing tenant bypassed RLS %d %v", n, err)
	}
	_ = tx.Rollback(ctx)
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `SELECT * FROM flow_query_views`)
		return err
	}); err == nil {
		t.Fatal("provider read views implicitly")
	}
	// WITH CHECK also denies direct writes, independently of store predicates.
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(blue.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_query_view_preferences(tenant_id,owner_id,view_id) VALUES($1::uuid,'alice',$2::uuid)`, red.ID, saved.ID)
		return err
	}); err == nil {
		t.Fatal("preference RLS accepted foreign tenant")
	}
	encoded, err := json.Marshal(saved.Definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(blue.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at) VALUES($1::uuid,gen_random_uuid(),'alice',$2,'private',$3::jsonb,1,now(),now())`, red.ID, saved.Definition.Name, string(encoded))
		return err
	}); err == nil {
		t.Fatal("view RLS WITH CHECK accepted foreign insert")
	}
	filters := flow.NewPostgresQueryFilterStore(pool, 0, audit.TenantRecord)
	filter, err := filters.SaveQueryFilter(ctx, red.ID, "alice", flow.SaveQueryFilter{Name: "view dependency", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	dependent := definition
	dependent.Plan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}
	if _, err := st.SaveQueryView(ctx, blue.ID, "alice", flow.SaveQueryView{Definition: dependent}); !errors.Is(err, flow.ErrQueryViewNotFound) {
		t.Fatal("view reference crossed tenant", err)
	}
	shared := saved.Definition
	shared.Visibility = "tenant"
	saved, err = st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{ID: saved.ID, Version: saved.Version, Definition: shared})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetQueryView(ctx, red.ID, "bob", saved.ID); err != nil {
		t.Fatal("shared view unavailable", err)
	}
	t.Run("current_visibility", func(t *testing.T) {
		queryViewMetadataAccessProof(ctx, t, pool, st, red.ID, blue.ID, saved)
	})
	if err := st.DeleteQueryView(ctx, red.ID, "bob", saved.ID, saved.Version); !errors.Is(err, flow.ErrQueryViewNotFound) {
		t.Fatal("shared view grants ownership", err)
	}
	favorite := true
	if err := st.SetQueryViewPreference(ctx, red.ID, "bob", saved.ID, &favorite, true); err != nil {
		t.Fatal(err)
	}
	own, err := st.GetQueryView(ctx, red.ID, "alice", saved.ID)
	if err != nil || own.Favorite || own.LastOpenedAt != nil {
		t.Fatal("private preference leaked", err)
	}
	page, err := st.ListQueryViews(ctx, red.ID, "bob", flow.QueryViewList{Tab: "favorites", Search: "complete", Label: "edge", Limit: 1})
	if err != nil || len(page.Items) != 1 || !page.Items[0].Favorite {
		t.Fatal("filtered private preference list", err)
	}
	// Stable keyset pagination with equal names and timestamps, every sort/tab.
	for i := 0; i < 3; i++ {
		item := shared
		item.Name = fmt.Sprintf("Query%d", i)
		v, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{Definition: item})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetQueryViewPreference(ctx, red.ID, "bob", v.ID, &favorite, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, tab := range []string{"all", "favorites", "recents"} {
		for _, sort := range []string{"name", "created_at", "updated_at"} {
			seen := map[string]bool{}
			after := ""
			for {
				page, err := st.ListQueryViews(ctx, red.ID, "bob", flow.QueryViewList{Tab: tab, Sort: sort, Limit: 1, After: after})
				if err != nil {
					t.Fatal(err)
				}
				for _, item := range page.Items {
					if seen[item.ID] {
						t.Fatal("duplicate page")
					}
					seen[item.ID] = true
				}
				if page.Next == "" {
					break
				}
				after = page.Next
			}
			if len(seen) != 4 {
				t.Fatalf("list %s/%s lost results%d", tab, sort, len(seen))
			}
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE flow_query_views SET version=9007199254740993 WHERE tenant_id=$1::uuid AND id=$2::uuid`, red.ID, saved.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{ID: saved.ID, Version: "9007199254740993", Definition: saved.Definition})
	if err != nil || updated.Version != "9007199254740994" {
		t.Fatal("revision rounded", err)
	}
	if _, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{ID: saved.ID, Version: saved.Version, Definition: saved.Definition}); !errors.Is(err, flow.ErrQueryViewConflict) {
		t.Fatal("stale revision committed", err)
	}
	tiny := flow.NewPostgresQueryViewStore(pool, 1, audit.TenantRecord)
	if _, err := tiny.SaveQueryView(ctx, blue.ID, "alice", flow.SaveQueryView{Definition: definition}); !errors.Is(err, flow.ErrQueryViewBudget) {
		t.Fatal("view quota bypassed", err)
	}
	const faultOwner = "probectl-qa-beta-view-audit-refusal"
	fault, err := st.SaveQueryView(ctx, red.ID, faultOwner, flow.SaveQueryView{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_view_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor='probectl-qa-beta-view-audit-refusal' AND NEW.action LIKE 'flow.view.%' THEN RAISE EXCEPTION 'QA view audit refused'; END IF; RETURN NEW; END $$; DROP TRIGGER IF EXISTS probectl_qa_beta_view_audit_fault ON audit_events; CREATE TRIGGER probectl_qa_beta_view_audit_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_view_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		if _, err := admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_view_audit_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_view_audit_fault()`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(dropFault)
	changed := fault.Definition
	changed.Name = "MUST ROLL BACK"
	if _, err := st.SaveQueryView(ctx, red.ID, faultOwner, flow.SaveQueryView{ID: fault.ID, Version: fault.Version, Definition: changed}); err == nil {
		t.Fatal("audit refusal accepted update")
	}
	if err := st.SetQueryViewPreference(ctx, red.ID, faultOwner, fault.ID, &favorite, true); err == nil {
		t.Fatal("audit refusal accepted preference")
	}
	if err := st.DeleteQueryView(ctx, red.ID, faultOwner, fault.ID, fault.Version); err == nil {
		t.Fatal("audit refusal accepted delete")
	}
	faultAfter, err := st.GetQueryView(ctx, red.ID, faultOwner, fault.ID)
	if err != nil || faultAfter.Version != fault.Version || faultAfter.Definition.Name != fault.Definition.Name || faultAfter.Favorite || faultAfter.LastOpenedAt != nil {
		t.Fatal("unaudited state persisted", err)
	}
	dropFault()
	const subject = "198.51.100.77"
	subj := definition
	subj.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryEqual, Values: []string{subject}}}}
	subjRed, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{Definition: subj})
	if err != nil {
		t.Fatal(err)
	}
	subjBlue, err := st.SaveQueryView(ctx, blue.ID, "alice", flow.SaveQueryView{Definition: subj})
	if err != nil {
		t.Fatal(err)
	}
	var full, partial bytes.Buffer
	manifest, err := engine.Export(ctx, red.ID, &full)
	if err != nil {
		t.Fatal(err)
	}
	text := queryFilterArchiveText(t, full.Bytes())
	if manifest.Tables["flow_query_views"] != 6 || !strings.Contains(text, subjRed.ID) || strings.Contains(text, subjBlue.ID) {
		t.Fatal("ordinary view portability crossed/omitted scope")
	}
	if !strings.Contains(text, "total_overlay") || !strings.Contains(text, "one_chart_per_series") {
		t.Fatal("ordinary export omitted saved display")
	}
	if _, err := engine.ExportSubject(ctx, red.ID, subject, &partial, false); err != nil {
		t.Fatal(err)
	}
	text = queryFilterArchiveText(t, partial.Bytes())
	if !strings.Contains(text, subjRed.ID) || strings.Contains(text, subjBlue.ID) {
		t.Fatal("subject view portability crossed/omitted scope")
	}
	var redacted bytes.Buffer
	if _, err := engine.ExportRedacted(ctx, red.ID, &redacted, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(queryFilterArchiveText(t, redacted.Bytes()), subject) {
		t.Fatal("redacted portability leaked saved-query predicate address")
	}
	report, err := engine.EraseSubject(ctx, red.ID, subject, "qa-privacy", "query view proof")
	if err != nil || !report.Complete {
		t.Fatalf("subject view deletion incomplete %+v %v", report, err)
	}
	if _, err := st.GetQueryView(ctx, red.ID, "alice", subjRed.ID); !errors.Is(err, flow.ErrQueryViewNotFound) {
		t.Fatal("subject query survived", err)
	}
	if _, err := st.GetQueryView(ctx, blue.ID, "alice", subjBlue.ID); err != nil {
		t.Fatal("subject deletion touched sibling", err)
	}
	if _, err := tenants.UpdateStatus(ctx, red.ID, "offboarding"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveQueryView(ctx, red.ID, "alice", flow.SaveQueryView{Definition: definition}); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatal("offboarding accepted view", err)
	}
	if err := st.SetQueryViewPreference(ctx, red.ID, "bob", saved.ID, &favorite, true); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatal("offboarding accepted preference", err)
	}
}
