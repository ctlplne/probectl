// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestQueryD102SavedPostgresRealIsolationPersistenceAndFence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "saved-filter PostgreSQL configuration unavailable")
		return
	}
	t.Cleanup(admin.Close)
	if err = admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "saved-filter PostgreSQL unavailable")
		return
	}
	if _, err = migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool := admin
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal("runtime database configuration invalid")
		}
		t.Cleanup(pool.Close)
		if err = pool.Ping(ctx); err != nil {
			t.Fatal("runtime database unavailable")
		}
	}
	tenants := store.NewTenants(pool)
	red, err := tenants.Create(ctx, fmt.Sprintf("fx1-filter-red-%d", time.Now().UnixNano()), "Red")
	if err != nil {
		t.Fatal(err)
	}
	blue, err := tenants.Create(ctx, fmt.Sprintf("fx1-filter-blue-%d", time.Now().UnixNano()), "Blue")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		engine := tenantlife.New(pool, nil, nil, nil, nil, "QA fixture has no backups", nil)
		for _, tenant := range []*store.Tenant{red, blue} {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			attestation, err := engine.Erase(cleanup, tenant.ID, tenant.Slug, "qa-fixture")
			if err != nil || !attestation.Complete {
				t.Errorf("own fixture lifecycle cleanup incomplete: %+v %v", attestation, err)
			}
			var remaining int
			if err := admin.QueryRow(cleanup, `SELECT count(*) FROM flow_query_filters WHERE tenant_id=$1::uuid`, tenant.ID).Scan(&remaining); err != nil || remaining != 0 {
				t.Errorf("saved filters survived full erasure: %d %v", remaining, err)
			}
			cancel()
		}
	})
	st := flow.NewPostgresQueryFilterStore(pool, 1<<20, audit.TenantRecord)
	input := flow.SaveQueryFilter{Name: "TLS", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{"443"}}}}}
	saved, err := st.SaveQueryFilter(ctx, red.ID, "operator@example.test", input)
	if err != nil {
		t.Fatal(err)
	}
	withoutAudit := flow.NewPostgresQueryFilterStore(pool, 1<<20, nil)
	if _, err := withoutAudit.SaveQueryFilter(ctx, red.ID, "operator", input); err == nil {
		t.Fatal("missing recorder committed a new filter")
	}
	if err := withoutAudit.DeleteQueryFilter(ctx, red.ID, "operator", saved.ID, saved.Version); err == nil {
		t.Fatal("missing recorder committed filter deletion")
	}
	page, err := st.ListQueryFilters(ctx, red.ID, "", 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != saved.ID {
		t.Fatal("missing recorder did not roll back filter mutations", err)
	}
	restarted := flow.NewPostgresQueryFilterStore(pool, 1<<20, audit.TenantRecord)
	got, err := restarted.GetQueryFilter(ctx, red.ID, saved.ID)
	if err != nil || got.Version != 1 || got.Expression.Conditions[0].Values[0] != "443" {
		t.Fatalf("durability: %+v %v", got, err)
	}
	if _, err = st.GetQueryFilter(ctx, blue.ID, saved.ID); !errors.Is(err, flow.ErrQueryFilterNotFound) {
		t.Fatalf("foreign read: %v", err)
	}
	input.ID = saved.ID
	input.Version = saved.Version
	if _, err = st.SaveQueryFilter(ctx, blue.ID, "op", input); !errors.Is(err, flow.ErrQueryFilterNotFound) {
		t.Fatalf("foreign update: %v", err)
	}
	if err = st.DeleteQueryFilter(ctx, blue.ID, "operator", saved.ID, 1); !errors.Is(err, flow.ErrQueryFilterNotFound) {
		t.Fatalf("foreign delete: %v", err)
	}
	if page, err := st.ListQueryFilters(ctx, blue.ID, "", 100); err != nil || len(page.Items) != 0 {
		t.Fatalf("foreign list: %+v %v", page, err)
	}
	// Prove the storage policy, independently of repository WHERE clauses.
	for _, tenant := range []string{red.ID, blue.ID} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var n int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_query_filters`).Scan(&n); err != nil {
				return err
			}
			want := 0
			if tenant == red.ID {
				want = 1
			}
			if n != want {
				return fmt.Errorf("predicate-free read count %d, want %d", n, want)
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
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM flow_query_filters`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing tenant policy: %d %v", count, err)
	}
	_ = tx.Rollback(ctx)
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(blue.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_query_filters SELECT * FROM flow_query_filters WHERE tenant_id=$1::uuid`, red.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	} // SELECT cannot see a foreign row to copy.
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(blue.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_query_filters(tenant_id,id,name,expression,version,updated_by,created_at,updated_at) VALUES($1::uuid,$2::uuid,'foreign','{}',1,'op',now(),now())`, red.ID, saved.ID)
		return err
	})
	if err == nil {
		t.Fatal("RLS WITH CHECK accepted foreign insert")
	}
	err = tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `SELECT * FROM flow_query_filters`)
		return err
	})
	if err == nil {
		t.Fatal("provider gained implicit filter access")
	}
	// Dependency resolution and optimistic versions remain atomic in PostgreSQL.
	dependent, err := st.SaveQueryFilter(ctx, red.ID, "op", flow.SaveQueryFilter{Name: "dependent", Expression: flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: saved.ID}}}})
	if err != nil {
		t.Fatal(err)
	}
	input.Expression = flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: dependent.ID}}}
	if _, err = st.SaveQueryFilter(ctx, red.ID, "op", input); err == nil {
		t.Fatal("cycle accepted")
	}
	got, err = st.GetQueryFilter(ctx, red.ID, saved.ID)
	if err != nil || got.Version != 1 || got.Name != "TLS" {
		t.Fatalf("cycle partly wrote: %+v %v", got, err)
	}
	input.Expression = got.Expression
	updated, err := st.SaveQueryFilter(ctx, red.ID, "op", input)
	if err != nil || updated.Version != 2 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if _, err = st.SaveQueryFilter(ctx, red.ID, "op", input); !errors.Is(err, flow.ErrQueryFilterConflict) {
		t.Fatalf("stale update: %v", err)
	}
	tiny := flow.NewPostgresQueryFilterStore(pool, 1, audit.TenantRecord)
	if _, err = tiny.SaveQueryFilter(ctx, blue.ID, "op", flow.SaveQueryFilter{Name: "too much", Expression: got.Expression}); !errors.Is(err, flow.ErrQueryFilterStorageBudget) {
		t.Fatalf("storage budget: %v", err)
	}
	// Domain audit and configuration mutation must commit or roll back together.
	// This exact-name, test-only trigger faults only the QA actor; no deployed
	// tenant or other test's audit write can match it.
	const faultActor = "probectl-qa-beta-filter-audit-refusal"
	if _, err = admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_filter_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor = 'probectl-qa-beta-filter-audit-refusal' THEN RAISE EXCEPTION 'QA audit append refused'; END IF; RETURN NEW; END $$;
DROP TRIGGER IF EXISTS probectl_qa_beta_filter_audit_fault ON audit_events;
CREATE TRIGGER probectl_qa_beta_filter_audit_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_filter_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_filter_audit_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_filter_audit_fault()`)
		if err != nil {
			t.Errorf("own audit fault cleanup: %v", err)
		}
	})
	failed := flow.SaveQueryFilter{ID: saved.ID, Version: updated.Version, Name: "must roll back", Expression: got.Expression}
	if _, err = st.SaveQueryFilter(ctx, red.ID, faultActor, failed); err == nil {
		t.Fatal("audit refusal accepted an update")
	}
	still, err := st.GetQueryFilter(ctx, red.ID, saved.ID)
	if err != nil || still.Version != updated.Version || still.Name == failed.Name {
		t.Fatalf("unaudited update persisted: %+v %v", still, err)
	}
	if err = st.DeleteQueryFilter(ctx, red.ID, faultActor, saved.ID, updated.Version); err == nil {
		t.Fatal("audit refusal accepted a delete")
	}
	if _, err = st.GetQueryFilter(ctx, red.ID, saved.ID); err != nil {
		t.Fatalf("unaudited delete persisted: %v", err)
	}
	if _, err = admin.Exec(ctx, `DROP TRIGGER probectl_qa_beta_filter_audit_fault ON audit_events; DROP FUNCTION public.probectl_qa_beta_filter_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	if err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('flow.filter.create','flow.filter.update')`).Scan(&count); err != nil {
			return err
		}
		if count != 3 {
			return fmt.Errorf("domain audit count %d, want3", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The new configuration table participates in ordinary portability and
	// subject erasure, without finding the same identity in a sibling tenant.
	const subject = "198.51.100.77"
	subjectInput := flow.SaveQueryFilter{Name: "subject-bearing", Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryEqual, Values: []string{subject}}}}}
	subjectRed, err := st.SaveQueryFilter(ctx, red.ID, "op", subjectInput)
	if err != nil {
		t.Fatal(err)
	}
	subjectBlue, err := st.SaveQueryFilter(ctx, blue.ID, "op", subjectInput)
	if err != nil {
		t.Fatal(err)
	}
	engine := tenantlife.New(pool, nil, nil, nil, nil, "QA fixture has no backups", nil)
	var full bytes.Buffer
	manifest, err := engine.Export(ctx, red.ID, &full)
	if err != nil {
		t.Fatal(err)
	}
	fullText := queryFilterArchiveText(t, full.Bytes())
	if manifest.Tables["flow_query_filters"] != 3 || !strings.Contains(fullText, saved.ID) || !strings.Contains(fullText, subjectRed.ID) || strings.Contains(fullText, subjectBlue.ID) {
		t.Fatal("full portability omitted own filters or crossed tenant scope")
	}
	var partial bytes.Buffer
	if _, err := engine.ExportSubject(ctx, red.ID, subject, &partial, false); err != nil {
		t.Fatal(err)
	}
	subjectText := queryFilterArchiveText(t, partial.Bytes())
	if !strings.Contains(subjectText, subjectRed.ID) || strings.Contains(subjectText, subjectBlue.ID) {
		t.Fatal("subject portability omitted own filter or crossed tenant scope")
	}
	report, err := engine.EraseSubject(ctx, red.ID, subject, "qa-privacy", "saved-filter lifecycle proof")
	if err != nil || !report.Complete {
		t.Fatalf("subject erasure incomplete: %+v %v", report, err)
	}
	if _, err = st.GetQueryFilter(ctx, red.ID, subjectRed.ID); !errors.Is(err, flow.ErrQueryFilterNotFound) {
		t.Fatalf("subject definition survived erasure: %v", err)
	}
	if _, err = st.GetQueryFilter(ctx, blue.ID, subjectBlue.ID); err != nil {
		t.Fatalf("subject erasure touched sibling: %v", err)
	}
	var definition tags.Definition
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.ID)), pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			var createErr error
			definition, createErr = (store.TagDefinitions{}).Create(ctx, scope, "customer")
			return createErr
		}); err != nil {
		t.Fatal(err)
	}
	vocabulary, err := flow.NewTagQueryVocabulary(red.ID, []tags.Definition{definition})
	if err != nil {
		t.Fatal(err)
	}
	tagCtx, err := flow.WithQueryVocabulary(ctx, red.ID, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	tagInput := flow.SaveQueryFilter{Name: "Customer blue", Expression: flow.QueryFilterGroup{
		Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"blue"}}}}}
	tagSaved, err := st.SaveQueryFilter(tagCtx, red.ID, "operator@example.test", tagInput)
	if err != nil {
		t.Fatalf("save tenant tag filter: %v", err)
	}
	tagRead, err := restarted.GetQueryFilter(tagCtx, red.ID, tagSaved.ID)
	if err != nil || tagRead.Expression.Conditions[0].Field != "tag.customer" {
		t.Fatalf("tenant tag filter did not persist under RLS: %+v %v", tagRead, err)
	}
	if _, err := restarted.GetQueryFilter(ctx, red.ID, tagSaved.ID); err == nil {
		t.Fatal("stored tag filter read without a tenant vocabulary")
	}
	if _, err := restarted.GetQueryFilter(tagCtx, blue.ID, tagSaved.ID); err == nil {
		t.Fatal("foreign tenant read another tenant's tag filter")
	}
	if _, err = tenants.UpdateStatus(ctx, red.ID, "offboarding"); err != nil {
		t.Fatal(err)
	}
	input.ID = ""
	input.Version = 0
	if _, err = st.SaveQueryFilter(ctx, red.ID, "op", input); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("offboarding write fence: %v", err)
	}
	if err = st.DeleteQueryFilter(ctx, red.ID, "operator", saved.ID, 2); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("offboarding delete fence: %v", err)
	}
}

func queryFilterArchiveText(t *testing.T, body []byte) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	archive := tar.NewReader(gz)
	var text strings.Builder
	for {
		_, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(archive, 8<<20))
		if err != nil {
			t.Fatal(err)
		}
		text.Write(data)
	}
	return text.String()
}
