// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

func TestSubjectErasureTableDiscoveryErrorFailsClosed(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	subject := "discovery-error-" + stamp + "@example.com"
	victim := mkTenant(t, pool, "it-subject-discovery-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-discovery-b-"+stamp)

	seed := func(tenantID string) {
		t.Helper()
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		if err := tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx,
				`INSERT INTO users (tenant_id, email, display_name, status, user_name, attributes)
				 VALUES ($1,$2,'Discovery Error Subject','active',$2,'{}'::jsonb)`,
				tenantID, subject)
			return err
		}); err != nil {
			t.Fatalf("seed %s: %v", tenantID, err)
		}
	}
	seed(victim)
	seed(bystander)

	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := New(pool, nil, nil, nil, sink, "backups expire after 14 days (it)", nil)
	discoveryErr := errors.New("injected table discovery failure")
	realTableExists := engine.subjectTableExists
	engine.subjectTableExists = func(ctx context.Context, sc tenancy.Scope, table string) (bool, error) {
		if sc.Tenant.String() == victim && table == "users" {
			return false, discoveryErr
		}
		return realTableExists(ctx, sc, table)
	}

	report, err := engine.EraseSubject(ctx, victim, subject, "privacy-admin", "dsar")
	if err != nil {
		t.Fatalf("subject erase should return its incomplete receipt: %v", err)
	}
	if report.Complete {
		t.Fatalf("table discovery failure produced a complete receipt: %+v", report)
	}
	postgres := subjectPlanesByName(report.Planes)["postgres"]
	if postgres.Status != SubjectStatusFailed || !strings.Contains(postgres.Notes, discoveryErr.Error()) {
		t.Fatalf("postgres failure receipt = %+v", postgres)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, victim, subject); got != 1 {
		t.Fatalf("victim row changed despite rolled-back discovery failure: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, bystander, subject); got != 1 {
		t.Fatalf("bystander row must remain untouched: %d", got)
	}
}

func TestSubjectErasureNotCapableProductionStoreFailsClosedAndIsolated(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	subject := "not-capable-" + stamp + "@example.com"
	victim := mkTenant(t, pool, "it-subject-not-capable-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-not-capable-b-"+stamp)

	for _, tenantID := range []string{victim, bystander} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx,
					`INSERT INTO users (tenant_id, email, display_name, status, user_name, attributes)
					 VALUES ($1,$2,'Not Capable Subject','active',$2,'{}'::jsonb)`,
					tenantID, subject)
				return err
			})
		if err != nil {
			t.Fatalf("seed %s: %v", tenantID, err)
		}
	}

	// Prometheus is the shipping production TSDB writer. It supports
	// whole-tenant admin deletion but cannot delete one subject locally, so
	// EraseSubject must return an honest incomplete receipt without contacting
	// the configured endpoint.
	prometheus := tsdb.NewPrometheus("https://prometheus.invalid")
	t.Cleanup(func() {
		if err := prometheus.Close(); err != nil {
			t.Errorf("close Prometheus writer: %v", err)
		}
	})
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	providerHead, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	engine := New(pool, nil, nil, prometheus, sink, "backups expire after 14 days (it)", nil)

	report, err := engine.EraseSubject(ctx, victim, subject, "privacy-admin", "dsar")
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}
	if report.Complete || report.ReportSHA256 == "" {
		t.Fatalf("production not-capable TSDB receipt must be incomplete and hashed: %+v", report)
	}
	planes := subjectPlanesByName(report.Planes)
	for _, plane := range []string{"tsdb_metrics", "rum"} {
		if got := planes[plane]; got.Status != SubjectStatusNotCapable {
			t.Fatalf("%s receipt = %+v, want status %q", plane, got, SubjectStatusNotCapable)
		}
	}

	if got := countRows(t, pool,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`,
		victim, subject); got != 0 {
		t.Fatalf("victim subject survived PostgreSQL erasure: %d", got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`,
		bystander, subject); got != 1 {
		t.Fatalf("bystander subject must remain untouched: %d", got)
	}

	if err := audit.ProviderVerifyFrom(ctx, pool, providerHead); err != nil {
		t.Fatalf("provider audit suffix must verify: %v", err)
	}
	events, err := audit.ListProvider(ctx, pool, providerHead, 100)
	if err != nil {
		t.Fatal(err)
	}
	var receiptAudit *audit.Event
	for i := range events {
		if events[i].Action == "privacy.subject_erase" && events[i].Target == victim {
			receiptAudit = &events[i]
			break
		}
	}
	if receiptAudit == nil {
		t.Fatalf("provider audit missing subject-erasure receipt after seq %d: %+v", providerHead, events)
	}
	if complete, ok := receiptAudit.Data["complete"].(bool); !ok || complete {
		t.Fatalf("provider audit complete = %#v, want false", receiptAudit.Data["complete"])
	}
	if got, _ := receiptAudit.Data["report_sha256"].(string); got != report.ReportSHA256 {
		t.Fatalf("provider audit report hash = %q, want %q", got, report.ReportSHA256)
	}
}

func TestSubjectLifecycleErasesIdentityAIAndProjectsAuditPG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	stamp := time.Now().UTC().Format("150405.000000000")
	subject := "alice-" + strings.ReplaceAll(stamp, ".", "") + "@example.com"
	victim := mkTenant(t, pool, "it-subject-a-"+strings.ReplaceAll(stamp, ".", "-"))
	bystander := mkTenant(t, pool, "it-subject-b-"+strings.ReplaceAll(stamp, ".", "-"))

	seedSubjectRows := func(tenantID string) {
		t.Helper()
		tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
		err := tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx,
				`INSERT INTO users (tenant_id, email, display_name, status, user_name, attributes)
				 VALUES ($1,$2,'Alice Subject','active',$2,'{"department":"privacy"}'::jsonb)`,
				tenantID, subject); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx,
				`INSERT INTO ai_answers (tenant_id, answer_id, question, root_cause, payload)
				 VALUES ($1,$2,'why is alice slow?',$3,$4::jsonb)`,
				tenantID, "ans-"+tenantID, "RCA mentions "+subject, `{"subject":"`+subject+`"}`); err != nil {
				return err
			}
			var incidentID string
			if err := sc.Q.QueryRow(ctx,
				`INSERT INTO incidents (tenant_id, title)
				 VALUES ($1, 'subject lifecycle incident') RETURNING id::text`,
				tenantID).Scan(&incidentID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx,
				`INSERT INTO incident_journal_entries
				       (tenant_id, id, incident_id, entry_kind, body, created_by, expires_at)
				 VALUES ($1, $2, $3, 'note', $4, $4, clock_timestamp() + interval '30 days')`,
				tenantID, "journal-"+tenantID, incidentID, subject); err != nil {
				return err
			}
			_, err := audit.TenantAppend(ctx, sc, subject, "directory.provision", subject, map[string]any{"email": subject})
			return err
		})
		if err != nil {
			t.Fatalf("seed subject rows: %v", err)
		}
	}
	seedSubjectRows(victim)
	seedSubjectRows(bystander)

	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	e := New(pool, nil, nil, nil, sink, "backups expire after 14 days (it)", nil)

	var bundle bytes.Buffer
	man, err := e.ExportSubject(ctx, victim, subject, &bundle, false)
	if err != nil {
		t.Fatalf("subject export: %v", err)
	}
	if man.SubjectHash == "" {
		t.Fatal("subject export must identify the subject by hash")
	}
	files := readTarGz(t, bundle.Bytes())
	if !strings.Contains(files["postgres/users.jsonl"], subject) {
		t.Fatalf("subject export missing user row: files=%v", files)
	}
	if !strings.Contains(files["postgres/incident_journal_entries.jsonl"], subject) {
		t.Fatalf("subject export missing incident journal row: files=%v", files)
	}

	providerHead, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	report, err := e.EraseSubject(ctx, victim, subject, "privacy-admin", "dsar")
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}
	if !report.Complete || report.ReportSHA256 == "" {
		t.Fatalf("subject erasure report incomplete/unhashed: %+v", report)
	}
	if err := audit.ProviderVerifyFrom(ctx, pool, providerHead); err != nil {
		t.Fatalf("provider audit suffix must verify: %v", err)
	}

	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, victim, subject); got != 0 {
		t.Fatalf("victim user survived subject erase: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND payload::text ILIKE $2`, victim, "%"+subject+"%"); got != 0 {
		t.Fatalf("victim AI answer survived subject erase: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM incident_journal_entries WHERE tenant_id = $1 AND body ILIKE $2`, victim, "%"+subject+"%"); got != 0 {
		t.Fatalf("victim incident journal entry survived subject erase: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, bystander, subject); got != 1 {
		t.Fatalf("bystander user must be untouched: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND payload::text ILIKE $2`, bystander, "%"+subject+"%"); got != 1 {
		t.Fatalf("bystander AI answer must be untouched: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM incident_journal_entries WHERE tenant_id = $1 AND body ILIKE $2`, bystander, "%"+subject+"%"); got != 1 {
		t.Fatalf("bystander incident journal entry must be untouched: %d", got)
	}

	tctx := tenancy.WithTenant(ctx, tenancy.ID(victim))
	err = tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		events, err := audit.List(ctx, sc, 0, 100)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(events)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(subject)) {
			t.Fatalf("audit projection leaked erased subject: %s", raw)
		}
		if !strings.Contains(string(raw), audit.SubjectErasureAction) {
			t.Fatalf("audit list missing subject erasure marker: %s", raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSubjectErasureCompleteCoversEveryTenantTableAndStaysTenantScoped(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	subject := "schema-complete-" + stamp + "@example.test"
	victim := mkTenant(t, pool, "it-subject-schema-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-schema-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`, victim, bystander); err != nil {
			t.Errorf("cleanup subject-schema tenants: %v", err)
		}
	})

	createUser := func(tenantID string) string {
		t.Helper()
		var userID string
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx,
					`INSERT INTO users
					       (tenant_id, email, display_name, status, user_name, external_id, attributes)
					 VALUES ($1, $2, 'Schema Complete Subject', 'active', $2, $2,
					         jsonb_build_object('subject', $2::text))
					 RETURNING id::text`,
					tenantID, subject).Scan(&userID)
			})
		if err != nil {
			t.Fatalf("seed user for %s: %v", tenantID, err)
		}
		return userID
	}
	victimUserID := createUser(victim)
	bystanderUserID := createUser(bystander)

	sessions := store.NewSessions(pool)
	mcpTokens := store.NewMCPTokens(pool)
	sessionHashes := map[string][]byte{
		victim:    []byte("subject-session-victim-" + stamp),
		bystander: []byte("subject-session-bystander-" + stamp),
	}
	mcpHashes := map[string][]byte{
		victim:    []byte("subject-mcp-victim-" + stamp),
		bystander: []byte("subject-mcp-bystander-" + stamp),
	}
	for tenantID, userID := range map[string]string{
		victim: victimUserID, bystander: bystanderUserID,
	} {
		now := time.Now().UTC()
		if err := sessions.Create(ctx, sessionHashes[tenantID], auth.Session{
			TenantID: tenantID, UserID: userID, Email: subject,
			DisplayName: "Schema Complete Subject", ExpiresAt: now.Add(time.Hour),
			CreatedAt: now, LastActivityAt: now,
		}); err != nil {
			t.Fatalf("seed session for %s: %v", tenantID, err)
		}
		if _, err := mcpTokens.Create(
			ctx, tenantID, userID, "subject-schema-regression", mcpHashes[tenantID],
		); err != nil {
			t.Fatalf("seed MCP token for %s: %v", tenantID, err)
		}
	}

	type seededRows struct {
		feedbackID string
		viewID     string
		shareID    string
	}
	seedOmittedTables := func(tenantID, subjectAlias, label string) seededRows {
		t.Helper()
		rows := seededRows{
			viewID:  "schema-view-" + label + "-" + stamp,
			shareID: "schema-share-" + label + "-" + stamp,
		}
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if err := sc.Q.QueryRow(ctx,
					`INSERT INTO ai_feedback
					       (tenant_id, answer_id, question, rating, comment, user_id)
					 VALUES ($1, $2, 'schema coverage', 'up', 'bounded regression', $3)
					 RETURNING id::text`,
					tenantID, "schema-feedback-"+label+"-"+stamp, subjectAlias).
					Scan(&rows.feedbackID); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx,
					`INSERT INTO dashboard_views
					       (tenant_id, id, owner_id, name, preset, shared, definition)
					 VALUES ($1, $2, $3, 'Subject-owned view', 'operator', false,
					         jsonb_build_object('owner', $3::text))`,
					tenantID, rows.viewID, subjectAlias); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx,
					`INSERT INTO incident_share_artifacts
					       (tenant_id, id, incident_id, payload, created_by, expires_at)
					 VALUES ($1, $2, gen_random_uuid(),
					         jsonb_build_object('created_by', $3::text), $3,
					         clock_timestamp() + interval '1 day')`,
					tenantID, rows.shareID, subjectAlias); err != nil {
					return err
				}
				_, err := audit.TenantAppend(
					ctx, sc, subjectAlias, "subject.schema_fixture", subjectAlias,
					map[string]any{"owner_id": subjectAlias},
				)
				return err
			})
		if err != nil {
			t.Fatalf("seed omitted subject tables for %s: %v", tenantID, err)
		}
		return rows
	}
	victimRows := seedOmittedTables(victim, victimUserID, "victim")
	// Deliberately place tenant A's opaque user identifier in tenant B too. The
	// eraser must use tenant scope before its subject predicate.
	bystanderRows := seedOmittedTables(bystander, victimUserID, "bystander")

	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	report, err := New(pool, nil, nil, nil, sink, "backups expire after 14 days (it)", nil).
		EraseSubject(ctx, victim, subject, "privacy-admin", "dsar")
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}

	countByID := func(tenantID, table, id string) int64 {
		t.Helper()
		return countRows(t, pool,
			`SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id = $1 AND id = $2`,
			tenantID, id)
	}
	remaining := map[string]int64{
		"ai_feedback":              countByID(victim, "ai_feedback", victimRows.feedbackID),
		"dashboard_views":          countByID(victim, "dashboard_views", victimRows.viewID),
		"incident_share_artifacts": countByID(victim, "incident_share_artifacts", victimRows.shareID),
	}
	for table, n := range remaining {
		if n != 0 {
			t.Errorf("victim subject survived in %s: %d", table, n)
		}
	}
	if t.Failed() && report.Complete {
		t.Fatalf("subject erasure reported Complete=true while tenant tables retained subject aliases: %+v", remaining)
	}
	if !report.Complete {
		t.Fatalf("schema-complete erasure receipt is incomplete: %+v", report)
	}
	receipts := subjectPlanesByName(report.Planes)
	for table, plane := range map[string]string{
		"ai_feedback":              "postgres:ai_feedback",
		"dashboard_views":          "postgres:dashboard_views",
		"incident_share_artifacts": "postgres:incident_share_artifacts",
	} {
		receipt := receipts[plane]
		if receipt.Status != SubjectStatusDeleted || receipt.Deleted != 1 || receipt.Remaining != 0 {
			t.Fatalf("%s count-verification receipt = %+v", table, receipt)
		}
	}
	if receipt := receipts["postgres:credential_locators"]; receipt.Deleted != 2 || receipt.Remaining != 0 {
		t.Fatalf("credential locator receipt = %+v, want two tenant-scoped locators removed", receipt)
	}
	if got, err := sessions.LookupByHash(ctx, sessionHashes[victim], time.Hour); err != nil || got != nil {
		t.Fatalf("victim session locator/detail survived: session=%+v err=%v", got, err)
	}
	if _, _, err := mcpTokens.Authenticate(ctx, mcpHashes[victim]); !errors.Is(err, store.ErrInvalidToken) {
		t.Fatalf("victim MCP locator/detail survived: %v", err)
	}
	if got, err := sessions.LookupByHash(ctx, sessionHashes[bystander], time.Hour); err != nil || got == nil {
		t.Fatalf("bystander session changed: session=%+v err=%v", got, err)
	}
	if tenantID, userID, err := mcpTokens.Authenticate(ctx, mcpHashes[bystander]); err != nil ||
		tenantID != bystander || userID != bystanderUserID {
		t.Fatalf("bystander MCP token changed: tenant=%q user=%q err=%v", tenantID, userID, err)
	}

	if got := countByID(bystander, "ai_feedback", bystanderRows.feedbackID); got != 1 {
		t.Fatalf("bystander ai_feedback row changed: %d", got)
	}
	if got := countByID(bystander, "dashboard_views", bystanderRows.viewID); got != 1 {
		t.Fatalf("bystander dashboard view changed: %d", got)
	}
	if got := countByID(bystander, "incident_share_artifacts", bystanderRows.shareID); got != 1 {
		t.Fatalf("bystander incident share changed: %d", got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`,
		bystander, subject); got != 1 {
		t.Fatalf("bystander identity changed: %d", got)
	}

	auditJSON := func(tenantID string) string {
		t.Helper()
		var raw []byte
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				events, err := audit.List(ctx, sc, 0, 100)
				if err != nil {
					return err
				}
				raw, err = json.Marshal(events)
				return err
			})
		if err != nil {
			t.Fatalf("list %s audit: %v", tenantID, err)
		}
		return string(raw)
	}
	if raw := auditJSON(victim); strings.Contains(strings.ToLower(raw), strings.ToLower(victimUserID)) {
		t.Fatalf("victim audit projection retained captured user UUID: %s", raw)
	}
	if raw := auditJSON(bystander); !strings.Contains(strings.ToLower(raw), strings.ToLower(victimUserID)) {
		t.Fatalf("bystander audit must not inherit tenant A's subject projection: %s", raw)
	}
}

func TestSubjectErasureSiloSchemaDriftFailsClosedBeforeMutation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	subject := "silo-drift-" + stamp + "@example.test"
	victim := mkTenant(t, pool, "it-subject-silo-"+stamp)
	schema := "it_subject_silo_" + stamp
	quotedSchema := pgIdent(schema)
	quotedAppRole := pgIdent(tenancy.AppRole)

	for _, statement := range []string{
		`CREATE SCHEMA ` + quotedSchema,
		`GRANT USAGE ON SCHEMA ` + quotedSchema + ` TO ` + quotedAppRole,
		`CREATE TABLE ` + quotedSchema + `.users (LIKE public.users INCLUDING ALL)`,
		`ALTER TABLE ` + quotedSchema + `.users ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + quotedSchema + `.users FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON ` + quotedSchema + `.users
		   USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
		   WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ` + quotedSchema + `.users TO ` + quotedAppRole,
		`CREATE TABLE ` + quotedSchema + `.future_subject_records (
		   id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
		   tenant_id uuid NOT NULL,
		   subject text NOT NULL
		 )`,
		`ALTER TABLE ` + quotedSchema + `.future_subject_records ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE ` + quotedSchema + `.future_subject_records FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation ON ` + quotedSchema + `.future_subject_records
		   USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
		   WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ` + quotedSchema + `.future_subject_records TO ` + quotedAppRole,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("prepare drifted subject-erasure silo: %v", err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DROP SCHEMA `+quotedSchema+` CASCADE`); err != nil {
			t.Errorf("drop subject-erasure silo schema: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, victim); err != nil {
			t.Errorf("delete subject-erasure silo tenant: %v", err)
		}
	})

	if _, err := pool.Exec(ctx,
		`INSERT INTO `+quotedSchema+`.users
		       (tenant_id, email, display_name, status, user_name, attributes)
		 VALUES ($1, $2, 'Silo Drift Subject', 'active', $2, '{}'::jsonb)`,
		victim, subject); err != nil {
		t.Fatalf("seed silo user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO `+quotedSchema+`.future_subject_records (tenant_id, subject)
		 VALUES ($1, $2)`,
		victim, subject); err != nil {
		t.Fatalf("seed silo-only subject row: %v", err)
	}

	previousRouter := tenancy.CurrentRouter()
	tenancy.SetRouter(subjectSiloTestRouter{
		PooledRouter: tenancy.PooledRouter{},
		tenantID:     victim,
		schema:       schema,
	})
	t.Cleanup(func() { tenancy.SetRouter(previousRouter) })

	report, err := New(pool, nil, nil, nil, nil, "", nil).
		EraseSubject(ctx, victim, subject, "privacy-admin", "silo drift regression")
	if err != nil {
		t.Fatalf("subject erase should return its incomplete receipt: %v", err)
	}
	if report.Complete {
		t.Fatalf("drifted silo schema produced Complete=true: %+v", report)
	}
	postgres := subjectPlanesByName(report.Planes)["postgres"]
	if postgres.Status != SubjectStatusFailed ||
		!strings.Contains(postgres.Notes, schema) ||
		!strings.Contains(postgres.Notes, "extra=future_subject_records") {
		t.Fatalf("silo drift receipt = %+v", postgres)
	}
	for table := range map[string]struct{}{
		"users":                  {},
		"future_subject_records": {},
	} {
		if got := countRows(t, pool,
			`SELECT count(*) FROM `+quotedSchema+`.`+pgIdent(table)+`
			  WHERE tenant_id = $1 AND `+map[string]string{
				"users":                  "email",
				"future_subject_records": "subject",
			}[table]+` = $2`,
			victim, subject); got != 1 {
			t.Fatalf("silo %s changed despite schema-drift rollback: %d", table, got)
		}
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM public.audit_events
		  WHERE tenant_id = $1 AND action = $2`,
		victim, audit.SubjectErasureAction); got != 0 {
		t.Fatalf("failed silo erasure wrote %d subject-projection markers", got)
	}
}

func TestSubjectErasureAmbiguousFreeformFailsClosedWithoutOverDelete(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	victim := mkTenant(t, pool, "it-subject-freeform-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-freeform-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`, victim, bystander); err != nil {
			t.Errorf("cleanup freeform subject tenants: %v", err)
		}
	})

	for label, tenantID := range map[string]string{"victim": victim, "bystander": bystander} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := sc.Q.Exec(ctx,
					`INSERT INTO roles (tenant_id, slug, name, description)
					 VALUES ($1, $2, 'Read-only administrator', 'active admin role')`,
					tenantID, "freeform-"+label+"-"+stamp); err != nil {
					return err
				}
				_, err := sc.Q.Exec(ctx,
					`INSERT INTO incidents (tenant_id, title, target)
					 VALUES ($1, 'read path remains active', 'read')`,
					tenantID)
				return err
			})
		if err != nil {
			t.Fatalf("seed %s freeform rows: %v", label, err)
		}
	}

	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	trackingFlows := &trackingSubjectFlowStore{Store: flowstore.NewMemory()}
	t.Cleanup(func() {
		if err := trackingFlows.Close(); err != nil {
			t.Errorf("close tracking flow store: %v", err)
		}
	})
	report, err := New(pool, trackingFlows, nil, nil, sink, "", nil).
		EraseSubject(ctx, victim, "read", "privacy-admin", "ambiguous regression")
	if err != nil {
		t.Fatalf("subject erase should return its incomplete receipt: %v", err)
	}
	if report.Complete {
		t.Fatalf("ambiguous freeform subject produced Complete=true: %+v", report)
	}
	postgres := subjectPlanesByName(report.Planes)["postgres"]
	if postgres.Status != SubjectStatusFailed ||
		!strings.Contains(postgres.Notes, "does not resolve to one exact identity") {
		t.Fatalf("ambiguous subject PostgreSQL receipt = %+v", postgres)
	}
	if trackingFlows.deleteSubjectCalls != 0 {
		t.Fatalf("ambiguous subject invoked downstream flow deletion %d time(s)", trackingFlows.deleteSubjectCalls)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM audit_events
		  WHERE tenant_id = $1 AND action = $2`,
		victim, audit.SubjectErasureAction); got != 0 {
		t.Fatalf("ambiguous subject wrote %d overbroad audit-projection markers", got)
	}
	for label, tenantID := range map[string]string{"victim": victim, "bystander": bystander} {
		if got := countRows(t, pool,
			`SELECT count(*) FROM roles WHERE tenant_id = $1 AND name = 'Read-only administrator'`,
			tenantID); got != 1 {
			t.Fatalf("%s unrelated role changed: %d", label, got)
		}
		if got := countRows(t, pool,
			`SELECT count(*) FROM incidents WHERE tenant_id = $1 AND target = 'read'`,
			tenantID); got != 1 {
			t.Fatalf("%s unrelated incident changed: %d", label, got)
		}
	}
}

type trackingSubjectFlowStore struct {
	flowstore.Store
	deleteSubjectCalls int
}

func (s *trackingSubjectFlowStore) DeleteSubject(
	context.Context,
	string,
	string,
) (int64, int64, error) {
	s.deleteSubjectCalls++
	return 0, 0, nil
}

type subjectSiloTestRouter struct {
	tenancy.PooledRouter
	tenantID string
	schema   string
}

func (r subjectSiloTestRouter) TargetsFor(
	_ context.Context,
	tenantID string,
) (tenancy.Targets, error) {
	if tenantID == r.tenantID {
		return tenancy.Targets{
			Model:    tenancy.IsolationSiloed,
			PGSchema: r.schema,
		}, nil
	}
	return r.PooledRouter.TargetsFor(context.Background(), tenantID)
}

func TestSubjectErasureAmbiguousExactIdentityAliasRollsBack(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	subject := "ambiguous-" + stamp + "@example.test"
	victim := mkTenant(t, pool, "it-subject-alias-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-alias-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`, victim, bystander); err != nil {
			t.Errorf("cleanup ambiguous-alias tenants: %v", err)
		}
	})

	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(victim)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx,
				`INSERT INTO users
				       (tenant_id, email, display_name, status, user_name, attributes)
				 VALUES ($1, $2, 'Email owner', 'active', $2, '{}'::jsonb)`,
				victim, subject); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx,
				`INSERT INTO users
				       (tenant_id, email, display_name, status, user_name, external_id, attributes)
				 VALUES ($1, $2, 'External-id owner', 'active', $2, $3, '{}'::jsonb)`,
				victim, "other-"+stamp+"@example.test", subject)
			return err
		})
	if err != nil {
		t.Fatalf("seed ambiguous victim identities: %v", err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(bystander)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx,
				`INSERT INTO users
				       (tenant_id, email, display_name, status, user_name, attributes)
				 VALUES ($1, $2, 'Bystander', 'active', $2, '{}'::jsonb)`,
				bystander, subject)
			return err
		})
	if err != nil {
		t.Fatalf("seed bystander identity: %v", err)
	}

	report, err := New(pool, nil, nil, nil, nil, "", nil).
		EraseSubject(ctx, victim, subject, "privacy-admin", "ambiguous alias")
	if err != nil {
		t.Fatalf("subject erase: %v", err)
	}
	if report.Complete {
		t.Fatalf("ambiguous identity aliases produced Complete=true: %+v", report)
	}
	postgres := subjectPlanesByName(report.Planes)["postgres"]
	if !strings.Contains(postgres.Notes, "ambiguous across 2 directory identities") {
		t.Fatalf("ambiguous identity receipt = %+v", postgres)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1`, victim); got != 2 {
		t.Fatalf("victim identities changed despite ambiguity rollback: %d", got)
	}
	if got := countRows(t, pool,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`,
		bystander, subject); got != 1 {
		t.Fatalf("bystander identity changed: %d", got)
	}
}

func TestSubjectErasureEscapesSQLWildcards(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()
	stamp := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	victim := mkTenant(t, pool, "it-subject-wildcard-a-"+stamp)
	bystander := mkTenant(t, pool, "it-subject-wildcard-b-"+stamp)
	subject := "account%_owner-" + stamp + "@example.test"
	nearMatch := "account-expandedXowner-" + stamp + "@example.test"

	type seededRows struct {
		answerID  string
		journalID string
	}
	seed := func(tenantID, value, label string) seededRows {
		t.Helper()
		rows := seededRows{
			answerID:  "wildcard-answer-" + label + "-" + stamp,
			journalID: "wildcard-journal-" + label + "-" + stamp,
		}
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := sc.Q.Exec(ctx,
					`INSERT INTO users (tenant_id, email, display_name, status, user_name, attributes)
					 VALUES ($1, $2, 'Wildcard Subject', 'active', $2, jsonb_build_object('subject', $2::text))`,
					tenantID, value); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx,
					`INSERT INTO ai_answers (tenant_id, answer_id, question, root_cause, payload)
					 VALUES ($1, $2, 'subject lookup', $3, jsonb_build_object('subject', $3::text))`,
					tenantID, rows.answerID, value); err != nil {
					return err
				}
				var incidentID string
				if err := sc.Q.QueryRow(ctx,
					`INSERT INTO incidents (tenant_id, title)
					 VALUES ($1, 'wildcard subject lifecycle incident') RETURNING id::text`,
					tenantID).Scan(&incidentID); err != nil {
					return err
				}
				_, err := sc.Q.Exec(ctx,
					`INSERT INTO incident_journal_entries
					       (tenant_id, id, incident_id, entry_kind, body, created_by, expires_at)
					 VALUES ($1, $2, $3, 'note', $4, $4, clock_timestamp() + interval '30 days')`,
					tenantID, rows.journalID, incidentID, value)
				return err
			})
		if err != nil {
			t.Fatalf("seed %s/%s: %v", tenantID, label, err)
		}
		return rows
	}

	literal := seed(victim, subject, "literal")
	near := seed(victim, nearMatch, "near")
	foreign := seed(bystander, subject, "foreign")

	engine := New(pool, nil, nil, nil, nil, "", nil)
	results, _, err := engine.eraseSubjectPostgres(ctx, victim, subject)
	if err != nil {
		t.Fatalf("erase subject containing SQL wildcards: %v", err)
	}
	byPlane := subjectPlanesByName(results)
	for _, plane := range []string{"identity", "ai_answers", "incident_journal"} {
		if result := byPlane[plane]; result.Deleted != 1 {
			t.Errorf("%s deleted %d rows, want exactly the literal match", plane, result.Deleted)
		}
	}

	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, victim, subject); got != 0 {
		t.Fatalf("literal user survived subject erasure: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND answer_id = $2`, victim, literal.answerID); got != 0 {
		t.Fatalf("literal AI answer survived subject erasure: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM incident_journal_entries WHERE tenant_id = $1 AND id = $2`, victim, literal.journalID); got != 0 {
		t.Fatalf("literal journal entry survived subject erasure: %d", got)
	}

	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, victim, nearMatch); got != 1 {
		t.Fatalf("same-tenant wildcard near-match was erased: %d rows remain", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND answer_id = $2`, victim, near.answerID); got != 1 {
		t.Fatalf("same-tenant AI wildcard near-match was erased: %d rows remain", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM incident_journal_entries WHERE tenant_id = $1 AND id = $2`, victim, near.journalID); got != 1 {
		t.Fatalf("same-tenant journal wildcard near-match was erased: %d rows remain", got)
	}

	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, bystander, subject); got != 1 {
		t.Fatalf("foreign-tenant literal user was erased: %d rows remain", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND answer_id = $2`, bystander, foreign.answerID); got != 1 {
		t.Fatalf("foreign-tenant literal AI answer was erased: %d rows remain", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM incident_journal_entries WHERE tenant_id = $1 AND id = $2`, bystander, foreign.journalID); got != 1 {
		t.Fatalf("foreign-tenant literal journal entry was erased: %d rows remain", got)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
