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
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
	results, err := engine.eraseSubjectPostgres(ctx, victim, subject)
	if err != nil {
		t.Fatalf("erase subject containing SQL wildcards: %v", err)
	}
	for _, result := range results {
		if result.Deleted != 1 {
			t.Errorf("%s deleted %d rows, want exactly the literal match", result.Plane, result.Deleted)
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
