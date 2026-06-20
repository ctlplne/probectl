// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

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
	if got := countRows(t, pool, `SELECT count(*) FROM users WHERE tenant_id = $1 AND email = $2`, bystander, subject); got != 1 {
		t.Fatalf("bystander user must be untouched: %d", got)
	}
	if got := countRows(t, pool, `SELECT count(*) FROM ai_answers WHERE tenant_id = $1 AND payload::text ILIKE $2`, bystander, "%"+subject+"%"); got != 1 {
		t.Fatalf("bystander AI answer must be untouched: %d", got)
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

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
