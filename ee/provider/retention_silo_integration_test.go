// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	eegovernance "github.com/imfeelingtheagi/probectl/ee/governance"
	"github.com/imfeelingtheagi/probectl/ee/silo"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

func TestSiloRetentionStaysProviderOwned(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	slug := "it-retention-silo-" + stamp
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (slug, name, isolation_model, residency)
		VALUES ($1, $1, 'siloed', '')
		RETURNING id::text`, slug).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	schema := silo.SchemaName(tenantID)

	prov := silo.NewProvisioner(pool, silo.CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, tenantID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision silo: %v", err)
	}
	t.Cleanup(func() { _ = prov.Teardown(ctx, tenantID, "", tenancy.IsolationSiloed) })

	router := silo.NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	if tableExists(t, pool, schema, "tenant_retention") {
		t.Fatal("tenant_retention is provider-owned lifecycle policy and must not be copied into a tenant silo")
	}
	if !tableExists(t, pool, "public", "tenant_retention") {
		t.Fatal("public.tenant_retention must exist for provider-owned lifecycle policy")
	}

	now := time.Now().UTC()
	flows := flowstore.NewMemory()
	if err := flows.Insert(ctx, []flowstore.Row{
		{TenantID: tenantID, AgentID: "old", Exporter: "router", TS: now.Add(-48 * time.Hour), Bytes: 1},
		{TenantID: tenantID, AgentID: "fresh", Exporter: "router", TS: now.Add(-1 * time.Hour), Bytes: 2},
	}); err != nil {
		t.Fatalf("seed flows: %v", err)
	}
	life := tenantlife.New(pool, flows, nil, tsdb.NewMemory(), func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}, "integration backups expire after 14 days", log).WithClock(func() time.Time { return now })

	days := 1
	if err := life.SetRetention(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		tenantlife.RetentionPolicy{
			TenantID: tenantID, FlowRetentionDays: &days, UpdatedBy: "provider-it",
		},
		"provider-it",
	); err != nil {
		t.Fatalf("set retention through silo-routed tenant scope: %v", err)
	}
	assertPublicRetentionDays(t, pool, tenantID, 1)

	if err := life.SweepRetention(ctx); err != nil {
		t.Fatalf("sweep retention: %v", err)
	}
	var remaining bytes.Buffer
	n, err := flows.ExportTenant(ctx, tenantID, &remaining)
	if err != nil {
		t.Fatalf("export remaining flows: %v", err)
	}
	if n != 1 || !bytes.Contains(remaining.Bytes(), []byte(`"agent_id":"fresh"`)) {
		t.Fatalf("retention sweep kept wrong flows: n=%d rows=%s", n, remaining.String())
	}

	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	f.h.WithGovernance(&Governance{Store: eegovernance.NewStore(pool), Pool: pool})
	token := f.bootstrapAndLoginFast(t)
	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/tenants/"+tenantID+"/governance", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("governance view: %d %s", rec.Code, rec.Body.String())
	}
	var view struct {
		IsolationModel string `json:"isolation_model"`
		RetentionDays  *int   `json:"retention_days"`
	}
	mustDecode(t, rec, &view)
	if view.IsolationModel != "siloed" || view.RetentionDays == nil || *view.RetentionDays != 1 {
		t.Fatalf("governance did not read provider-owned retention: %+v", view)
	}

	if err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			_, err := audit.RecordSubjectErasure(
				ctx,
				scope,
				"provider-it",
				"full-erasure-projection@example.test",
				"full tenant erasure regression",
			)
			return err
		},
	); err != nil {
		t.Fatalf("seed silo subject-erasure projection: %v", err)
	}
	quotedProjection := pgx.Identifier{schema, "audit_subject_erasures"}.Sanitize()
	var projectionRows int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM `+quotedProjection+`
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&projectionRows); err != nil {
		t.Fatalf("count silo subject-erasure projection: %v", err)
	}
	if projectionRows != 1 {
		t.Fatalf("silo subject-erasure projections = %d, want 1 before erase", projectionRows)
	}

	att, err := life.Erase(ctx, tenantID, slug, "provider-it")
	if err != nil {
		t.Fatalf("erase tenant: %v", err)
	}
	if !att.Complete {
		t.Fatalf("erasure attestation incomplete: %+v", att.Stores)
	}
	assertPublicRetentionDays(t, pool, tenantID, 0)
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM `+quotedProjection+`
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&projectionRows); err != nil {
		t.Fatalf("verify erased silo subject projection: %v", err)
	}
	if projectionRows != 0 {
		t.Fatalf("silo subject-erasure projections after tenant erase = %d, want 0", projectionRows)
	}
}

type siloRetentionState struct {
	PolicyRows        int64
	FlowRetentionDays int
	UpdatedBy         string
	AuditRows         int64
	RetentionAudits   int64
	HeadSeq           int64
	HeadHash          string
	PrunedSeq         int64
	PrunedHash        string
}

func snapshotSiloRetentionState(
	t *testing.T,
	pool *pgxpool.Pool,
	schema, tenantID string,
) siloRetentionState {
	t.Helper()
	var got siloRetentionState
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*), max(flow_retention_days), max(updated_by)
		   FROM public.tenant_retention
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&got.PolicyRows, &got.FlowRetentionDays, &got.UpdatedBy); err != nil {
		t.Fatalf("snapshot public retention for %s: %v", tenantID, err)
	}
	quotedEvents := pgx.Identifier{schema, "audit_events"}.Sanitize()
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*),
		        count(*) FILTER (WHERE action = 'lifecycle.retention_set')
		   FROM `+quotedEvents+`
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&got.AuditRows, &got.RetentionAudits); err != nil {
		t.Fatalf("snapshot silo audit events for %s: %v", tenantID, err)
	}
	if err := pool.QueryRow(
		context.Background(),
		`SELECT head_seq, head_hash, pruned_seq, pruned_hash
		   FROM public.audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&got.HeadSeq, &got.HeadHash, &got.PrunedSeq, &got.PrunedHash); err != nil {
		t.Fatalf("snapshot audit head for %s: %v", tenantID, err)
	}
	return got
}

func TestSiloRetentionTenantMismatchLeavesBothTenantsUnchanged(t *testing.T) {
	pool := pgPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())

	tenantIDs := make([]string, 0, 2)
	for _, suffix := range []string{"a", "b"} {
		slug := "it-retention-silo-mismatch-" + suffix + "-" + stamp
		var tenantID string
		if err := pool.QueryRow(
			ctx,
			`INSERT INTO tenants (slug, name, isolation_model, residency)
			 VALUES ($1, $1, 'siloed', '')
			 RETURNING id::text`,
			slug,
		).Scan(&tenantID); err != nil {
			t.Fatalf("create silo tenant %s: %v", suffix, err)
		}
		tenantIDs = append(tenantIDs, tenantID)
	}

	provisioner := silo.NewProvisioner(pool, silo.CHPlanes{}, nil, 0, log)
	for _, tenantID := range tenantIDs {
		if err := provisioner.Provision(ctx, tenantID, "", tenancy.IsolationSiloed); err != nil {
			t.Fatalf("provision retention silo %s: %v", tenantID, err)
		}
	}
	t.Cleanup(func() {
		for i := len(tenantIDs) - 1; i >= 0; i-- {
			if err := provisioner.Teardown(
				context.Background(),
				tenantIDs[i],
				"",
				tenancy.IsolationSiloed,
			); err != nil {
				t.Errorf("teardown retention silo %s: %v", tenantIDs[i], err)
			}
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = ANY($1::uuid[])`,
			tenantIDs,
		); err != nil {
			t.Errorf("cleanup retention silo tenants: %v", err)
		}
	})

	router := silo.NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	engine := tenantlife.New(pool, nil, nil, nil, nil, "", log)
	seedDays := []int{30, 60}
	for i, tenantID := range tenantIDs {
		if err := engine.SetRetention(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			tenantlife.RetentionPolicy{
				TenantID:          tenantID,
				FlowRetentionDays: &seedDays[i],
				UpdatedBy:         "fixture-" + tenantID,
			},
			"fixture",
		); err != nil {
			t.Fatalf("seed silo tenant %s retention: %v", tenantID, err)
		}
	}

	before := []siloRetentionState{
		snapshotSiloRetentionState(t, pool, silo.SchemaName(tenantIDs[0]), tenantIDs[0]),
		snapshotSiloRetentionState(t, pool, silo.SchemaName(tenantIDs[1]), tenantIDs[1]),
	}
	nextDays := 14
	for _, mismatch := range []struct {
		contextTenant string
		policyTenant  string
	}{
		{contextTenant: tenantIDs[0], policyTenant: tenantIDs[1]},
		{contextTenant: tenantIDs[1], policyTenant: tenantIDs[0]},
	} {
		err := engine.SetRetention(
			tenancy.WithTenant(ctx, tenancy.ID(mismatch.contextTenant)),
			tenantlife.RetentionPolicy{
				TenantID:          mismatch.policyTenant,
				FlowRetentionDays: &nextDays,
				UpdatedBy:         "cross-tenant-probe",
			},
			"tenant-admin",
		)
		if err == nil {
			t.Fatalf(
				"tenant %s context accepted tenant %s retention policy",
				mismatch.contextTenant,
				mismatch.policyTenant,
			)
		}
	}

	for i, tenantID := range tenantIDs {
		got := snapshotSiloRetentionState(t, pool, silo.SchemaName(tenantID), tenantID)
		if !reflect.DeepEqual(got, before[i]) {
			t.Fatalf(
				"silo tenant %s changed after cross-tenant mismatch:\n got  %+v\n want %+v",
				tenantID,
				got,
				before[i],
			)
		}
	}
}

func tableExists(t *testing.T, pool *pgxpool.Pool, schema, table string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			 WHERE table_schema = $1 AND table_name = $2
		)`, schema, table).Scan(&exists); err != nil {
		t.Fatalf("check table %s.%s: %v", schema, table, err)
	}
	return exists
}

func assertPublicRetentionDays(t *testing.T, pool *pgxpool.Pool, tenantID string, want int) {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM public.tenant_retention WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count public tenant_retention: %v", err)
	}
	if want == 0 {
		if n != 0 {
			t.Fatalf("public tenant_retention row must be erased, got %d", n)
		}
		return
	}
	var days int
	if err := pool.QueryRow(context.Background(),
		`SELECT flow_retention_days FROM public.tenant_retention WHERE tenant_id = $1`, tenantID).Scan(&days); err != nil {
		t.Fatalf("read public tenant_retention: %v", err)
	}
	if days != want {
		t.Fatalf("public retention days = %d, want %d", days, want)
	}
}
