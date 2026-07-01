// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

//go:build integration

package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	eegovernance "github.com/imfeelingtheagi/probectl/ee/governance"
	"github.com/imfeelingtheagi/probectl/ee/silo"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
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
	if err := life.SetRetention(ctx, tenantlife.RetentionPolicy{
		TenantID: tenantID, FlowRetentionDays: &days, UpdatedBy: "provider-it",
	}); err != nil {
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

	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
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

	att, err := life.Erase(ctx, tenantID, slug, "provider-it")
	if err != nil {
		t.Fatalf("erase tenant: %v", err)
	}
	if !att.Complete {
		t.Fatalf("erasure attestation incomplete: %+v", att.Stores)
	}
	assertPublicRetentionDays(t, pool, tenantID, 0)
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
