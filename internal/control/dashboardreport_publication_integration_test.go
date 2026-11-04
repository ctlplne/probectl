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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real PG/application-role RLS and atomic artifact/audit publication. The
// render callback deliberately needs the same one-connection pool; it cannot
// proceed if generation still holds its capture transaction. This is not a
// live query, Unicode PDF, network-sender or release-stack report proof.
func TestDashboardReportRenderingReleasesTransactionAndRechecksPublication(t *testing.T) {
	core, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	configuration := db.Pool().Config()
	configuration.MaxConns, configuration.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	core.pool = pool
	tenants := []string{freshTenant(t, db, "report-publication-a"), freshTenant(t, db, "report-publication-b")}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("report publication fixture cleanup failed")
		}
	})
	owner, viewer := uuid(t), uuid(t)
	mutate := func(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn)
	}
	request := func(ctx context.Context, tenant string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/dashboard-reports", nil)
		return r.WithContext(auth.WithPrincipal(ctx, &auth.Principal{TenantID: tenant, UserID: viewer, Email: "viewer@example.invalid"}))
	}
	definition, err := json.Marshal(validDashboardRequest().Definition)
	if err != nil {
		t.Fatal(err)
	}
	create := func(tenant, id string) {
		t.Helper()
		if err := mutate(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{
				ID: id, OwnerID: owner, Name: "Publication " + tenant, Preset: "operator", Shared: true, Definition: definition,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	counts := func(tenant, id string) (int, int) {
		t.Helper()
		var artifacts, audits int
		if err := mutate(ctx, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND dashboard_id=$2`, tenant, id).Scan(&artifacts); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='dashboard.report_export'`, tenant).Scan(&audits)
		}); err != nil {
			t.Fatal(err)
		}
		return artifacts, audits
	}
	for _, scenario := range []string{"success", "changed-name", "changed-definition", "withdraw-sharing", "deleted", "canceled", "render-failed", "audit-failed"} {
		t.Run(scenario, func(t *testing.T) {
			id := uuid(t)
			for _, tenant := range tenants {
				create(tenant, id)
			}
			if scenario == "audit-failed" {
				fault := "report_publication_" + strings.ReplaceAll(uuid(t), "-", "")
				if _, err := db.Pool().Exec(ctx, `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='`+tenants[0]+`'::uuid AND NEW.action='dashboard.report_export' THEN RAISE EXCEPTION 'QA report audit refused'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := db.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`() `); err != nil {
						t.Error("report audit fault cleanup failed")
					}
				})
			}
			_, before := counts(tenants[0], id)
			renderContext, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			calls := 0
			render := func(ctx context.Context, format string, document reporting.Document) ([]byte, string, error) {
				calls++
				if document.TenantScope != tenants[0] || document.Title != "Publication "+tenants[0] {
					t.Fatal("rendering received a foreign or changed capture")
				}
				databaseContext, stop := context.WithTimeout(ctx, time.Second)
				defer stop()
				if err := mutate(databaseContext, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
					// Even the successful case must acquire the only connection.
					if _, err := sc.Q.Exec(ctx, `SELECT 1`); err != nil {
						return err
					}
					var sql string
					switch scenario {
					case "changed-name":
						sql = `UPDATE dashboard_views SET name='changed without a timestamp bump' WHERE tenant_id=$1 AND id=$2`
					case "changed-definition":
						sql = `UPDATE dashboard_views SET definition=definition || '{"metrics":{"Current count":"99"}}'::jsonb WHERE tenant_id=$1 AND id=$2`
					case "withdraw-sharing":
						sql = `UPDATE dashboard_views SET shared=false WHERE tenant_id=$1 AND id=$2`
					case "deleted":
						sql = `DELETE FROM dashboard_views WHERE tenant_id=$1 AND id=$2`
					}
					if sql != "" {
						_, err := sc.Q.Exec(ctx, sql, tenants[0], id)
						return err
					}
					return nil
				}); err != nil {
					return nil, "", err
				}
				if scenario == "canceled" {
					cancel()
				}
				if scenario == "render-failed" {
					return nil, "", errors.New("QA renderer refused")
				}
				return renderReport(format, document)
			}
			artifact, err := core.generateDashboardReport(request(renderContext, tenants[0]), reportGenerateRequest{DashboardID: id, Format: "csv"}, render)
			if calls != 1 {
				t.Fatalf("render calls=%d, want exactly one", calls)
			}
			artifacts, audits := counts(tenants[0], id)
			if scenario == "success" {
				if err != nil || artifact == nil || artifacts != 1 || audits != before+1 || !strings.Contains(string(artifact.Content), tenants[0]) || strings.Contains(string(artifact.Content), tenants[1]) {
					t.Fatalf("single-connection report did not publish exact tenant data and audit: artifact=%v counts=%d/%d error=%v", artifact != nil, artifacts, audits-before, err)
				}
			} else {
				if err == nil || artifact != nil || artifacts != 0 || audits != before {
					t.Fatalf("refused report published artifact or audit: artifact=%v counts=%d/%d error=%v", artifact != nil, artifacts, audits-before, err)
				}
				switch scenario {
				case "changed-name", "changed-definition":
					if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindConflict {
						t.Fatal("changed capture did not return its conflict contract", err)
					}
				case "withdraw-sharing", "deleted":
					if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindNotFound {
						t.Fatal("hidden/deleted capture did not preserve not-found semantics", err)
					}
				case "canceled":
					if !errors.Is(err, context.Canceled) {
						t.Fatal("canceled renderer published or lost cancellation", err)
					}
				}
			}
			// The equal dashboard ID in another tenant remains unchanged and
			// usable even after tenant A's mutation or publication failure.
			sibling, err := core.generateDashboardReport(request(ctx, tenants[1]), reportGenerateRequest{DashboardID: id, Format: "csv"}, renderDashboardReport)
			if err != nil || sibling == nil || !strings.Contains(string(sibling.Content), tenants[1]) || strings.Contains(string(sibling.Content), tenants[0]) {
				t.Fatal("publication refusal or row lock affected the sibling tenant", err)
			}
		})
	}
	id := uuid(t)
	create(tenants[0], id)
	for _, candidate := range []string{id, uuid(t)} {
		calls := 0
		render := func(ctx context.Context, format string, document reporting.Document) ([]byte, string, error) {
			calls++
			return renderDashboardReport(ctx, format, document)
		}
		out, err := core.generateDashboardReport(request(ctx, tenants[1]), reportGenerateRequest{DashboardID: candidate, Format: "csv"}, render)
		if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindNotFound || out != nil || calls != 0 {
			t.Fatal("foreign/missing report source reached rendering or disclosed data", err)
		}
	}
}
