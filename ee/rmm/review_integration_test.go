// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package rmm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestRMMSyncPublishesOnlyOwnedReviewCandidates(t *testing.T) {
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	provisioner := silo.NewProvisioner(pool, silo.CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	previousRouter := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(previousRouter); tenancy.SetSiloRequiredTables(nil) })
	router := silo.NewRouter(pool, nil, 0)
	tenancy.SetRouter(router)
	required, err := silo.RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)
	contextID, otherContext := uuid.NewString(), uuid.NewString()
	newOwner := func(model tenancy.IsolationModel, contexts ...string) (context.Context, tenancy.ID) {
		t.Helper()
		var tenant string
		if err := pool.QueryRow(ctx, `INSERT INTO tenants (slug,name,isolation_model)
			VALUES ($1,'RMM review lab',$2) RETURNING id::text`, "rmm-review-"+uuid.NewString(), model).Scan(&tenant); err != nil {
			t.Fatal(err)
		}
		router.Invalidate()
		t.Cleanup(func() {
			if err := provisioner.Teardown(context.Background(), tenant, "", model); err != nil {
				t.Error(err)
			}
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant); err != nil {
				t.Error(err)
			}
		})
		if model == tenancy.IsolationSiloed {
			if err := provisioner.Provision(ctx, tenant, "", model); err != nil {
				t.Fatal(err)
			}
			table := pgx.Identifier{silo.SchemaName(tenant), "nms_import_sources"}.Sanitize()
			// Exercise catch-up from a silo created before discovery imports.
			if _, err := pool.Exec(ctx, "ALTER TABLE "+table+` DROP CONSTRAINT nms_import_sources_source_kind_check,
				ADD CONSTRAINT nms_import_sources_source_kind_check
				CHECK (source_kind IN ('librenms','zabbix','orion','prtg','sightline','defenseflow'))`); err != nil {
				t.Fatal(err)
			}
			if err := provisioner.CatchUpSchema(ctx, tenant); err != nil {
				t.Fatal(err)
			}
		}
		id := tenancy.ID(tenant)
		owner := tenancy.WithTenant(ctx, id)
		err := tenancy.InTenant(owner, pool, func(ctx context.Context, sc tenancy.Scope) error {
			for _, routingContext := range contexts {
				vrf := "Private"
				if routingContext == otherContext {
					vrf = "Other"
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
					(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
					VALUES ($1,$2,$3,$4,'Lab',$5)`, id.String(), routingContext,
					uuid.NewString(), uuid.NewString(), vrf); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return owner, id
	}
	alpha, tenantA := newOwner(tenancy.IsolationPooled, contextID, otherContext)
	beta, tenantB := newOwner(tenancy.IsolationSiloed, contextID)
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		hostname := map[string]string{
			"Bearer first.fixture": "alpha.lab", "Bearer second.fixture": "beta.lab",
		}[r.Header.Get("Authorization")]
		if r.Method != http.MethodGet || r.URL.Path != "/api/v2/site/same-site/devices" || hostname == "" {
			t.Error("inventory request left its configured site or credential")
			http.Error(w, "invalid fixture request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pageDetails": map[string]any{"nextPageUrl": nil},
			"devices": []map[string]string{{
				"siteUid": "same-site", "uid": "same-device", "hostname": hostname, "intIpAddress": "192.0.2.10",
			}},
		})
	}))
	t.Cleanup(server.Close)
	routes, err := json.Marshal([]inventoryRoute{
		{SiteMapping: fixtureSite(tenantA, contextID, Site{Vendor: DattoRMM, Account: "first", ID: "same-site"}),
			Alias: "first", Origin: server.URL, CredentialRef: "env:RMM_FIRST_FIXTURE"},
		{SiteMapping: fixtureSite(tenantB, contextID, Site{Vendor: DattoRMM, Account: "second", ID: "same-site"}),
			Alias: "second", Origin: server.URL, CredentialRef: "env:RMM_SECOND_FIXTURE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var resolutions int
	resolver := credentialResolverFunc(func(ctx context.Context, ref string) ([]byte, func(), error) {
		resolutions++
		tenant, _ := tenancy.FromContext(ctx)
		switch {
		case tenant == tenantA && ref == "env:RMM_FIRST_FIXTURE":
			return []byte(`{"access_token":"first.fixture"}`), func() {}, nil
		case tenant == tenantB && ref == "env:RMM_SECOND_FIXTURE":
			return []byte(`{"access_token":"second.fixture"}`), func() {}, nil
		default:
			t.Fatal("inventory requested a credential outside its tenant")
			return nil, nil, nmsimport.ErrSourceUnavailable
		}
	})
	syncer, err := NewInventorySync(routes, resolver, func() bool { return true }, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	var denySeal bool
	var rejectedID string
	denied := errors.New("audit append refused")
	capture := nmsimport.NewCaptureStore(pool, func(_ context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
		if data["context_id"] != contextID || (sc.Tenant != tenantA && sc.Tenant != tenantB) {
			return errors.New("audit scope changed")
		}
		if denySeal && action == "nms_import.capture_sealed" {
			rejectedID = target
			return denied
		}
		return nil
	})
	for _, attempt := range []struct {
		owner context.Context
		scope string
		alias string
	}{{alpha, contextID, "second"}, {beta, contextID, "first"}, {alpha, otherContext, "first"}} {
		if _, err := syncer.Start(attempt.owner, attempt.scope, attempt.alias, capture); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatal("a foreign site or context was accepted", err)
		}
	}
	if resolutions != 0 || reads.Load() != 0 {
		t.Fatal("a foreign site or context reached credentials or the inventory reader")
	}
	denySeal = true
	if _, err := syncer.Start(alpha, contextID, "first", capture); !errors.Is(err, denied) || rejectedID == "" {
		t.Fatal("publication did not roll back after a failed audit", err)
	}
	if _, err := capture.ListSealedRows(alpha, contextID, rejectedID, -1, 10); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatal("failed audit left a visible plan", err)
	}
	denySeal = false

	var plans []nmsimport.DiscoveryPlan
	for _, owned := range []struct {
		owner           context.Context
		alias, hostname string
	}{{alpha, "first", "alpha.lab"}, {beta, "second", "beta.lab"}} {
		plan, err := syncer.Start(owned.owner, contextID, owned.alias, capture)
		if err != nil || plan.ContextID != contextID || plan.RowCount != 1 {
			t.Fatal("owned inventory was not published", err)
		}
		rows, err := capture.ListSealedRows(owned.owner, contextID, plan.PlanID, -1, 10)
		if err != nil || rows.SnapshotHash != plan.SnapshotHash || len(rows.Items) != 1 ||
			rows.Items[0].Hostname != owned.hostname || rows.Items[0].Reviewed ||
			rows.Items[0].Action != "captured" || rows.Items[0].TargetID != "" {
			t.Fatal("published row was reviewed, activated, or crossed the tenant boundary", err)
		}
		if _, err := capture.FinalizeReview(owned.owner, contextID, plan.PlanID, plan.SnapshotHash); err == nil {
			t.Fatal("review finalized without an operator choice")
		}
		plans = append(plans, plan)
	}
	if resolutions != 3 || reads.Load() != 3 {
		t.Fatal("each owned sync must resolve one credential and read one complete site page")
	}
	for _, attempt := range []struct {
		owner context.Context
		scope string
		plan  nmsimport.DiscoveryPlan
	}{{alpha, contextID, plans[1]}, {beta, contextID, plans[0]}, {alpha, otherContext, plans[0]}} {
		if _, err := capture.ListSealedRows(attempt.owner, attempt.scope, attempt.plan.PlanID, -1, 10); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatal("a foreign sealed inventory was visible", err)
		}
		if err := capture.SetReviewChoices(attempt.owner, attempt.scope, attempt.plan.PlanID, attempt.plan.SnapshotHash,
			[]nmsimport.ReviewChoice{{RowNumber: 0, Action: "create"}}); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatal("a foreign plan accepted review choices", err)
		}
	}
}
