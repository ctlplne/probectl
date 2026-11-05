// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real managed Postgres silo, verified TLS and current bearer-user grants.
// Hold the context row before a policy write reaches its first policy query:
// both role tables must already have real PostgreSQL relation locks, rather
// than relying on a table existence check or on the later policy statement.
func TestInterfaceRoleAPIKeepsSiloRelationsLockedBeforeConfigurationSQL(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := t.Context()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	stamp := fmt.Sprint(time.Now().UnixNano())
	a := mkTenant(t, pool, "role-silo-a-"+stamp, "siloed", "")
	b := mkTenant(t, pool, "role-pooled-b-"+stamp, "pooled", "")
	if err := prov.Provision(ctx, a, "", tenancy.IsolationSiloed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := prov.Teardown(context.Background(), a, "", tenancy.IsolationSiloed); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM public.tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Error(err)
		}
	})
	previous := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(previous); tenancy.SetSiloRequiredTables(nil) })
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))
	required, err := RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)
	newID := func() string {
		t.Helper()
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	contextID, siteID, vrfID := newID(), newID(), newID()
	schema := SchemaName(a)
	seedContext := func(target, tenant string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO `+pgx.Identifier{target, "entity_contexts"}.Sanitize()+`(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'owned','private')`, tenant, contextID, siteID, vrfID); err != nil {
			t.Fatal(err)
		}
	}
	seedContext(schema, a)
	seedContext("public", a)
	seedContext("public", b)
	shadowID := newID()
	if _, err := pool.Exec(ctx, `INSERT INTO public.interface_role_policies(tenant_id,context_id,id,definition) VALUES($1,$2,$3,'{"provider_asns":[64512],"customer_asns":[],"description_rules":[]}'::jsonb)`, a, contextID, shadowID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.interface_role_policies(tenant_id,context_id,id,definition) VALUES($1,$2,$3,'{"provider_asns":[64496],"customer_asns":[],"description_rules":[]}'::jsonb)`, b, contextID, newID()); err != nil {
		t.Fatal(err)
	}
	identity := func(tenant string) string {
		t.Helper()
		var userID string
		err := tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), pool, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "writer@"+tenant+".example.test", "Role writer")
			if err != nil {
				return err
			}
			userID = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "role-config-writer", "Role configuration writer", "Owned isolation fixture")
			if err != nil {
				return err
			}
			for _, permission := range []string{"entities.read", "agent.write"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID)
		})
		if err != nil {
			t.Fatal(err)
		}
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(pool).CreateWithLifetime(ctx, tenant, userID, "role-silo-fixture", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		return token
	}
	tokenA, tokenB := identity(a), identity(b)
	cfg := &config.Config{AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour}
	server := control.New(cfg, log, pool, pool, nil, nil).WithTenantStatus(control.NewTenantStatusCache(pool, 0))
	socket := httptest.NewTLSServer(server.Handler())
	t.Cleanup(socket.Close)
	path := "/v1/entity-contexts/" + contextID + "/interface-role-policy"
	read := func(token string) entity.InterfaceRolePolicyRecord {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, socket.URL+path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var out entity.InterfaceRolePolicyRecord
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&out) != nil {
			t.Fatal("owned real-token policy read failed", response.StatusCode)
		}
		return out
	}
	if initial := read(tokenA); initial.TenantID != a || initial.ID != "" || initial.Revision != "0" {
		t.Fatal("silo policy read reached the pooled shadow")
	}
	if own := read(tokenB); own.TenantID != b || len(own.Definition.ProviderASNs) != 1 || own.Definition.ProviderASNs[0] != 64496 {
		t.Fatal("pooled tenant policy reached the silo")
	}
	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT id FROM `+pgx.Identifier{schema, "entity_contexts"}.Sanitize()+` WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, a, contextID); err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw := []byte(`{"expected_id":"","expected_revision":"0","definition":{"provider_asns":[64500],"customer_asns":[],"description_rules":[]}}`)
	request, _ := http.NewRequestWithContext(requestCtx, http.MethodPut, socket.URL+path, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+tokenA)
	request.Header.Set("Content-Type", "application/json")
	type publication struct {
		status int
		record entity.InterfaceRolePolicyRecord
		err    error
	}
	done := make(chan publication, 1)
	go func() {
		response, err := socket.Client().Do(request)
		if err != nil {
			done <- publication{err: err}
			return
		}
		defer response.Body.Close()
		var record entity.InterfaceRolePolicyRecord
		err = json.NewDecoder(response.Body).Decode(&record)
		done <- publication{status: response.StatusCode, record: record, err: err}
	}()
	var pid int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(ctx, `SELECT COALESCE(min(pid),0) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT 1 FROM entity_contexts%FOR UPDATE'`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		if pid != 0 {
			break
		}
		select {
		case result := <-done:
			t.Fatal("role request completed before the owned context lock", result.status, result.err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if pid == 0 {
		t.Fatal("role write never reached its current owned context lock")
	}
	for _, table := range []string{"interface_role_policies", "interface_role_overrides"} {
		var held bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation=to_regclass($2) AND mode='AccessShareLock' AND granted)`, pid, pgx.Identifier{schema, table}.Sanitize()).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if !held {
			t.Fatal("role transaction left an unvisited silo configuration table unlocked", table)
		}
	}
	ddl, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ddl.Exec(ctx, `SET LOCAL lock_timeout='200ms'`); err != nil {
		_ = ddl.Rollback(ctx)
		t.Fatal(err)
	}
	_, dropErr := ddl.Exec(ctx, `DROP TABLE `+pgx.Identifier{schema, "interface_role_policies"}.Sanitize())
	_ = ddl.Rollback(ctx)
	var pgErr *pgconn.PgError
	if !errors.As(dropErr, &pgErr) || pgErr.Code != "55P03" {
		t.Fatal("in-flight role transaction did not block its silo table drop", dropErr)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil || result.status != http.StatusOK || result.record.TenantID != a || result.record.ID == shadowID || result.record.Revision != "1" || len(result.record.Definition.ProviderASNs) != 1 || result.record.Definition.ProviderASNs[0] != 64500 {
		t.Fatal("audited role publication crossed the physical silo", result.status, result.err)
	}
	var untouched string
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT id::text,revision FROM public.interface_role_policies WHERE tenant_id=$1 AND context_id=$2`, a, contextID).Scan(&untouched, &revision); err != nil || untouched != shadowID || revision != 1 {
		t.Fatal("role write changed pooled shadow state", err)
	}
	if own := read(tokenB); own.TenantID != b || len(own.Definition.ProviderASNs) != 1 || own.Definition.ProviderASNs[0] != 64496 {
		t.Fatal("silo write changed the other tenant's policy")
	}
}
