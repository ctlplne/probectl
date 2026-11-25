// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPSASyncKeepsInventoryAndAuditInTenant(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	alpha, beta := uuid.NewString(), uuid.NewString()
	contextID := uuid.NewString()
	devices := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	seedBillableInventory(t, pool, alpha, contextID, devices, 1, 2)
	seedBillableInventory(t, pool, beta, contextID, devices, 2, 1)
	seedRevokedPSAAgent(t, pool, alpha)

	type account struct {
		mapping HaloSubscriptions
		counts  map[int32]int64
		writes  int
	}
	accounts := map[string]*account{
		"alpha": {mapping: HaloSubscriptions{7, 12, 13}, counts: map[int32]int64{12: 0, 13: 0}},
		"beta":  {mapping: HaloSubscriptions{8, 22, 23}, counts: map[int32]int64{22: 0, 23: 0}},
	}
	var traffic atomic.Int32
	var mu sync.Mutex
	halo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traffic.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/auth/token" && r.Method == http.MethodPost {
			if r.ParseForm() == nil {
				name := r.PostForm.Get("client_id")
				if accounts[name] != nil && r.PostForm.Get("client_secret") == name+"-fixture" {
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": name, "token_type": "Bearer", "expires_in": 3600})
					return
				}
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		name, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		a := accounts[name]
		if a == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			for id, count := range a.counts {
				if r.URL.Path == "/api/SoftwareLicence/"+strconv.FormatInt(int64(id), 10) {
					_ = json.NewEncoder(w).Encode(haloSubscription{ID: id, Customer: a.mapping.CustomerID, Type: haloUsageSubscription, Count: &count})
					return
				}
			}
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/SoftwareLicence" {
			var updates []haloQuantityWrite
			if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, line := range updates {
				if _, own := a.counts[line.ID]; !own {
					t.Error("a write used another tenant's subscription")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				a.counts[line.ID] = line.Count
			}
			a.writes++
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(halo.Close)

	var enabled atomic.Bool
	mappings := []haloBillingRoute{
		{Tenant: alpha, Origin: halo.URL, HaloSubscriptions: accounts["alpha"].mapping,
			HaloCredentials: notify.HaloCredentials{ClientID: "alpha", ClientSecret: "alpha-fixture"}},
		{Tenant: beta, Origin: halo.URL, HaloSubscriptions: accounts["beta"].mapping,
			HaloCredentials: notify.HaloCredentials{ClientID: "beta", ClientSecret: "beta-fixture"}},
	}
	raw, err := json.Marshal(mappings)
	if err != nil {
		t.Fatal(err)
	}
	syncer, err := NewPSASync(PSAConfigurations{Halo: raw}, pool, enabled.Load, slog.New(slog.NewTextHandler(io.Discard, nil)), halo.Client())
	if err != nil {
		t.Fatal(err)
	}
	syncer.reconcile(t.Context())
	if traffic.Load() != 0 {
		t.Fatal("read-only entitlement reached the vendor")
	}
	enabled.Store(true)
	for _, route := range syncer.routes {
		if err := route.run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	syncer.reconcile(t.Context())
	mu.Lock()
	if accounts["alpha"].writes != 1 || accounts["alpha"].counts[12] != 1 || accounts["alpha"].counts[13] != 2 ||
		accounts["beta"].writes != 1 || accounts["beta"].counts[22] != 2 || accounts["beta"].counts[23] != 1 {
		t.Error("the two tenants' inventory, credentials or subscriptions crossed")
	}
	mu.Unlock()

	for _, expected := range []struct {
		id      string
		devices string
		agents  string
	}{{alpha, "1", "2"}, {beta, "2", "1"}} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(expected.id))
		err := tenancy.InTenant(ctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
			var devices, agents, outcome string
			var attempted, completed int64
			err := scope.Q.QueryRow(ctx, `
SELECT request.data->>'devices', request.data->>'agents',
       result.data->>'outcome', request.seq, result.seq
  FROM audit_events request JOIN audit_events result ON result.tenant_id=request.tenant_id
   AND result.data->>'request_seq'=request.seq::text
 WHERE request.action='billing.psa.sync.requested' AND result.action='billing.psa.sync.result'`).
				Scan(&devices, &agents, &outcome, &attempted, &completed)
			if err != nil {
				return err
			}
			if devices != expected.devices || agents != expected.agents || outcome != "confirmed" || attempted >= completed {
				return fmt.Errorf("the tenant audit contains invalid quantities or sequence")
			}
			var receipts int
			err = scope.Q.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action LIKE 'billing.psa.sync.%'").Scan(&receipts)
			if err == nil && receipts != 2 {
				return fmt.Errorf("readback change/no-op recorded %d entries instead of two", receipts)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func seedRevokedPSAAgent(t *testing.T, pool *pgxpool.Pool, tenant string) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	agentID := uuid.NewString()
	spiffeID := crypto.AgentSPIFFEID(tenant, agentID)
	if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := (store.Agents{}).Reserve(ctx, scope, agentID, agentID, "", "", spiffeID, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	identities := store.NewAgentIdentities(pool)
	if err := identities.Record(ctx, tenant, agentID, spiffeID, strings.ReplaceAll(agentID, "-", ""), time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identities.RevokeAgent(ctx, tenant, agentID, "billing-fixture-operator"); err != nil {
		t.Fatal(err)
	}
}

func seedBillableInventory(t *testing.T, pool *pgxpool.Pool, tenant, contextID string, devices []string, monitored, agents int) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,slug,name) VALUES ($1::uuid,$1::uuid::text,$1::uuid::text)", tenant); err != nil {
		t.Fatal(err)
	}
	seedBillableInventoryRows(t, pool, tenant, contextID, devices, monitored, agents)
}

func seedBillableInventoryRows(t *testing.T, pool *pgxpool.Pool, tenant, contextID string, devices []string, monitored, agents int) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
		if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_contexts
(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
VALUES ($1,$2,$2,$2,'site','vrf')`, tenant, contextID); err != nil {
			return err
		}
		for _, deviceID := range devices {
			if _, err := scope.Q.Exec(ctx, `INSERT INTO entities
(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device','fixture')`, tenant, contextID, deviceID); err != nil {
				return err
			}
		}
		for n := range agents {
			agent := uuid.NewString()
			if _, err := scope.Q.Exec(ctx, "INSERT INTO agents(id,tenant_id,name,status) VALUES ($1::uuid,$2,$1::uuid::text,'offline')", agent, tenant); err != nil {
				return err
			}
			if _, err := scope.Q.Exec(ctx, "INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)", tenant, agent, contextID); err != nil {
				return err
			}
			for _, id := range devices[:monitored] {
				if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_source_contexts
(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES ($1,$2,'device_target',$3::uuid::text,$4,$3::uuid)`,
					tenant, agent, id, contextID); err != nil {
					return err
				}
			}
			if n == 0 {
				if _, err := scope.Q.Exec(ctx, `INSERT INTO entity_source_contexts
(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id,assigned_at,expires_at)
VALUES ($1,$2,'device_target',$3::uuid::text,$4,$3::uuid,now()-interval '2 hours',now()-interval '1 hour')`,
					tenant, agent, devices[len(devices)-1], contextID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
