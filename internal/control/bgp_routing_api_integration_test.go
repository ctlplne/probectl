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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Certificate-verified HTTPS, actual bearer/current grants, application-role
// Postgres/FORCE-RLS and durable audit. Router identities are registry fixtures;
// this does not claim a physical BMP sender or route/flow attribution proof.
func TestBGPRoutingConfigurationAPIKeepsTenantCurrentActorEpochAndAtomicAudit(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	cfg := f.pool.Config().Copy()
	cfg.MaxConns, cfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.server.pool = pool
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	path := "/v1/entity-contexts/" + f.contextID + "/bgp-routing-bindings"
	getPath := path + "?collector_agent_id=role-listener&source_ref=role-router"
	request := func(lane int, method, path string, input any) (int, []byte) {
		t.Helper()
		var body []byte
		if input != nil {
			var err error
			body, err = json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, socket.URL+path, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[f.tenants[lane]])
		req.Header.Set("Content-Type", "application/json")
		res, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, raw
	}
	target, router := uuid.NewString(), uuid.NewString()
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'mapped-target','routed')`, tenant, target); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','mapped-router')`, tenant, target, router)
			return err
		})
	}
	epoch := ""
	bindings := []store.BGPRoutingBinding{{ContextID: target, RouterID: router, Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{2, 1}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1}}
	input := bgpRoutingBindingsInput{CollectorAgentID: "role-listener", SourceRef: "role-router", ExpectedEpoch: &epoch, Bindings: &bindings}
	current := make([]store.BGPRoutingBindingConfiguration, 2)
	for lane := range f.tenants {
		status, body := request(lane, http.MethodGet, getPath, nil)
		var legacy store.BGPRoutingBindingConfiguration
		if status != http.StatusOK || json.Unmarshal(body, &legacy) != nil || legacy.Manifest != nil || legacy.ContextID != f.contextID {
			t.Fatal("served routing source read lost its owned strict default", status, string(body))
		}
		status, body = request(lane, http.MethodPut, path, input)
		if status != http.StatusOK || json.Unmarshal(body, &current[lane]) != nil || current[lane].Manifest == nil || len(current[lane].Manifest.Bindings) != 1 || current[lane].Manifest.Bindings[0].SourceFormat != store.BGPRoutingSourceFRRLocRIBV1 || current[lane].Manifest.Bindings[0].ID == "" {
			t.Fatal("served complete routing binding lost canonical owned metadata", status, string(body))
		}
		if status, _ := request(lane, http.MethodPut, path, input); status != http.StatusConflict {
			t.Fatal("served stale epoch replaced routing source configuration", status)
		}
	}
	for lane := range f.tenants {
		status, body := request(lane, http.MethodGet, getPath, nil)
		var got store.BGPRoutingBindingConfiguration
		if status != http.StatusOK || json.Unmarshal(body, &got) != nil || got.Manifest == nil || got.Manifest.Epoch != current[lane].Manifest.Epoch || got.Manifest.Epoch == current[1-lane].Manifest.Epoch {
			t.Fatal("identical served source keys borrowed another tenant epoch", status, string(body))
		}
	}
	policyID := ""
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny-mapped-routing-context", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"site_label": "mapped-target"}, Priority: 100})
		policyID = policy.ID
		return err
	})
	if status, _ := request(0, http.MethodGet, getPath, nil); status != http.StatusForbidden {
		t.Fatal("served routing read bypassed current mapped-context policy", status)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='abac.denied' AND target='entities.read'`).Scan(&count); err != nil || count != 1 {
			t.Fatal("scoped routing denial was unaudited or acquired a second held connection", count, err)
		}
		return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
	})
	fault := "probectl_qa_beta_routing_audit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := f.pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION public.%s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='%s'::uuid AND NEW.action='bgp.routing_bindings.replaced' THEN RAISE EXCEPTION 'owned QA routing audit refused'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.%s()`, fault, f.tenants[0], fault, fault)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`()`); err != nil {
			t.Error(err)
		}
	})
	epoch = current[0].Manifest.Epoch
	bindings = []store.BGPRoutingBinding{}
	if status, _ := request(0, http.MethodPut, path, input); status < 400 {
		t.Fatal("routing audit failure committed a source replacement", status)
	}
	status, body := request(0, http.MethodGet, getPath, nil)
	var after store.BGPRoutingBindingConfiguration
	if status != http.StatusOK || json.Unmarshal(body, &after) != nil || after.Manifest == nil || after.Manifest.Epoch != epoch || len(after.Manifest.Bindings) != 1 {
		t.Fatal("failed routing audit changed configuration epoch or whole bindings", status, string(body))
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='agent.write'`, f.tenants[0], f.roles[f.tenants[0]])
		return err
	})
	if status, _ := request(0, http.MethodPut, path, input); status != http.StatusForbidden {
		t.Fatal("revoked current writer retained routing configuration authority", status)
	}
}
