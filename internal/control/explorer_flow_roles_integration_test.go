// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type rolePublicationFlowStore struct {
	*flowstore.Memory
	mutate func()
}

func (s *rolePublicationFlowStore) ExplorePlan(ctx context.Context, query flowstore.PlanQuery) (flowstore.PlanResult, error) {
	result, err := s.Memory.ExplorePlan(ctx, query)
	if err == nil && s.mutate != nil {
		mutate := s.mutate
		s.mutate = nil
		mutate()
	}
	return result, err
}

// Actual application-role Postgres/current bearer and verified TLS; sender
// identities are seeded and flow execution is the memory simulation. Actual
// ClickHouse, frozen objects, native protocol and router wire remain separate.
func TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := &rolePublicationFlowStore{Memory: flowstore.NewMemory()}
	f.server.WithFlowStore(rows)
	actors := map[string]*auth.Principal{}
	for _, tenant := range f.tenants {
		const agent, address = "role-flow", "192.0.2.1"
		serial := strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant, agent, f.contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'flow_exporter',$3,$4,$5)`, tenant, agent, address, f.contextID, f.routerID); err != nil {
				return err
			}
			for _, permission := range []string{"ai.query", "flow.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: f.users[tenant], ViaBearerToken: true}, grants)
			return err
		})
		claim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter, SourceRef: address}, Alias: entity.AliasKey{Kind: entity.FlowExporterAlias, Value: address + "/ipfix/4294967295"}, SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
		accepted, unresolved, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agent, serial, []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("owned flow observation was not accepted", accepted, unresolved, err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRoleBackbone)
		return err
	})
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := rows.Insert(t.Context(), []flowstore.Row{
		{TenantID: a, TS: at, AgentID: "forged-other-context", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: 4294967295, InIf: 7, OutIf: 99, BytesScaled: 100},
		{TenantID: a, TS: at, Exporter: "192.0.2.2", Protocol: "ipfix", ObsDomain: 4294967295, InIf: 7, OutIf: 99, BytesScaled: 200},
		{TenantID: b, TS: at, AgentID: "forged-other-context", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: 4294967295, InIf: 7, OutIf: 99, BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &plan}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	read := func(tenant string) (int, explorerResult) {
		t.Helper()
		body, err := json.Marshal(query)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/explorer/query", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var out explorerResult
		if response.StatusCode == http.StatusOK && json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid served role query", string(raw))
		}
		if response.StatusCode != http.StatusOK {
			t.Log("served role status", response.StatusCode, string(raw))
		}
		return response.StatusCode, out
	}
	code, first := read(a)
	if code != http.StatusOK || first.Flow == nil || first.Flow.Totals["bytes:total"] != "300" || first.Flow.RoleTenantID != a || len(first.Flow.RoleSources) != 1 {
		t.Fatal("served role query lost complete owned tenant inputs", code, first.Flow)
	}
	groups := map[string]string{}
	for _, item := range first.Flow.Rows {
		groups[item.Group["in_if_role"]+"/"+item.Group["out_if_role"]] = item.Metrics["bytes:total"]
	}
	if groups["transit/other"] != "100" || groups["other/other"] != "200" {
		t.Fatal("served role query changed exact totals or chose forged agent", groups)
	}
	if code, out := read(b); code != http.StatusOK || out.Flow == nil || out.Flow.Totals["bytes:total"] != "900" || out.Flow.Rows[0].Group["in_if_role"] != "backbone" {
		t.Fatal("paired tenant lost its independent same-index role", code, out.Flow)
	}
	ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(a)), actors[a])
	source := &flowSnapshotSource{server: f.server, now: time.Now}
	proof := flowSnapshotValidity{Inputs: []flowstore.SnapshotInputs{{Fields: []string{"in_if_role", "out_if_role"}}}, RoleDigest: first.Flow.RoleDigest}
	scope := flowsnapshot.Scope{TenantID: a, Owner: f.users[a]}
	if err := source.validateRoleAuthorization(ctx, scope, proof); err != nil {
		t.Fatal("current role receipt was not readable", err)
	}
	rows.mutate = func() { f.peer(a, 64500) }
	if code, _ := read(a); code != http.StatusServiceUnavailable {
		t.Fatal("role query published stale source metadata after computation", code)
	}
	if err := source.validateRoleAuthorization(ctx, scope, proof); err == nil {
		t.Fatal("old frozen role source identity survived reclassification")
	}
	f.peer(a, 64496)
	for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
			return err
		})
		if code, _ := read(a); code != http.StatusForbidden {
			t.Fatal("served role query ignored a current source grant withdrawal", permission, code)
		}
		if _, err := f.server.recordFlowSpec(ctx, a, plan, nil); err == nil {
			t.Fatal("stale native principal retained role source access", permission)
		}
		if err := source.validateRoleAuthorization(ctx, scope, proof); err == nil {
			t.Fatal("frozen role result ignored a current source grant withdrawal", permission)
		}
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
	saveCompleteRoleExplanationPolicy(f, a)
	code, complete := read(a)
	if code != http.StatusOK || complete.Flow == nil || complete.Flow.Totals["bytes:total"] != "300" || len(complete.Flow.RoleSources) != 1 || complete.Flow.RoleSources[0].Role != entity.InterfaceRoleBackbone || complete.Flow.RoleSources[0].Reason != "description_rule" {
		t.Fatal("complete saved policy cannot drive role flow queries under the default profile", code, complete.Flow)
	}
	if code, out := read(b); code != http.StatusOK || out.Flow == nil || out.Flow.Rows[0].Group["in_if_role"] != "backbone" {
		t.Fatal("tenant refusal damaged another tenant's role", code)
	}
}
