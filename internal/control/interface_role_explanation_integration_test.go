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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real Postgres/FORCE-RLS and actual evidence/configuration writers. Issued
// sender identities and fault receipts are seeded; transport and real routers
// remain separate required integration proof, not claimed by this fixture.
type roleExplanationAPIFixture struct {
	t                                             *testing.T
	pool                                          *pgxpool.Pool
	server                                        *Server
	tokens, users, roles                          map[string]string
	tenants                                       []string
	contextID, routerID, interfaceID, otherRouter string
	serials                                       map[string]string
}

func newRoleExplanationAPIFixture(t *testing.T) *roleExplanationAPIFixture {
	t.Helper()
	_, db := setupAPIServerWithLatest(t, nil)
	pool := db.Pool()
	cfg := &config.Config{AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour}
	srv := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), db, pool, nil, nil).WithTenantStatus(NewTenantStatusCache(pool, 0))
	testsupport.LockPostgresPublicCatalog(t, pool)
	f := &roleExplanationAPIFixture{t: t, pool: pool, server: srv, tokens: map[string]string{}, users: map[string]string{}, roles: map[string]string{}, contextID: gouuid.NewString(), routerID: gouuid.NewString(), interfaceID: gouuid.NewString(), otherRouter: gouuid.NewString(), serials: map[string]string{}}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, f.tenants); err != nil {
			t.Error(err)
		}
	})
	for lane := range 2 {
		tenant, err := store.NewTenants(pool).Create(t.Context(), fmt.Sprintf("role-inputs-%d-%d", lane, time.Now().UnixNano()), "Role inputs")
		if err != nil {
			t.Fatal(err)
		}
		f.tenants = append(f.tenants, tenant.ID)
		for _, agent := range []string{"role-snmp", "role-listener", "role-router"} {
			serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
			spiffe := crypto.EntitySPIFFEID(tenant.ID, agent)
			if agent == "role-router" {
				spiffe = crypto.BMPSPIFFEID(tenant.ID, agent)
			}
			if err := store.NewAgentIdentities(pool).Record(t.Context(), tenant.ID, agent, spiffe, serial, time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
			f.serials[tenant.ID+agent] = serial
		}
		f.in(tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'owned','private')`, tenant.ID, f.contextID, gouuid.NewString(), gouuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','router'),($1,$2,$4,'device','other')`, tenant.ID, f.contextID, f.routerID, f.otherRouter); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index) VALUES($1,$2,$3,'interface','canonical',$4,'role-snmp','192.0.2.1',7)`, tenant.ID, f.contextID, f.interfaceID, f.routerID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'role-snmp',$2),($1,'role-listener',$2)`, tenant.ID, f.contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'role-snmp','device_target','192.0.2.1',$2,$3),($1,'role-listener','bmp_peer','role-router',$2,$3)`, tenant.ID, f.contextID, f.routerID); err != nil {
				return err
			}
			_, err := (store.InterfaceRoleConfiguration{}).PutPolicy(ctx, sc, f.contextID, "", "0", entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{64496 + uint32(lane)}, CustomerASNs: []uint32{64500}}, roleExplanationStoreBudget())
			return err
		})
		f.poll(tenant.ID, fmt.Sprintf("owned-%d", lane), roleExplanationPrefixes())
		f.peer(tenant.ID, 64496+uint32(lane))
		f.in(tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "roles@"+tenant.ID+".invalid", "Role reader")
			if err != nil {
				return err
			}
			f.users[tenant.ID] = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "role-explain-reader", "Role reader", "Served role proof")
			if err != nil {
				return err
			}
			f.roles[tenant.ID] = role.ID
			for _, permission := range []string{"entities.read", "metrics.read", "events.read", "agent.write"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID)
		})
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(pool).CreateWithLifetime(t.Context(), tenant.ID, f.users[tenant.ID], "role-explanation-proof", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		f.tokens[tenant.ID] = token

	}
	return f
}

func roleExplanationStoreBudget() entity.InterfaceRolePolicyBudget {
	return entity.InterfaceRolePolicyBudget{MemoryBytes: 128 << 20, WorkUnits: 64 << 20}
}
func roleExplanationPrefixes() []entity.SNMPInterfacePrefix {
	return []entity.SNMPInterfacePrefix{{IfIndex: 7, Prefix: netip.MustParsePrefix("10.42.0.0/24"), OnLink: true}, {IfIndex: 7, Prefix: netip.MustParsePrefix("2001:db8::/64"), OnLink: true}}
}
func (f *roleExplanationAPIFixture) in(tenant string, fn func(context.Context, tenancy.Scope) error) {
	f.t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), f.pool, fn); err != nil {
		f.t.Fatal(err)
	}
}
func (f *roleExplanationAPIFixture) poll(tenant, description string, prefixes []entity.SNMPInterfacePrefix) string {
	f.t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
	root := gouuid.NewString()
	claims := []entity.Observation{
		{ID: root, Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: at, SNMPInterfacePrefixes: prefixes},
		{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceDescription: description, ObservedAt: at},
		{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at},
	}
	accepted, unresolved, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), source.AgentID, f.serials[tenant+source.AgentID], claims)
	if err != nil || accepted != len(claims) || unresolved != 0 {
		f.t.Fatal("owned complete poll was not accepted", accepted, unresolved, err)
	}
	return root
}
func (f *roleExplanationAPIFixture) peer(tenant string, asn uint32) {
	f.peerAtAddress(tenant, "10.42.0.1", asn)
}
func (f *roleExplanationAPIFixture) peerAtAddress(tenant, address string, asn uint32) {
	f.t.Helper()
	claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-listener", Kind: entity.BMPPeer, SourceRef: "role-router"},
		Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: fmt.Sprintf("%s/as%d", address, asn)}, SourceRef: fmt.Sprintf("bmp:router:role-router:peer-asn:%d", asn), OriginSerial: f.serials[tenant+"role-router"], ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	accepted, unresolved, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), "role-listener", f.serials[tenant+"role-listener"], []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		f.t.Fatal("owned BMP observation was not accepted", accepted, unresolved, err)
	}
}

// Verified TLS, real bearer authentication/current role grants, actual evidence
// writers and application-role RLS. Sender identities are seeded: live mTLS
// sender/router sessions remain separate acceptance, not asserted here.
func TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	path := "/v1/entity-contexts/" + f.contextID + "/interfaces/" + f.interfaceID + "/role"
	request := func(tenant, suffix string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+suffix, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
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
	read := func(tenant string, role entity.InterfaceRole, reason string) interfaceRoleExplanation {
		t.Helper()
		status, raw := request(tenant, path)
		var out interfaceRoleExplanation
		if status != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Scope.TenantID != tenant || out.ContextID != f.contextID || out.InterfaceID != f.interfaceID || out.Role != role || out.Reason != reason || out.Sources == nil {
			t.Fatal("served role explanation lost owned current source or tenant authority", status, string(raw))
		}
		return out
	}
	for _, tenant := range f.tenants {
		out := read(tenant, entity.InterfaceRoleTransit, "current_evidence")
		if !out.SNMPCurrent || !out.PrefixCurrent || len(out.Sources) < 5 {
			t.Fatal("served role explanation lost complete source provenance", out)
		}
		var actor *auth.Principal
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			actor = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: f.users[tenant], ViaBearerToken: true}, grants)
			return err
		})
		raw, err := (mcpInterfaceRoleBackend{server: f.server}).InterfaceRoleConfiguration(t.Context(), actor, "interface_role_explain", mcp.InterfaceRoleCommand{ContextID: f.contextID, InterfaceID: f.interfaceID})
		var native interfaceRoleExplanation
		if err != nil || json.Unmarshal(raw, &native) != nil || native.Role != out.Role || native.Scope != out.Scope || !reflect.DeepEqual(native.Sources, out.Sources) {
			t.Fatal("native role explanation diverged from served authorized operation", err)
		}
		for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permission)
				return err
			})
			if status, raw := request(tenant, path); status != http.StatusForbidden || strings.Contains(string(raw), "current_evidence") {
				t.Fatal("served role explanation accepted a revoked source grant", permission, status)
			}
			if raw, err := (mcpInterfaceRoleBackend{server: f.server}).InterfaceRoleConfiguration(t.Context(), actor, "interface_role_explain", mcp.InterfaceRoleCommand{ContextID: f.contextID, InterfaceID: f.interfaceID}); err == nil || len(raw) != 0 {
				t.Fatal("stale native principal retained revoked current grants", permission)
			}
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission)
			})
			read(tenant, entity.InterfaceRoleTransit, "current_evidence")
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	f.peer(a, 64500)
	read(a, entity.InterfaceRoleCustomer, "current_evidence")
	read(b, entity.InterfaceRoleTransit, "current_evidence")
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRolePrivate)
		return err
	})
	f.poll(a, "withdrawn-prefix", nil)
	out := read(a, entity.InterfaceRolePrivate, "operator_override")
	if out.PrefixCurrent || len(out.Sources) != 1 || !strings.HasPrefix(out.Sources[0], "override/") {
		t.Fatal("owned override fabricated automatic evidence after withdrawal", out)
	}
	read(b, entity.InterfaceRoleTransit, "current_evidence")
	foreign := gouuid.NewString()
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'interface','foreign')`, b, f.contextID, foreign)
		return err
	})
	if status, raw := request(a, strings.Replace(path, f.interfaceID, foreign, 1)); status != http.StatusNotFound || strings.Contains(string(raw), "operator_override") {
		t.Fatal("foreign canonical interface was observable", status)
	}
	if status, _ := request(a, strings.Replace(path, f.interfaceID, f.routerID, 1)); status != http.StatusNotFound {
		t.Fatal("device admitted as interface", status)
	}
	var policyID string
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "role-context-deny", Enabled: true, Effect: auth.PolicyDeny, Permission: "metrics.read", Resource: map[string]string{"site_label": "owned"}, Priority: 100})
		if err == nil {
			policyID = policy.ID
		}
		return err
	})
	if status, _ := request(a, path); status != http.StatusForbidden {
		t.Fatal("current role explanation ignored context source ABAC", status)
	}
	read(b, entity.InterfaceRoleTransit, "current_evidence")
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM abac_policies WHERE tenant_id=$1 AND id=$2`, a, policyID)
		return err
	})
	read(a, entity.InterfaceRolePrivate, "operator_override")
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, a, f.users[a])
		return err
	})
	if status, _ := request(a, path); status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Fatal("disabled user retained role disclosure", status)
	}
	read(b, entity.InterfaceRoleTransit, "current_evidence")
}

// This tracer belongs only to the fixture's pool. Pause BEFORE the second
// snapshot starts; no production hook, artificial source clock or DB mutation
// hidden inside a handler. The mutation commits on the separate fixture pool.
type roleExplanationPublicationTracer struct {
	snapshots atomic.Int32
	entered   chan struct{}
	resume    chan struct{}
}

func (q *roleExplanationPublicationTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.EqualFold(strings.TrimSpace(data.SQL), "begin isolation level repeatable read read only") && q.snapshots.Add(1) == 2 {
		close(q.entered)
		select {
		case <-q.resume:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*roleExplanationPublicationTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges(t *testing.T) {
	for _, change := range []string{"source-anchor", "current-grant", "policy"} {
		t.Run(change, func(t *testing.T) {
			f := newRoleExplanationAPIFixture(t)
			a, b := f.tenants[0], f.tenants[1]
			tracer := &roleExplanationPublicationTracer{entered: make(chan struct{}), resume: make(chan struct{})}
			cfg := f.pool.Config().Copy()
			cfg.ConnConfig.Tracer = tracer
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			f.server.pool = pool
			socket := httptest.NewTLSServer(f.server.Handler())
			t.Cleanup(socket.Close)
			path := "/v1/entity-contexts/" + f.contextID + "/interfaces/" + f.interfaceID + "/role"
			type result struct {
				status int
				body   []byte
				err    error
			}
			request := func(tenant string) result {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, socket.URL+path, nil)
				if err != nil {
					return result{err: err}
				}
				req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
				res, err := socket.Client().Do(req)
				if err != nil {
					return result{err: err}
				}
				defer res.Body.Close()
				raw, err := io.ReadAll(res.Body)
				return result{status: res.StatusCode, body: raw, err: err}
			}
			done := make(chan result, 1)
			go func() { done <- request(a) }()
			select {
			case <-tracer.entered:
			case <-time.After(15 * time.Second):
				t.Fatal("role publication did not start a fresh authority snapshot", tracer.snapshots.Load())
			}
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				switch change {
				case "source-anchor":
					_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$2 WHERE tenant_id=$1 AND source_kind='device_target'`, a, f.otherRouter)
					return err
				case "current-grant":
					_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
					return err
				default:
					old, err := (store.InterfaceRoleConfiguration{}).Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
					if err != nil {
						return err
					}
					old.Definition.ProviderASNs = nil
					old.Definition.CustomerASNs = []uint32{64496}
					_, err = (store.InterfaceRoleConfiguration{}).PutPolicy(ctx, sc, f.contextID, old.ID, old.Revision, old.Definition, roleExplanationStoreBudget())
					return err
				}
			})
			close(tracer.resume)
			var got result
			select {
			case got = <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("role publication did not finish after committed authority change")
			}
			want := http.StatusServiceUnavailable
			if change == "current-grant" {
				want = http.StatusForbidden
			}
			if got.err != nil || got.status != want || strings.Contains(string(got.body), "current_evidence") {
				t.Fatal("role explanation published after its authority changed", change, got.status, got.err, string(got.body))
			}
			other := request(b)
			var out interfaceRoleExplanation
			if other.err != nil || other.status != http.StatusOK || json.Unmarshal(other.body, &out) != nil || out.TenantID != b || out.Role != entity.InterfaceRoleTransit {
				t.Fatal("authority change damaged another tenant's explanation", other.status, other.err)
			}
		})
	}
}

func TestInterfaceRoleExplanationEvaluatesCompleteSavedPolicyWithDefaultAdmission(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	a := f.tenants[0]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		configuration := store.InterfaceRoleConfiguration{}
		old, err := configuration.Policy(ctx, sc, f.contextID, interfaceRoleStoreBudget(flowstore.DefaultExplorerBudget()))
		if err != nil {
			return err
		}
		for i := range 4096 {
			old.Definition.DescriptionRules = append(old.Definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{Pattern: "^" + a + strings.Repeat("-uplink", 25) + fmt.Sprint(i) + "$", Role: entity.InterfaceRoleOther})
		}
		old.Definition.DescriptionRules = append(old.Definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{Pattern: "^owned-0$", Role: entity.InterfaceRoleBackbone})
		raw, err := json.Marshal(old.Definition)
		if err != nil {
			return err
		}
		if len(raw) <= 1<<20 {
			t.Fatal("complete role explanation fixture lost its saved workload")
		}
		_, err = configuration.PutPolicy(ctx, sc, f.contextID, old.ID, old.Revision, old.Definition, interfaceRoleStoreBudget(flowstore.DefaultExplorerBudget()))
		return err
	})
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/entity-contexts/"+f.contextID+"/interfaces/"+f.interfaceID+"/role", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tokens[a])
	res, err := socket.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out interfaceRoleExplanation
	if res.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Role != entity.InterfaceRoleBackbone || out.Reason != "description_rule" || len(out.Sources) != 2 {
		t.Fatal("complete saved role policy cannot be explained under the default profile", res.StatusCode, string(raw))
	}
}
