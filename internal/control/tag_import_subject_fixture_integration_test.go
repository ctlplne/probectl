// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type tagImportSubjectFixture struct {
	srv                                    *Server
	db                                     *store.DB
	a, b, contextID, tagID, device, prefix string
	agents, tests, interfaces, serials     map[string]string
	calls                                  atomic.Int64
	hookMu                                 sync.Mutex
	hook                                   func()
}

func newTagImportSubjectFixture(t *testing.T) *tagImportSubjectFixture {
	t.Helper()
	srv, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	f := &tagImportSubjectFixture{srv: srv, db: db, a: freshTenant(t, db, "tag-subject-import-a"), b: freshTenant(t, db, "tag-subject-import-b"),
		contextID: uuid(t), tagID: uuid(t), device: uuid(t), prefix: uuid(t), agents: map[string]string{}, tests: map[string]string{}, interfaces: map[string]string{}, serials: map[string]string{}}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.a, f.b}); err != nil {
			t.Error(err)
		}
	})
	for _, tenant := range []string{f.a, f.b} {
		agent, serial, siteID := uuid(t), strings.ReplaceAll(uuid(t), "-", ""), uuid(t)
		f.agents[tenant], f.tests[tenant], f.serials[tenant] = agent, uuid(t), serial
		for _, row := range []struct{ uri, serial string }{{crypto.AgentSPIFFEID(tenant, agent), strings.ReplaceAll(uuid(t), "-", "")}, {crypto.EntitySPIFFEID(tenant, agent), serial}} {
			if err := store.NewAgentIdentities(db.Pool()).Record(t.Context(), tenant, agent, row.uri, row.serial, time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
		}
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agent, "operator-agent", "192.0.2.99", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, f.contextID, siteID, uuid(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,network_prefix) VALUES
			 ($1,$2,$3,'device','operator-device',NULL),($1,$2,$4,'prefix','operator-prefix','192.0.2.0/24'::cidr),($1,$2,$5,'site','operator-site',NULL)`, tenant, f.contextID, f.device, f.prefix, siteID); err != nil {
				return err
			}
			repo := store.NewEntityRegistry(db.Pool())
			for _, row := range []struct {
				kind        entity.SourceKind
				ref, anchor string
			}{{entity.DeviceTarget, "target", f.device}, {entity.AgentSite, agent, siteID}, {entity.FlowExporter, "192.0.2.10", f.device}} {
				if err := repo.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: row.kind, SourceRef: row.ref}, f.contextID, row.anchor); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,target) VALUES ($1,$2,'operator-test','https://192.0.2.10/health')`, tenant, f.tests[tenant]); err != nil {
				return err
			}
			if err := repo.AssignPathTestContext(ctx, sc, f.tests[tenant], f.contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'role')`, tenant, f.tagID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		source := entity.SourceKey{AgentID: agent, Kind: entity.DeviceTarget, SourceRef: "target"}
		claims := []entity.Observation{
			{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.10"}, SourceRef: "snmp:configured-target", ObservedAt: at},
			{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceName: "observed-interface", ObservedAt: at},
			{ID: uuid(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.10"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at},
			{ID: uuid(t), Source: entity.SourceKey{AgentID: agent, Kind: entity.AgentSite, SourceRef: agent}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "operator-site"}, SourceRef: "agent:label:site", ObservedAt: at, AgentAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		}
		if accepted, unresolved, err := store.NewEntityRegistry(db.Pool()).WriteEvidenceBatch(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agent, serial, claims); err != nil || accepted != len(claims) || unresolved != 0 {
			t.Fatalf("current source setup %d/%d: %v", accepted, unresolved, err)
		}
		var interfaceID string
		if err := db.Pool().QueryRow(t.Context(), `SELECT id::text FROM entities WHERE tenant_id=$1 AND context_id=$2 AND source_agent_id=$3 AND configured_ref='target' AND interface_index=7`, tenant, f.contextID, agent).Scan(&interfaceID); err != nil {
			t.Fatal(err)
		}
		f.interfaces[tenant] = interfaceID
	}
	server := httptest.NewServer(http.HandlerFunc(f.serveSource))
	t.Cleanup(server.Close)
	srv.WithCMDB(cmdb.NewResolver(cmdb.NewNetBox(server.URL, "test-token", map[string]string{f.a: "7", f.b: "8"}), time.Hour))
	return f
}

func (f *tagImportSubjectFixture) serveSource(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	source := r.URL.Query().Get("tenant_id")
	if source != "7" && source != "8" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.hookMu.Lock()
	hook := f.hook
	f.hook = nil
	f.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	ip, owner, prefix := "10", "42", "101"
	if source == "8" {
		ip, owner, prefix = "20", "84", "201"
	}
	switch r.URL.Path {
	case "/api/ipam/ip-addresses/":
		if id := r.URL.Query().Get("id"); (id != "" && id != ip) || (id == "" && r.URL.Query().Get("address") != "192.0.2.10") {
			fmt.Fprint(w, `{"count":0,"results":[]}`)
			return
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":%s,"tenant":{"id":%s},"address":"192.0.2.10/32","dns_name":"configured.example","assigned_object":{"device":{"id":%s}}}]}`, ip, source, owner)
	case "/api/dcim/devices/":
		if r.URL.Query().Get("id") != owner {
			fmt.Fprint(w, `{"count":0,"results":[]}`)
			return
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":%s,"tenant":{"id":%s},"name":"source-router","role":{"id":51,"name":"import-%s"},"site":{"id":71,"name":"site-%s"}}]}`, owner, source, source, source)
	case "/api/ipam/prefixes/":
		if id := r.URL.Query().Get("id"); (id != "" && id != prefix) || r.URL.Query().Get("prefix") != "192.0.2.0/24" {
			fmt.Fprint(w, `{"count":0,"results":[]}`)
			return
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":%s,"tenant":{"id":%s},"prefix":"192.0.2.0/24","vrf":{"id":9},"role":{"id":51,"name":"import-%s"},"scope_type":"dcim.site","scope_id":71,"scope":{"id":71,"name":"site-%s"}}]}`, prefix, source, source, source)
	default:
		fmt.Fprint(w, `{"count":0,"results":[]}`)
	}
}

func (f *tagImportSubjectFixture) input(tenant, kind string) netBoxTagPreviewRequest {
	i := netBoxTagPreviewRequest{TagID: f.tagID, TargetKind: kind, Field: "role"}
	switch kind {
	case "device":
		i.TargetID = f.device
	case "interface":
		i.TargetID = f.interfaces[tenant]
	case "prefix":
		i.TargetID = f.prefix
	case "agent":
		i.TargetID = f.agents[tenant]
	case "test":
		i.TargetID = f.tests[tenant]
	case "exporter":
		i.ExporterAgentID = f.agents[tenant]
		i.ExporterSourceRef = "192.0.2.10"
	}
	return i
}
