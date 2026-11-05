// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real Postgres/FORCE-RLS and actual evidence/configuration writers. Issued
// sender identities and fault receipts are seeded; transport and real routers
// remain separate required integration proof, not claimed by this fixture.
type roleInputsFixture struct {
	t                                             *testing.T
	pool                                          *pgxpool.Pool
	tenants                                       []string
	contextID, routerID, interfaceID, otherRouter string
	serials                                       map[string]string
}

func newRoleInputsFixture(t *testing.T) *roleInputsFixture {
	t.Helper()
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	f := &roleInputsFixture{t: t, pool: pool, contextID: gouuid.NewString(), routerID: gouuid.NewString(), interfaceID: gouuid.NewString(), otherRouter: gouuid.NewString(), serials: map[string]string{}}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, f.tenants); err != nil {
			t.Error(err)
		}
	})
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("role-inputs-%d-%d", lane, time.Now().UnixNano()), "Role inputs")
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
			if err := NewAgentIdentities(pool).Record(t.Context(), tenant.ID, agent, spiffe, serial, time.Now().Add(time.Hour), ""); err != nil {
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
			_, err := (InterfaceRoleConfiguration{}).PutPolicy(ctx, sc, f.contextID, "", "0", entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{64496 + uint32(lane)}, CustomerASNs: []uint32{64500}}, roleInputsBudget())
			return err
		})
		f.poll(tenant.ID, fmt.Sprintf("owned-%d", lane), roleInputsPrefixes())
		f.peer(tenant.ID, 64496+uint32(lane))
	}
	return f
}

func roleInputsBudget() entity.InterfaceRolePolicyBudget {
	return entity.InterfaceRolePolicyBudget{MemoryBytes: 128 << 20, WorkUnits: 64 << 20}
}
func roleInputsPrefixes() []entity.SNMPInterfacePrefix {
	return []entity.SNMPInterfacePrefix{{IfIndex: 7, Prefix: netip.MustParsePrefix("10.42.0.0/24"), OnLink: true}, {IfIndex: 7, Prefix: netip.MustParsePrefix("2001:db8::/64"), OnLink: true}}
}
func (f *roleInputsFixture) in(tenant string, fn func(context.Context, tenancy.Scope) error) {
	f.t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), f.pool, fn); err != nil {
		f.t.Fatal(err)
	}
}
func (f *roleInputsFixture) poll(tenant, description string, prefixes []entity.SNMPInterfacePrefix) string {
	f.t.Helper()
	at := time.Now().UTC().Truncate(time.Microsecond)
	source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
	root := gouuid.NewString()
	claims := []entity.Observation{
		{ID: root, Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: at, SNMPInterfacePrefixes: prefixes},
		{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceDescription: description, ObservedAt: at},
		{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at},
	}
	accepted, unresolved, err := NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), source.AgentID, f.serials[tenant+source.AgentID], claims)
	if err != nil || accepted != len(claims) || unresolved != 0 {
		f.t.Fatal("owned complete poll was not accepted", accepted, unresolved, err)
	}
	return root
}
func (f *roleInputsFixture) peer(tenant string, asn uint32) {
	f.peerAtAddress(tenant, "10.42.0.1", asn)
}
func (f *roleInputsFixture) peerAtAddress(tenant, address string, asn uint32) {
	f.t.Helper()
	claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-listener", Kind: entity.BMPPeer, SourceRef: "role-router"},
		Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: fmt.Sprintf("%s/as%d", address, asn)}, SourceRef: fmt.Sprintf("bmp:router:role-router:peer-asn:%d", asn), OriginSerial: f.serials[tenant+"role-router"], ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	accepted, unresolved, err := NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), "role-listener", f.serials[tenant+"role-listener"], []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		f.t.Fatal("owned BMP observation was not accepted", accepted, unresolved, err)
	}
}
func (f *roleInputsFixture) load(tenant string) InterfaceRoleInputs {
	f.t.Helper()
	out, err := NewInterfaceRoleInputs(f.pool).Load(tenancy.WithTenant(f.t.Context(), tenancy.ID(tenant)), entity.Scope{TenantID: tenant, ContextID: f.contextID}, f.interfaceID, roleInputsBudget())
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func TestInterfaceRoleInputsKeepCurrentOwnedSourcesAndNegativeFences(t *testing.T) {
	f := newRoleInputsFixture(t)
	a, b := f.tenants[0], f.tenants[1]
	for lane, tenant := range f.tenants {
		out := f.load(tenant)
		if out.Scope.TenantID != tenant || out.RouterID != f.routerID || out.InterfaceID != f.interfaceID || out.IfIndex != 7 || out.AsOf.IsZero() ||
			out.SNMP == nil || out.SNMP.Description != fmt.Sprintf("owned-%d", lane) || len(out.SNMP.Prefixes) != 2 || len(out.SNMP.Bindings) != 1 || len(out.Peers) != 1 || out.Peers[0].ASN != 64496+uint32(lane) || out.Policy.Definition.ProviderASNs[0] != 64496+uint32(lane) {
			t.Fatal("role snapshot crossed tenant/router/source or lost complete current facts", out)
		}
		if !out.SNMP.ValidUntil.After(out.AsOf) || !out.Peers[0].ValidUntil.After(out.AsOf) {
			t.Fatal("source expiry did not bound the current snapshot")
		}
	}
	reader := NewInterfaceRoleInputs(f.pool)
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID(b))} {
		got, err := reader.Load(ctx, entity.Scope{TenantID: a, ContextID: f.contextID}, f.interfaceID, roleInputsBudget())
		if !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(got, InterfaceRoleInputs{}) {
			t.Fatal("foreign or absent tenant returned role inputs", err)
		}
	}
	f.poll(a, "new-null-table", nil)
	out := f.load(a)
	if out.SNMP == nil || out.SNMP.Prefixes != nil || out.SNMP.Description != "new-null-table" {
		t.Fatal("latest unavailable prefix snapshot revived old metadata")
	}
	latest := f.poll(a, "expired-newer-table", roleInputsPrefixes())
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET expires_at=observed_at+interval '1 microsecond' WHERE tenant_id=$1 AND observation_id=$2`, a, latest)
		return err
	})
	if got := f.load(a); got.SNMP != nil {
		t.Fatal("expired latest poll revived older current prefix facts")
	}
	f.poll(a, "recovered", roleInputsPrefixes())
	f.peer(a, 64500)
	if got := f.load(a); len(got.Peers) != 1 || got.Peers[0].ASN != 64500 {
		t.Fatal("new peer ASN retained a superseded relationship", got.Peers)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRoleCustomer); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$3 WHERE tenant_id=$1 AND source_kind='device_target' AND source_ref=$2`, a, "192.0.2.1", f.otherRouter)
		return err
	})
	if got := f.load(a); got.SNMP != nil || got.Override == nil || got.Override.Role != entity.InterfaceRoleCustomer {
		t.Fatal("source rebind migrated old facts or erased owned override")
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$3 WHERE tenant_id=$1 AND source_kind='device_target' AND source_ref=$2`, a, "192.0.2.1", f.routerID)
		return err
	})
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-snmp' AND serial=$2`, a, f.serials[a+"role-snmp"])
		return err
	})
	if got := f.load(a); got.SNMP != nil || got.Override == nil {
		t.Fatal("revoked sender retained automatic authority or discarded owned override")
	}
	if got := f.load(b); got.SNMP == nil || got.SNMP.Description != "owned-1" || len(got.Peers) != 1 || got.Peers[0].ASN != 64497 {
		t.Fatal("source changes crossed the other tenant")
	}
	for _, id := range []string{f.routerID, gouuid.NewString()} {
		got, err := reader.Load(tenancy.WithTenant(t.Context(), tenancy.ID(b)), entity.Scope{TenantID: b, ContextID: f.contextID}, id, roleInputsBudget())
		if !errors.Is(err, pgx.ErrNoRows) || !reflect.DeepEqual(got, InterfaceRoleInputs{}) {
			t.Fatal("unknown or wrong-kind interface returned partial inputs", err)
		}
	}
}

func TestInterfaceRoleInputsRetainWholePrefixTableAndRefusePartialBudget(t *testing.T) {
	f := newRoleInputsFixture(t)
	a := f.tenants[0]
	prefixes := make([]entity.SNMPInterfacePrefix, 0, 20000)
	for index := uint32(1); index <= 20000; index++ {
		prefixes = append(prefixes, entity.SNMPInterfacePrefix{IfIndex: index, Prefix: netip.MustParsePrefix("2001:db8::/32"), OnLink: true})
	}
	f.poll(a, "complete-large-table", prefixes)
	got := f.load(a)
	if got.SNMP == nil || !reflect.DeepEqual(got.SNMP.Prefixes, prefixes) {
		t.Fatal("current role loader truncated the complete in-wire prefix population")
	}
	for _, budget := range []entity.InterfaceRolePolicyBudget{{}, {MemoryBytes: 5 << 20, WorkUnits: 64 << 20}} {
		out, err := NewInterfaceRoleInputs(f.pool).Load(tenancy.WithTenant(t.Context(), tenancy.ID(a)), entity.Scope{TenantID: a, ContextID: f.contextID}, f.interfaceID, budget)
		if !errors.Is(err, entity.ErrInterfaceRoleBudget) || !reflect.DeepEqual(out, InterfaceRoleInputs{}) {
			t.Fatal("role source admission returned partial policy or metadata", err)
		}
	}
	ctx, cancel := context.WithCancel(tenancy.WithTenant(t.Context(), tenancy.ID(a)))
	cancel()
	if out, err := NewInterfaceRoleInputs(f.pool).Load(ctx, entity.Scope{TenantID: a, ContextID: f.contextID}, f.interfaceID, roleInputsBudget()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, InterfaceRoleInputs{}) {
		t.Fatal("canceled role input snapshot returned partial facts", err)
	}
}

func TestInterfaceRoleInputsRequireAuthenticatedFaultClockAndRecovery(t *testing.T) {
	f := newRoleInputsFixture(t)
	a, b := f.tenants[0], f.tenants[1]
	createSignal := func(authenticated bool) string {
		t.Helper()
		sig := incident.Signal{TenantID: a, Plane: "device", Kind: "device.poll_failed", Severity: incident.SeverityWarning, Title: "SNMP device poll failed", Target: "192.0.2.1", OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Attributes: map[string]string{entity.AttrFaultObservationID: gouuid.NewString(), "probectl.agent.id": "role-snmp"}}
		var incidentID string
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			created, err := (Incidents{}).Create(ctx, sc, incident.Incident{TenantID: a, Severity: incident.SeverityWarning, Title: sig.Title, Target: sig.Target, StartedAt: sig.OccurredAt, LastSeenAt: sig.OccurredAt})
			if err != nil {
				return err
			}
			incidentID = created.ID
			if _, err := (Incidents{}).AppendSignal(ctx, sc, created.ID, sig); err != nil {
				return err
			}
			if authenticated {
				_, err = sc.Q.Exec(ctx, `INSERT INTO entity_fault_receipts(tenant_id,agent_id,observation_id,source_kind,source_ref,payload_fingerprint,incident_id) VALUES($1,'role-snmp',$2,'device_target','192.0.2.1',$3,$4)`, a, sig.Attributes[entity.AttrFaultObservationID], sig.Fingerprint(), created.ID)
			}
			return err
		})
		return incidentID
	}
	createSignal(false)
	if got := f.load(a); got.SNMP == nil {
		t.Fatal("unattested bus lookalike became source fault authority")
	}
	incidentID := createSignal(true)
	if got := f.load(a); got.SNMP != nil {
		t.Fatal("current authenticated poll fault retained automatic source authority")
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE incidents SET status='resolved',resolved_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, a, incidentID)
		return err
	})
	if got := f.load(a); got.SNMP != nil {
		t.Fatal("incident resolution fabricated successful source recovery")
	}
	if got := f.load(b); got.SNMP == nil {
		t.Fatal("fault authority crossed the other tenant")
	}
	f.poll(a, "actual-recovery", roleInputsPrefixes())
	if got := f.load(a); got.SNMP == nil || got.SNMP.Description != "actual-recovery" {
		t.Fatal("new successful complete observation did not recover source authority")
	}
}

func TestInterfaceRoleInputsRequireExplicitBMPOriginRouterBinding(t *testing.T) {
	f := newRoleInputsFixture(t)
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=NULL WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	// The actual writer may infer the peer's identity from independently
	// attested SNMP. That legal registry identity is not the BMP origin.
	f.peerAtAddress(a, "10.42.0.2", 64496)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		var current int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence e WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.source_kind='bmp_peer' AND e.alias_kind='bmp_peer_id' AND e.support_evidence_id IS NOT NULL AND `+currentEntityEvidenceSnapshotSQL(), a, f.contextID).Scan(&current)
		if err == nil && current != 1 {
			t.Fatal("independently inferred current-peer prerequisite is missing", current)
		}
		return err
	})
	if got := f.load(a); len(got.Peers) != 0 {
		t.Fatal("inferred BMP peer identity supplied origin-router role authority")
	}
	if got := f.load(b); len(got.Peers) != 1 || got.Peers[0].ASN != 64497 {
		t.Fatal("origin binding refusal changed the other tenant")
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=$2 WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a, f.routerID)
		return err
	})
	f.peer(a, 64496)
	if got := f.load(a); len(got.Peers) != 1 || got.Peers[0].Address != netip.MustParseAddr("10.42.0.1") {
		t.Fatal("new explicitly anchored origin observation was refused", got.Peers)
	}
}
