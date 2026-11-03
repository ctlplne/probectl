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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real PostgreSQL, application-role RLS and the actual evidence writer with
// persisted issuance/source bindings. This is not a network sender/release
// proof. Agent-address and live canonical-prefix producers remain required.
func TestOwnedTagSubjectSnapshotUsesCurrentFactsAndTenantIsolation(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, suffix := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("tag-subject-%s-%d", suffix, time.Now().UnixNano()), "Tag subject "+suffix)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Errorf("remove subject tenants: %v", err)
		}
	})
	contextID, deviceID, prefixID, otherDevice := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	agentIDs := map[string]string{}
	for _, tenant := range tenants {
		agentIDs[tenant] = uuid.NewString()
	}
	agentFor := func(tenant string) string { return agentIDs[tenant] }
	testIDs := map[string]string{}
	for _, tenant := range tenants {
		testIDs[tenant] = uuid.NewString()
	}
	keys := map[string]string{}
	for _, key := range []string{"manual", "snmp", "cidr", "name", "raw_name"} {
		keys[key] = uuid.NewString()
	}
	serials := map[string]string{}
	interfaces := map[string]string{}
	repo := NewEntityRegistry(pool)
	snapshots := NewTagSnapshots(pool)
	scopeFor := func(tenant string) tags.Scope { return tags.Scope{TenantID: tenant, ContextID: contextID} }
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	writePoll := func(tenant, description, name string, withInterface bool) {
		t.Helper()
		agentID := agentFor(tenant)
		at := time.Now().UTC().Truncate(time.Microsecond)
		source := entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "target"}
		claims := []entity.Observation{{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", SystemDescription: description, SystemName: &name, ObservedAt: at}}
		if name != "" {
			claims = append(claims, entity.Observation{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPDeviceAlias, Value: name}, SourceRef: "snmp:sysName", ObservedAt: at})
		}
		if withInterface {
			claims = append(claims,
				entity.Observation{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceName: "observed-interface", InterfaceDescription: "uplink", ObservedAt: at},
				entity.Observation{ID: uuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.2.0.7"}, SourceRef: "snmp:ifIndex:7", ObservedAt: at})
		}
		accepted, unresolved, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), agentID, serials[tenant], claims)
		if err != nil || accepted != len(claims) || unresolved != 0 {
			t.Fatalf("write owned poll: accepted=%d unresolved=%d err=%v", accepted, unresolved, err)
		}
	}
	for index, tenant := range tenants {
		agentID, testID := agentFor(tenant), testIDs[tenant]
		for _, plane := range []string{"transport", "evidence"} {
			serial := strings.ReplaceAll(uuid.NewString(), "-", "")
			spiffe := crypto.AgentSPIFFEID(tenant, agentID)
			if plane == "evidence" {
				spiffe = crypto.EntitySPIFFEID(tenant, agentID)
				serials[tenant] = serial
			}
			if err := NewAgentIdentities(pool).Record(ctx, tenant, agentID, spiffe, serial, time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
		}
		run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (Agents{}).Register(ctx, sc, agentID, "observed-agent", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant, agentID), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts (tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities (tenant_id,context_id,id,kind,label) VALUES
			 ($1,$2,$3,'device','operator-edge'),($1,$2,$4,'prefix','10.2.0.0/24'),($1,$2,$5,'device','other-device')`, tenant, contextID, deviceID, prefixID, otherDevice); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts (tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, tenant, agentID, contextID); err != nil {
				return err
			}
			for _, source := range []struct{ kind, ref string }{{"device_target", "target"}, {"device_target", "target-2"}, {"flow_exporter", "10.2.0.9"}} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts (tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES ($1,$2,$3,$4,$5,$6)`, tenant, agentID, source.kind, source.ref, contextID, deviceID); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target) VALUES ($1,$2,'observed-test','https://10.2.0.8/health')`, tenant, testID); err != nil {
				return err
			}
			if err := repo.AssignPathTestContext(ctx, sc, testID, contextID); err != nil {
				return err
			}
			for key, id := range keys {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions (tenant_id,id,key) VALUES ($1,$2,$3)`, tenant, id, key); err != nil {
					return err
				}
			}
			return nil
		})
		writePoll(tenant, fmt.Sprintf("description-%d", index), "observed-router", true)
		var interfaceID string
		if err := pool.QueryRow(ctx, `SELECT id::text FROM entities WHERE tenant_id=$1 AND context_id=$2 AND source_agent_id=$3 AND configured_ref='target' AND interface_index=7`, tenant, contextID, agentID).Scan(&interfaceID); err != nil {
			t.Fatal(err)
		}
		interfaces[tenant] = interfaceID
		for _, kind := range []string{"device", "interface", "prefix", "agent", "test", "exporter"} {
			id := deviceID
			switch kind {
			case "interface":
				id = interfaces[tenant]
			case "prefix":
				id = prefixID
			case "agent":
				id = agentID
			case "test":
				id = testID
			case "exporter":
				id = ""
			}
			run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				input := ManualTagAssignmentInput{Scope: scopeFor(tenant), TagID: keys["manual"], TargetKind: kind, TargetID: id, Value: fmt.Sprintf("%s-%d", kind, index)}
				if kind == "exporter" {
					input.ExporterAgentID = agentID
					input.ExporterSourceRef = "10.2.0.9"
				}
				if _, err := (TagAssignments{}).CreateManual(ctx, sc, input); err != nil {
					return err
				}
				for _, rule := range []tags.Rule{
					{Scope: scopeFor(tenant), TagID: keys["cidr"], TargetKind: kind, Match: "cidr", AddressSide: kind, CIDR: "10.2.0.0/24", Value: fmt.Sprintf("cidr-%d", index)},
					{Scope: scopeFor(tenant), TagID: keys["name"], TargetKind: kind, Match: "name_pattern", NamePattern: "^observed-", Value: fmt.Sprintf("name-%d", index)},
				} {
					if _, err := (TagRules{}).Create(ctx, sc, rule); err != nil {
						return err
					}
				}
				if kind == "device" || kind == "interface" {
					if _, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: scopeFor(tenant), TagID: keys["raw_name"], TargetKind: kind, Match: "snmp_field", SNMPField: "sys_name", SNMPValue: "  observed-router  ", Value: fmt.Sprintf("raw-%d", index)}); err != nil {
						return err
					}
					field, value := "sys_descr", fmt.Sprintf("description-%d", index)
					if kind == "interface" {
						field, value = "if_name", "observed-interface"
					}
					_, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: scopeFor(tenant), TagID: keys["snmp"], TargetKind: kind, Match: "snmp_field", SNMPField: field, SNMPValue: value, Value: fmt.Sprintf("snmp-%d", index)})
					return err
				}
				return nil
			})
		}
	}
	resolve := func(tenant, kind string) (ResolvedTagSubject, error) {
		agentID, testID := agentFor(tenant), testIDs[tenant]
		id := deviceID
		switch kind {
		case "interface":
			id = interfaces[tenant]
		case "prefix":
			id = prefixID
		case "agent":
			id = agentID
		case "test":
			id = testID
		}
		ref := TagSubjectReference{Kind: kind, ID: id}
		if kind == "exporter" {
			ref.ID = ""
			ref.ExporterAgentID = agentID
			ref.ExporterSourceRef = "10.2.0.9"
		}
		return snapshots.ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(tenant)), scopeFor(tenant), ref, 8<<20)
	}
	values := func(result ResolvedTagSubject) map[string]string {
		out := map[string]string{}
		for _, item := range result.Items {
			out[item.Key] = item.Value
		}
		return out
	}
	for index, tenant := range tenants {
		for _, kind := range []string{"device", "interface", "prefix", "agent", "test", "exporter"} {
			result, err := resolve(tenant, kind)
			if err != nil || result.Scope != scopeFor(tenant) || result.AsOf.IsZero() {
				t.Fatalf("resolve owned %s: %+v %v", kind, result, err)
			}
			got := values(result)
			if got["manual"] != fmt.Sprintf("%s-%d", kind, index) {
				t.Fatalf("%s crossed a tenant or typed target: %v", kind, got)
			}
			wantCIDR := kind == "device" || kind == "interface" || kind == "test" || kind == "exporter"
			if (got["cidr"] != "") != wantCIDR || (wantCIDR && got["cidr"] != fmt.Sprintf("cidr-%d", index)) {
				t.Fatalf("%s invented a fact from a label or lost a real typed address: %v", kind, got)
			}
			if (kind == "device" || kind == "interface") && got["snmp"] != fmt.Sprintf("snmp-%d", index) {
				t.Fatalf("%s lost current source metadata: %v", kind, got)
			}
		}
	}
	a, b := tenants[0], tenants[1]
	agentID, testID := agentFor(a), testIDs[a]
	ref := TagSubjectReference{Kind: "device", ID: deviceID}
	if _, err := snapshots.ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(a)), scopeFor(b), ref, 8<<20); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatal("caller selected another tenant")
	}
	if result, err := snapshots.ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(a)), scopeFor(a), ref, 1); !errors.Is(err, ErrTagSnapshotBudget) || len(result.Items) != 0 {
		t.Fatal("small budget returned partial metadata")
	}
	if _, err := snapshots.ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(a)), scopeFor(a), TagSubjectReference{Kind: "device", ID: prefixID}, 8<<20); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("wrong canonical kind resolved")
	}
	for _, foreign := range []TagSubjectReference{
		{Kind: "agent", ID: agentFor(b)}, {Kind: "test", ID: testIDs[b]},
		{Kind: "exporter", ExporterAgentID: agentFor(b), ExporterSourceRef: "10.2.0.9"},
	} {
		if _, err := snapshots.ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(a)), scopeFor(a), foreign, 8<<20); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("foreign typed reference crossed tenant scope")
		}
	}
	canceled, cancel := context.WithCancel(tenancy.WithTenant(ctx, tenancy.ID(a)))
	cancel()
	if result, err := snapshots.ResolveSubject(canceled, scopeFor(a), ref, 8<<20); !errors.Is(err, context.Canceled) || len(result.Items) != 0 || !result.AsOf.IsZero() {
		t.Fatal("canceled subject read exposed partial metadata")
	}
	before, err := resolve(a, "device")
	if err != nil {
		t.Fatal(err)
	}
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		rules, _, err := (TagRules{}).List(ctx, sc, contextID, "", 100)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if rule.TargetKind == "device" && rule.Match == "snmp_field" {
				rule.Value = "retagged-current-rule"
				_, err := (TagRules{}).Update(ctx, sc, rule)
				return err
			}
		}
		return errors.New("owned SNMP rule was absent")
	})
	after, err := resolve(a, "device")
	if err != nil {
		t.Fatal(err)
	}
	if values(after)["snmp"] != "retagged-current-rule" || after.Revision <= before.Revision {
		t.Fatal("new rule did not retag retained evidence")
	}
	writePoll(a, "description-0", "  observed-router  ", true)
	for _, kind := range []string{"device", "interface"} {
		result, err := resolve(a, kind)
		if err != nil || values(result)["raw_name"] != "raw-0" {
			t.Fatalf("%s did not match exact raw system-name spaces: %v", kind, err)
		}
		other, err := resolve(b, kind)
		if err != nil || values(other)["raw_name"] != "" {
			t.Fatal("raw SNMP rule facts crossed tenants with reused canonical IDs")
		}
	}
	writePoll(a, "", "", false)
	for _, kind := range []string{"device", "interface"} {
		result, err := resolve(a, kind)
		if err != nil {
			t.Fatal(err)
		}
		got := values(result)
		if got["snmp"] != "" || got["cidr"] != "" || got["name"] != "" || got["raw_name"] != "" || got["manual"] == "" {
			t.Fatalf("new empty poll revived old facts for %s: %v", kind, got)
		}
	}
	writePoll(a, "description-0", "observed-router", true)
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "target"}, contextID, otherDevice)
	})
	result, err := resolve(a, "device")
	if err != nil {
		t.Fatal(err)
	}
	if got := values(result); got["snmp"] != "" || got["cidr"] != "" {
		t.Fatal("rebound source revived old device facts")
	}
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		return repo.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "target"}, contextID, deviceID)
	})
	result, err = resolve(a, "device")
	if err != nil {
		t.Fatal(err)
	}
	if values(result)["snmp"] != "" {
		t.Fatal("restored anchor revived pre-rebind evidence")
	}
	writePoll(a, "description-0", "observed-router", true)
	if _, _, err := NewAgentIdentities(pool).RevokeAgent(ctx, a, agentID, "operator"); err != nil {
		t.Fatal(err)
	}
	result, err = resolve(a, "device")
	if err != nil {
		t.Fatal(err)
	}
	if got := values(result); got["snmp"] != "" || got["cidr"] != "" {
		t.Fatal("revoked sender still supplied current facts")
	}
	if _, err := resolve(a, "agent"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("revoked agent identity resolved")
	}
	if result, err := resolve(b, "agent"); err != nil || values(result)["manual"] != "agent-1" {
		t.Fatal("revocation crossed tenant scope")
	}
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tests SET target='https://10.3.0.8/health' WHERE tenant_id=$1 AND id=$2`, a, testID)
		return err
	})
	if _, err := resolve(a, "test"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("retargeted test retained its old context")
	}
	// Independent current sources cannot win by observation time or row order.
	at := time.Now().UTC().Truncate(time.Microsecond)
	claim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agentFor(b), Kind: entity.DeviceTarget, SourceRef: "target-2"},
		Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.2"}, SourceRef: "snmp:configured-target", SystemDescription: "conflicting-description", ObservedAt: at}
	if accepted, unresolved, err := repo.WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(b)), agentFor(b), serials[b], []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatalf("seed second current source: %v", err)
	}
	if result, err := resolve(b, "device"); !errors.Is(err, ErrTagSubjectFactsAmbiguous) || len(result.Items) != 0 {
		t.Fatal("conflicting source published selected tags")
	}
	run(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=transaction_timestamp()-interval '1 second' WHERE tenant_id=$1 AND agent_id=$2 AND source_ref='target-2'`, b, agentFor(b))
		return err
	})
	if result, err := resolve(b, "device"); err != nil || values(result)["snmp"] != "snmp-1" {
		t.Fatal("expired independent source hid the current owner fact")
	}
	// Wall-clock expiry between SELECTs must not change a pinned read. A fresh
	// transaction must then drop those observations. Exercise the actual fact
	// SQL, including all nested current-source and SVID checks.
	var expires time.Time
	if err := pool.QueryRow(ctx, `UPDATE entity_evidence SET expires_at=clock_timestamp()+interval '3 seconds'
		WHERE tenant_id=$1 AND configured_ref='target' RETURNING expires_at`, b).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	readCtx := tenancy.WithTenant(ctx, tenancy.ID(b))
	if err := tenancy.InTenantReadSnapshot(readCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var asOf time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&asOf); err != nil {
			return err
		}
		if !asOf.Before(expires) {
			return errors.New("expiry fixture elapsed before its first snapshot read")
		}
		load := func() (tags.Subject, error) {
			return loadOwnedTagSubject(ctx, sc, scopeFor(b), ref, 8<<20, func(...string) error { return nil })
		}
		first, err := load()
		if err != nil || first.SNMP["sys_descr"] != "description-1" {
			return fmt.Errorf("first expiry snapshot lost current facts: %w", err)
		}
		if _, err := sc.Q.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.02)`, expires); err != nil {
			return err
		}
		last, err := load()
		if err != nil || last.SNMP["sys_descr"] != first.SNMP["sys_descr"] || len(last.Addresses) != len(first.Addresses) {
			return fmt.Errorf("expiry mixed fact epochs inside one read snapshot: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := resolve(b, "device"); err != nil || values(result)["snmp"] != "" || values(result)["cidr"] != "" || values(result)["name"] != "" {
		t.Fatal("fresh snapshot retained expired observational facts")
	}
	writePoll(b, "description-1", "observed-router", true)
	writePoll(b, "", "", false)
	if _, err := pool.Exec(ctx, `UPDATE entity_evidence SET expires_at=observed_at+interval '1 microsecond'
		WHERE tenant_id=$1 AND configured_ref='target' AND source_ref='snmp:configured-target'
		AND observed_at=(SELECT max(observed_at) FROM entity_evidence WHERE tenant_id=$1 AND configured_ref='target' AND source_ref='snmp:configured-target')`, b); err != nil {
		t.Fatal(err)
	}
	if result, err := resolve(b, "device"); err != nil || values(result)["snmp"] != "" || values(result)["cidr"] != "" || values(result)["name"] != "" {
		t.Fatal("expired clearing poll revived older unexpired facts")
	}
}
