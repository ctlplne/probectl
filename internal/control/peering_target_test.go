// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func peeringTargetSources(t testing.TB, at time.Time, lan int64, ports int, subnet ...string) *opendata.Enricher {
	t.Helper()
	v4 := "198.51.100.0/24"
	if len(subnet) == 1 {
		v4 = subnet[0]
	}
	dir := t.TempDir()
	write := func(name string, body any) string {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	prefixes := write("ixpfx.json", map[string]any{"version": 1, "object": "ixpfx", "observed_at": at.Add(-30 * time.Second), "complete": true, "record_count": 2, "data": []any{
		map[string]any{"id": 7, "ixlan_id": lan, "protocol": "IPv4", "prefix": v4, "status": "ok"},
		map[string]any{"id": 8, "ixlan_id": lan, "protocol": "IPv6", "prefix": "2001:db8::/64", "status": "ok"},
	}})
	rows := make([]any, 0, ports)
	for i := range ports {
		rows = append(rows, map[string]any{"id": i + 1, "ix_id": 71, "ixlan_id": 11, "asn": ^uint32(0), "status": "ok", "operational": true})
	}
	members := write("netixlan.json", map[string]any{"version": 1, "object": "netixlan", "observed_at": at.Add(-time.Minute), "complete": true, "record_count": ports, "data": rows})
	en := opendata.NewEnricher(statusQuietLog())
	p, err := opendata.LoadPeeringDBIXPrefixes(t.Context(), prefixes, time.Hour, 2<<30, at)
	if err != nil {
		t.Fatal(err)
	}
	m, err := opendata.LoadPeeringDBIXMemberships(t.Context(), members, time.Hour, 2<<30, at)
	if err != nil {
		t.Fatal(err)
	}
	en.Register(p)
	en.Register(m)
	return en
}

func peeringTargetFixture(tenant string) (peeringTarget, store.InterfaceRoleInputs) {
	in := roleExplanationFixture(tenant)
	in.Policy.Definition = entity.InterfaceRolePolicyDefinition{}
	in.SNMP.Addresses = append(in.SNMP.Addresses, netip.MustParseAddr("2001:db8::7"))
	in.SNMP.Prefixes = append(in.SNMP.Prefixes, entity.SNMPInterfacePrefix{IfIndex: in.IfIndex, Prefix: netip.MustParsePrefix("2001:db8::/64"), OnLink: true})
	return peeringTarget{Scope: in.Scope, InterfaceID: in.InterfaceID, PeerASN: ^uint32(0), IXID: 71, LANID: 11}, in
}

func TestPeeringTargetKeepsWholeOwnedLANMembershipAndOriginalGenerations(t *testing.T) {
	var previous string
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		target, in := peeringTargetFixture(tenant)
		en := peeringTargetSources(t, in.AsOf, 11, 5001)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		budget := interfaceRoleBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20}
		got, err := evaluatePeeringTarget(ctx, target, in, en.IXPrefixes(in.AsOf), en.IXMemberships(in.AsOf), budget)
		if err != nil || !got.Eligible || got.Target != target || got.RouterID != in.RouterID || len(got.PrefixIDs) != 2 || len(got.MembershipIDs) != 5001 || got.Role.Role != interfaceRoleIX || !got.ValidUntil.Equal(in.SNMP.ValidUntil) || len(got.InputDigest) != 64 || got.InputDigest == previous {
			t.Fatal("peering target lost complete owned LAN/membership evidence or crossed tenants", got, err)
		}
		previous = got.InputDigest
		later := in
		later.AsOf = later.AsOf.Add(time.Nanosecond)
		again, err := evaluatePeeringTarget(ctx, target, later, en.IXPrefixes(later.AsOf), en.IXMemberships(later.AsOf), budget)
		if err != nil || !again.Eligible || again.InputDigest != got.InputDigest || !again.ValidUntil.Equal(got.ValidUntil) {
			t.Fatal("peering evidence changed generation or renewed expiry on a read", again, err)
		}
		changed := in
		changed.Policy.UpdatedAt = changed.Policy.UpdatedAt.Add(time.Nanosecond)
		newer, err := evaluatePeeringTarget(ctx, target, changed, en.IXPrefixes(in.AsOf), en.IXMemberships(in.AsOf), budget)
		if err != nil || !newer.Eligible || newer.InputDigest == got.InputDigest {
			t.Fatal("peering target lost a changed current policy incarnation", newer, err)
		}
	}
}

func TestPeeringTargetRefusesForeignScopeBeforePublicAvailabilityAndAdmission(t *testing.T) {
	target, in := peeringTargetFixture("11111111-1111-4111-8111-111111111111")
	budget := interfaceRoleBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20}
	// Empty/unavailable public sources must not make the outer tenant check
	// disappear. No later role evaluator is needed to reject these inputs.
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))} {
		if got, err := evaluatePeeringTarget(ctx, target, in, opendata.IXPrefixSnapshot{}, opendata.IXMembershipSnapshot{}, budget); !errors.Is(err, entity.ErrScopeMismatch) || got.Eligible || got.Target.InterfaceID != "" {
			t.Fatal("peering target consulted public availability before the tenant boundary", got, err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(target.Scope.TenantID))
	en := peeringTargetSources(t, in.AsOf, 11, 1)
	for _, limits := range []interfaceRoleBudget{{MemoryBytes: 1, WorkUnits: 1 << 30}, {MemoryBytes: 1 << 30, WorkUnits: 1}} {
		if got, err := evaluatePeeringTarget(ctx, target, in, en.IXPrefixes(in.AsOf), en.IXMemberships(in.AsOf), limits); err == nil || got.Eligible || got.Target.InterfaceID != "" {
			t.Fatal("unadmitted peering input exposed partial evidence", got, err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := evaluatePeeringTarget(canceled, target, in, en.IXPrefixes(in.AsOf), en.IXMemberships(in.AsOf), budget); !errors.Is(err, context.Canceled) || got.Eligible {
		t.Fatal("canceled peering target kept working", got, err)
	}
}

func TestPeeringTargetRequiresExactCurrentLANBindingRoleAndMembership(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	budget := interfaceRoleBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20}
	for _, name := range []string{"wrong-lan", "wrong-ix", "wrong-asn", "expired-members", "expired-prefixes", "disabled-members", "missing-snmp", "missing-prefixes", "stale-binding", "foreign-binding", "private-override"} {
		t.Run(name, func(t *testing.T) {
			target, in := peeringTargetFixture(tenant)
			lan := int64(11)
			if name == "wrong-lan" {
				lan = 12
			}
			en := peeringTargetSources(t, in.AsOf, lan, 1)
			prefixes, members := en.IXPrefixes(in.AsOf), en.IXMemberships(in.AsOf)
			switch name {
			case "wrong-ix":
				target.IXID++
			case "wrong-asn":
				target.PeerASN--
			case "expired-members":
				members.ValidUntil = in.AsOf // stale cached Current=true is insufficient
			case "expired-prefixes":
				prefixes.ValidUntil = in.AsOf
			case "disabled-members":
				members.Enabled = false
			case "missing-snmp":
				in.SNMP = nil
			case "missing-prefixes":
				in.SNMP.Prefixes = nil
			case "stale-binding":
				in.SNMP.Bindings[0].ValidUntil = in.AsOf
			case "foreign-binding":
				in.SNMP.Bindings[0].InterfaceID = "77777777-7777-4777-8777-777777777777"
			case "private-override":
				in.Override = &entity.InterfaceRoleOverrideRecord{Scope: in.Scope, InterfaceID: in.InterfaceID, ID: "66666666-6666-4666-8666-666666666666", Revision: "1", Role: interfaceRolePrivate}
			}
			got, err := evaluatePeeringTarget(ctx, target, in, prefixes, members, budget)
			if err != nil || got.Eligible {
				t.Fatal("peering target admitted unavailable or mismatched IX/owner evidence", name, got, err)
			}
		})
	}
}
