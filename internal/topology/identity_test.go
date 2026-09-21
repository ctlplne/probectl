// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIdentityConflictsPreserveCompetingClaims(t *testing.T) {
	g := NewGraph("tenant-a")
	base := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
	g.ObserveDevice(DeviceInput{
		Address: "10.0.0.1", Name: "edge-a", Source: "snmp", AgentID: "agent-snmp",
		IfIndex: 7, IfName: "Gi0/7", InterfaceIPs: []string{"192.0.2.7"},
	}, base)
	g.ObserveDevice(DeviceInput{
		Address: "10.0.0.1", Name: "edge-b", Source: "gnmi", AgentID: "agent-gnmi",
		IfIndex: 7, IfName: "Ethernet7",
	}, base.Add(time.Minute))
	g.ObserveDevice(DeviceInput{
		Address: "10.0.0.2", Name: "edge-a", Source: "gnmi", AgentID: "agent-gnmi",
		IfIndex: 8, IfName: "Gi0/7", InterfaceIPs: []string{"192.0.2.7"},
	}, base.Add(2*time.Minute))

	got := g.IdentityConflicts()
	for _, kind := range []IdentityConflictKind{
		IdentityDeviceName,
		IdentityManagementAddress,
		IdentityInterfaceName,
		IdentityInterfaceAddress,
	} {
		conflict := findIdentityConflict(got.Items, kind)
		if conflict == nil {
			t.Fatalf("missing %s conflict: %+v", kind, got.Items)
		}
		if len(conflict.Claims) != 2 {
			t.Fatalf("%s claims = %+v, want two competing assertions", kind, conflict.Claims)
		}
		if conflict.ID == "" || conflict.FirstSeen.IsZero() || conflict.LastSeen.IsZero() {
			t.Fatalf("%s conflict lacks stable identity/timestamps: %+v", kind, conflict)
		}
	}
	if got := findIdentityConflict(got.Items, IdentityInterfaceIndex); got != nil {
		t.Fatalf("same interface name was observed on different devices; subject scoping must avoid a false conflict: %+v", got)
	}
}

func TestIdentityConflictsNeedDistinctValues(t *testing.T) {
	g := NewGraph("tenant-a")
	at := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
	for _, source := range []string{"snmp", "gnmi"} {
		g.ObserveDevice(DeviceInput{
			Address: "10.0.0.1", Name: "edge-a", Source: source,
			AgentID: source + "-collector", IfIndex: 1, IfName: "eth0",
		}, at)
	}
	if got := g.IdentityConflicts(); len(got.Items) != 0 {
		t.Fatalf("matching source assertions manufactured a conflict: %+v", got.Items)
	}
}

func TestIdentityConflictsAreBoundedStableAndReportTruncation(t *testing.T) {
	g := NewGraph("tenant-a")
	at := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
	subject := strings.Repeat("s", maxIdentityTextRunes+20)
	for i := 0; i < maxIdentityClaimsPerSet+1; i++ {
		g.recordIdentityClaim(
			IdentityDeviceName,
			subject,
			strings.Repeat(string(rune('a'+i)), maxIdentityTextRunes+20),
			"SNMP",
			"agent",
			"device.metric.device_name",
			at.Add(time.Duration(i)*time.Second),
		)
	}
	first := g.IdentityConflicts()
	if !first.Truncated || len(first.Items) != 1 || len(first.Items[0].Claims) != maxIdentityClaimsPerSet {
		t.Fatalf("bounded conflict = %+v", first)
	}
	if len([]rune(first.Items[0].Subject)) != maxIdentityTextRunes {
		t.Fatalf("subject length = %d, want %d", len([]rune(first.Items[0].Subject)), maxIdentityTextRunes)
	}
	stableID := first.Items[0].ID
	g.recordIdentityClaim(
		IdentityDeviceName, subject, "replacement", "gnmi", "agent-2",
		"device.metric.device_name", at.Add(time.Hour),
	)
	if got := g.IdentityConflicts(); len(got.Items) != 1 || got.Items[0].ID != stableID {
		t.Fatalf("conflict ID changed across bounded claim replacement: before=%q after=%+v", stableID, got)
	}

	sets := NewGraph("tenant-a")
	for i := 0; i < maxIdentityClaimSets+1; i++ {
		sets.recordIdentityClaim(
			IdentityDeviceName, "subject-"+strconv.Itoa(i), "name", "snmp", "agent",
			"device.metric.device_name", at.Add(time.Duration(i)*time.Second),
		)
	}
	if len(sets.identityClaims) != maxIdentityClaimSets || !sets.IdentityConflicts().Truncated {
		t.Fatalf("claim-set safety bound not enforced: sets=%d snapshot=%+v", len(sets.identityClaims), sets.IdentityConflicts())
	}
}

func TestIdentityConflictTenantIsolationRetentionAndErasure(t *testing.T) {
	tests := []struct {
		name string
		new  func() Store
	}{
		{name: "memory", new: func() Store { return NewMemoryStore() }},
		{name: "indexed", new: func() Store { return NewIndexedStore() }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.new()
			base := time.Date(2026, 7, 27, 8, 0, 0, 0, time.UTC)
			seedIdentityNameConflict(t, store, "tenant-a", "10.0.0.1", "a-old", "a-new", base)
			seedIdentityNameConflict(t, store, "tenant-b", "10.0.0.2", "b-secret", "b-new", base)

			a, err := store.ForTenant("tenant-a")
			if err != nil {
				t.Fatal(err)
			}
			if body := a.IdentityConflicts(); len(body.Items) != 1 ||
				body.Items[0].Subject != "10.0.0.1" ||
				identityClaimsContain(body.Items[0].Claims, "b-secret") {
				t.Fatalf("tenant-a conflict view leaked or lost evidence: %+v", body)
			}

			switch concrete := store.(type) {
			case *MemoryStore:
				if deleted := concrete.PruneTenantBefore("tenant-a", base.Add(time.Hour)); deleted == 0 {
					t.Fatal("retention did not report deletion")
				}
				if len(a.IdentityConflicts().Items) != 0 {
					t.Fatal("tenant-a identity claims survived retention")
				}
				if len(mustTenantStore(t, store, "tenant-b").IdentityConflicts().Items) != 1 {
					t.Fatal("tenant-a retention touched tenant-b")
				}
				if concrete.DeleteTenant("tenant-b") != 1 {
					t.Fatal("tenant-b erasure did not remove graph")
				}
			case *IndexedStore:
				if deleted := concrete.PruneTenantBefore("tenant-a", base.Add(time.Hour)); deleted == 0 {
					t.Fatal("retention did not report deletion")
				}
				if len(a.IdentityConflicts().Items) != 0 {
					t.Fatal("tenant-a identity claims survived retention")
				}
				if len(mustTenantStore(t, store, "tenant-b").IdentityConflicts().Items) != 1 {
					t.Fatal("tenant-a retention touched tenant-b")
				}
				if concrete.DeleteTenant("tenant-b") != 1 {
					t.Fatal("tenant-b erasure did not remove graph")
				}
			default:
				t.Fatalf("unexpected store %T", store)
			}
			if len(mustTenantStore(t, store, "tenant-b").IdentityConflicts().Items) != 0 {
				t.Fatal("tenant-b conflicts survived tenant erasure")
			}
		})
	}
}

func seedIdentityNameConflict(
	t *testing.T,
	store Store,
	tenant, address, first, second string,
	at time.Time,
) {
	t.Helper()
	bound := mustTenantStore(t, store, tenant)
	bound.ObserveDevice(DeviceInput{
		Address: address, Name: first, Source: "snmp", AgentID: tenant + "-snmp",
	}, at)
	bound.ObserveDevice(DeviceInput{
		Address: address, Name: second, Source: "gnmi", AgentID: tenant + "-gnmi",
	}, at.Add(time.Minute))
}

func mustTenantStore(t *testing.T, store Store, tenant string) TenantStore {
	t.Helper()
	bound, err := store.ForTenant(tenant)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func findIdentityConflict(items []IdentityConflict, kind IdentityConflictKind) *IdentityConflict {
	for i := range items {
		if items[i].Kind == kind {
			return &items[i]
		}
	}
	return nil
}

func identityClaimsContain(claims []IdentityClaim, value string) bool {
	for _, claim := range claims {
		if claim.Value == value {
			return true
		}
	}
	return false
}
