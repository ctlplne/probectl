// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSyslogPatternUsesScopedStructureAndClassifiesBoundSource(t *testing.T) {
	first := SyslogEvent{TenantID: "tenant-a", AppName: "device-monitor", Message: "node 192.0.2.41 observed 78 errors"}
	second := SyslogEvent{TenantID: first.TenantID, AppName: first.AppName, Message: "NODE 192.0.2.42 observed 2 errors"}
	left, ok := DeriveSyslogPattern(first, "")
	right, otherOK := DeriveSyslogPattern(second, "")
	if !ok || !otherOK || left.ID != right.ID || left.Kind != SyslogPatternOther || left.Subject != "" {
		t.Fatal("variable fields changed a deterministic structural pattern", left, right)
	}
	second.TenantID = "tenant-b"
	foreign, ok := DeriveSyslogPattern(second, "")
	if !ok || foreign.ID == right.ID {
		t.Fatal("a sibling tenant received a comparable structural key", foreign)
	}
	for _, input := range []struct {
		app, message string
		want         SyslogPatternKind
		subject      string
	}{
		{"%LINK-3-UPDOWN", "Interface Ethernet2/8, changed state to down", SyslogPatternLinkDown, "Ethernet2/8"},
		{"logger", "%BGP-5-ADJCHANGE: neighbor 2001:db8:1::9 Down Interface flap", SyslogPatternBGPDown, "2001:db8:1::9"},
		{"%PLATFORM-2-PS_FAIL", "Power supply 7 failed or shut down (Serial number sample-supply-71)", SyslogPatternSupplyFault, "7"},
		{"%LINK-3-UPDOWN", "Interface Ethernet2/8, changed state to up", SyslogPatternOther, ""},
		{"testing", "Reported %LINK-3-UPDOWN: Interface Ethernet2/8, changed state to down", SyslogPatternOther, ""},
	} {
		row := SyslogEvent{TenantID: first.TenantID, AppName: input.app, Message: input.message}
		got, ok := DeriveSyslogPattern(row, "cisco_ios")
		if !ok || got.Kind != input.want || got.Subject != input.subject {
			t.Fatalf("classification of %q: got %+v", input.message, got)
		}
		got, ok = DeriveSyslogPattern(row, "")
		if !ok || got.Kind != SyslogPatternOther || got.Subject != "" {
			t.Fatalf("unbound source classified %q as %+v", input.message, got)
		}
	}
	frr := SyslogEvent{TenantID: first.TenantID, AppName: "bgpd",
		Message: "BGP: [PXVXG-TFNNT] %ADJCHANGE: neighbor 192.0.2.19(test-peer) in vrf internal Down Admin. shutdown"}
	if got, ok := DeriveSyslogPattern(frr, "frr"); !ok || got.Kind != SyslogPatternOther || got.Subject != "" {
		t.Fatalf("an explicit administrative transition became a fault: %+v", got)
	}
	frr.Message = "[PXVXG-TFNNT] %ADJCHANGE: neighbor 192.0.2.19(test-peer) in vrf internal Down Peer closed the session"
	if got, ok := DeriveSyslogPattern(frr, "frr"); !ok || got.Kind != SyslogPatternBGPDown ||
		got.Subject != "192.0.2.19" || got.RoutingContext != "internal" {
		t.Fatalf("the unexpected local state transition lost its peer context: %+v", got)
	}
}

func TestMemorySyslogPatternsKeepTenantAndOriginalWindow(t *testing.T) {
	store := NewMemoryOpsStore()
	left := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	selection := SyslogPatternSelection{Device: "edge", From: left, To: left.Add(time.Minute), Limit: 1, MaxInputRows: 4}
	tenants := [2]string{"tenant-a", "tenant-b"}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for index := range lane + 1 {
			observed := left.Add(time.Duration(10-index) * time.Second)
			_, err := store.RecordSyslog(ctx, SyslogEvent{TenantID: tenant, Device: "edge",
				Message: "node 192.0.2.45 counted 14 errors", ObservedAt: observed})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		got, err := store.ListSyslogPatterns(ctx, tenant, selection)
		if err != nil || len(got.Patterns) != 1 || got.IndexedRows != int64(lane+1) || got.UnindexedRows != 0 ||
			!got.Patterns[0].FirstAt.Equal(left.Add(time.Duration(10-lane)*time.Second)) {
			t.Fatalf("wrong tenant coverage or event clocks: %+v, %v", got, err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[0]))
	if _, err := store.ListSyslogPatterns(ctx, tenants[1], selection); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("a sibling selector obtained memory reader scope", err)
	}
}
