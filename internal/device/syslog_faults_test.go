// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import "testing"

func TestSyslogFaultBindingFencesDeviceAndRoutingInstance(t *testing.T) {
	source := SyslogPatternSource{Family: "frr", Name: "edge-collector", FaultDevice: "edge-overlap", RoutingInstance: "peering"}
	row := SyslogEvent{TenantID: "tenant-a", Device: "edge-overlap", Hostname: "edge-overlap", AppName: "bgpd",
		Message: "BGP: [HZN6M-XRM1G] %NOTIFICATION: sent to neighbor 192.0.2.9 4/0 (Hold Timer Expired) 0 bytes"}
	pattern, ok := DeriveSyslogPattern(row, source.Family)
	if !ok || pattern.Kind != SyslogPatternBGPDown || pattern.Subject != "192.0.2.9" || pattern.RoutingContext != "" {
		t.Fatal("the original FRR notification lost its observed peer or gained an unreported instance", pattern)
	}
	want := syslogFaultForPattern(row, pattern, source)
	if want.target == "" || want.subject != pattern.Subject {
		t.Fatal("the operator-bound FRR notification was not admitted", want)
	}
	withoutHostname := row
	withoutHostname.Hostname = ""
	if got := syslogFaultForPattern(withoutHostname, pattern, source); got.target != "" {
		t.Fatal("a device label stood in for an absent original hostname", got)
	}
	for _, unbound := range []SyslogPatternSource{
		{Family: "frr", Name: source.Name},
		{Family: "frr", Name: source.Name, FaultDevice: source.FaultDevice},
		{Family: "frr", Name: source.Name, FaultDevice: "another-edge", RoutingInstance: source.RoutingInstance},
	} {
		if got := syslogFaultForPattern(row, pattern, unbound); got.target != "" {
			t.Fatal("an unbound or ambiguous device fault obtained a target", got)
		}
	}
	row.TenantID = "tenant-b"
	if foreign := syslogFaultForPattern(row, pattern, source); foreign.target == "" || foreign.target == want.target {
		t.Fatal("an overlapping tenant reused the original target key", foreign)
	}
	row.Message = "[PXVXG-TFNNT] %ADJCHANGE: neighbor 192.0.2.9(edge-b) in vrf internal Down Peer closed the session"
	mismatch, _ := DeriveSyslogPattern(row, source.Family)
	if got := syslogFaultForPattern(row, mismatch, source); got.target != "" {
		t.Fatal("the reported VRF conflicts with the source binding", got)
	}
	row.Message = "BGP: [PXVXG-TFNNT] %ADJCHANGE: neighbor 192.0.2.9(edge-b) in vrf peering Down Admin. shutdown"
	planned, _ := DeriveSyslogPattern(row, source.Family)
	if got := syslogFaultForPattern(row, planned, source); got.target != "" {
		t.Fatal("an administrative shutdown became a device fault", got)
	}
}
