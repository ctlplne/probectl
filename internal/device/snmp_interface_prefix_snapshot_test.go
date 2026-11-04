// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// A protocol fixture, not a real SNMP transport or authenticated sender proof.
type snmpPrefixSnapshotConn struct {
	rows           []gosnmp.SnmpPDU
	walkErr        error
	ignoreRefusals bool
	afterRow       func(int)
	afterWalk      func()
	calls          int
}

func (c *snmpPrefixSnapshotConn) walkInterfacePrefixes(_ context.Context, fn gosnmp.WalkFunc) error {
	c.calls++
	for i, row := range c.rows {
		err := fn(row)
		if c.afterRow != nil {
			c.afterRow(i)
		}
		if err != nil && !c.ignoreRefusals {
			return err
		}
	}
	if c.afterWalk != nil {
		c.afterWalk()
	}
	return c.walkErr
}

func snmpPrefixSnapshotBudgetForTest(rows []gosnmp.SnmpPDU) snmpInterfacePrefixLimits {
	budget := snmpInterfacePrefixLimits{Rows: uint64(len(rows))}
	for _, row := range rows {
		budget.IndexBytes += uint64(len(row.Name))
	}
	return budget
}

func TestSNMPInterfacePrefixSnapshotRetainsCompleteOrderedProtocolData(t *testing.T) {
	input := []gosnmp.SnmpPDU{
		snmpPrefixPDUForTest("8", netip.MustParsePrefix("2001:db8:2::/64"), 1),
		snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 2),
		snmpPrefixPDUForTest("7", netip.MustParsePrefix("0.0.0.0/0"), 1),
		snmpPrefixPDUForTest("8", netip.MustParsePrefix("2001:db8:1::/64"), 1),
		snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/31"), 1),
	}
	want := []snmpInterfacePrefix{
		{IfIndex: 7, Prefix: netip.MustParsePrefix("0.0.0.0/0"), OnLink: true},
		{IfIndex: 7, Prefix: netip.MustParsePrefix("192.0.2.0/24"), OnLink: false},
		{IfIndex: 7, Prefix: netip.MustParsePrefix("192.0.2.0/31"), OnLink: true},
		{IfIndex: 8, Prefix: netip.MustParsePrefix("2001:db8:1::/64"), OnLink: true},
		{IfIndex: 8, Prefix: netip.MustParsePrefix("2001:db8:2::/64"), OnLink: true},
	}
	for _, reversed := range []bool{false, true} {
		conn := &snmpPrefixSnapshotConn{rows: append([]gosnmp.SnmpPDU(nil), input...)}
		if reversed {
			for i, j := 0, len(conn.rows)-1; i < j; i, j = i+1, j-1 {
				conn.rows[i], conn.rows[j] = conn.rows[j], conn.rows[i]
			}
		}
		got, err := collectSNMPInterfacePrefixes(context.Background(), conn, snmpPrefixSnapshotBudgetForTest(input))
		if err != nil || !reflect.DeepEqual(got, want) || conn.calls != 1 {
			t.Fatal("complete prefix table changed with walk order or exact budget", got, err)
		}
		conn.rows[0].Value = 2
		conn.rows[0].Name = "mutated after capture"
		if !reflect.DeepEqual(got, want) {
			t.Fatal("snapshot retained mutable PDU storage")
		}
	}
	empty := &snmpPrefixSnapshotConn{}
	got, err := collectSNMPInterfacePrefixes(context.Background(), empty, snmpInterfacePrefixLimits{Rows: 1, IndexBytes: 1})
	if !errors.Is(err, errSNMPInterfacePrefixIncomplete) || got != nil {
		t.Fatal("ambiguous empty table became an authoritative clear", got, err)
	}
}

func TestSNMPInterfacePrefixSnapshotRefusesIncompleteOrOverBudgetWalk(t *testing.T) {
	one := snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1)
	two := snmpPrefixPDUForTest("8", netip.MustParsePrefix("2001:db8::/64"), 1)
	base := []gosnmp.SnmpPDU{one, two}
	for _, test := range []struct {
		name   string
		rows   []gosnmp.SnmpPDU
		budget snmpInterfacePrefixLimits
		walk   error
		want   error
	}{
		{"walk-failed-after-rows", base, snmpPrefixSnapshotBudgetForTest(base), errors.New("untrusted transport detail"), errSNMPInterfacePrefixIncomplete},
		{"walk-unavailable", nil, snmpPrefixSnapshotBudgetForTest(base), errors.New("missing MIB"), errSNMPInterfacePrefixIncomplete},
		{"late-malformed", []gosnmp.SnmpPDU{one, {Name: "bad", Type: gosnmp.Integer, Value: 1}}, snmpPrefixSnapshotBudgetForTest(base), nil, errSNMPInterfacePrefix},
		{"duplicate", []gosnmp.SnmpPDU{one, one}, snmpInterfacePrefixLimits{Rows: 2, IndexBytes: 1024}, nil, errSNMPInterfacePrefixIncomplete},
		{"conflicting-duplicate", []gosnmp.SnmpPDU{one, {Name: one.Name, Type: gosnmp.Integer, Value: 2}}, snmpInterfacePrefixLimits{Rows: 2, IndexBytes: 1024}, nil, errSNMPInterfacePrefixIncomplete},
		{"late-row-budget", base, snmpInterfacePrefixLimits{Rows: 1, IndexBytes: 1024}, nil, errSNMPInterfacePrefixBudget},
		{"late-index-budget", base, snmpInterfacePrefixLimits{Rows: 2, IndexBytes: uint64(len(one.Name) + len(two.Name) - 1)}, nil, errSNMPInterfacePrefixBudget},
		{"zero-row-budget", base, snmpInterfacePrefixLimits{IndexBytes: 1024}, nil, errSNMPInterfacePrefixBudget},
		{"zero-index-budget", base, snmpInterfacePrefixLimits{Rows: 2}, nil, errSNMPInterfacePrefixBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, ignore := range []bool{false, true} {
				conn := &snmpPrefixSnapshotConn{rows: test.rows, walkErr: test.walk, ignoreRefusals: ignore}
				got, err := collectSNMPInterfacePrefixes(context.Background(), conn, test.budget)
				if !errors.Is(err, test.want) || got != nil {
					t.Fatal("incomplete prefix walk returned usable partial evidence", got, err)
				}
			}
		})
	}
	if got, err := collectSNMPInterfacePrefixes(context.Background(), nil, snmpPrefixSnapshotBudgetForTest(base)); !errors.Is(err, errSNMPInterfacePrefixBudget) || got != nil {
		t.Fatal("missing transport returned usable prefix evidence", got, err)
	}
}

func TestSNMPInterfacePrefixSnapshotCancellationReturnsNoPartialTable(t *testing.T) {
	rows := []gosnmp.SnmpPDU{
		snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1),
		snmpPrefixPDUForTest("8", netip.MustParsePrefix("2001:db8::/64"), 1),
	}
	for _, phase := range []string{"before-walk", "between-rows", "after-walk"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			conn := &snmpPrefixSnapshotConn{rows: rows, ignoreRefusals: true}
			switch phase {
			case "before-walk":
				cancel()
			case "between-rows":
				conn.afterRow = func(int) { cancel() }
			case "after-walk":
				conn.afterWalk = cancel
			}
			got, err := collectSNMPInterfacePrefixes(ctx, conn, snmpPrefixSnapshotBudgetForTest(rows))
			if !errors.Is(err, context.Canceled) || got != nil || phase == "before-walk" && conn.calls != 0 {
				t.Fatal("cancelled prefix walk returned partial evidence or started IO", got, err)
			}
		})
	}
}
