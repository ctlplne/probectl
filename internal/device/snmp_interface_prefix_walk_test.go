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
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestSNMPInterfacePrefixPacketsRequireProtocolCompletion(t *testing.T) {
	one := snmpPrefixPDUForTest("9", netip.MustParsePrefix("192.0.2.0/24"), 1)
	two := snmpPrefixPDUForTest("10", netip.MustParsePrefix("2001:db8::/64"), 2)
	for _, terminal := range []gosnmp.SnmpPDU{
		{Name: two.Name, Type: gosnmp.EndOfMibView},
		{Name: ".1.3.6.1.2.1.4.32.1.7.1", Type: gosnmp.Integer, Value: 1},
	} {
		calls, rows := 0, 0
		err := walkSNMPInterfacePrefixPackets(context.Background(), func(oid string) (*gosnmp.SnmpPacket, error) {
			calls++
			switch calls {
			case 1:
				if oid != oidIPAddressPrefixOnLink {
					t.Fatal("first request did not select the exact prefix column")
				}
				return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{one}}, nil
			case 2:
				if oid != one.Name {
					t.Fatal("next request lost its last exact numeric OID")
				}
				return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{two, terminal}}, nil
			default:
				t.Fatal("walk continued after explicit completion")
				return nil, nil
			}
		}, func(gosnmp.SnmpPDU) error { rows++; return nil })
		if err != nil || calls != 2 || rows != 2 {
			t.Fatal("complete multi-packet prefix walk was not retained", err, calls, rows)
		}
	}
}

func TestSNMPInterfacePrefixPacketsRejectErrorsAfterPositiveRows(t *testing.T) {
	one := snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1)
	two := snmpPrefixPDUForTest("8", netip.MustParsePrefix("2001:db8::/64"), 1)
	completeTail := []gosnmp.SnmpPDU{two, {Name: two.Name, Type: gosnmp.EndOfMibView}}
	for _, test := range []struct {
		name   string
		packet *gosnmp.SnmpPacket
		err    error
	}{
		{"transport", nil, errors.New("untrusted transport detail")},
		{"nil-packet", nil, nil},
		{"empty-packet", &gosnmp.SnmpPacket{}, nil},
		{"packet-generr", &gosnmp.SnmpPacket{Error: gosnmp.GenErr, Variables: completeTail}, nil},
		{"packet-noaccess", &gosnmp.SnmpPacket{Error: gosnmp.NoAccess, Variables: completeTail}, nil},
		{"packet-toobig", &gosnmp.SnmpPacket{Error: gosnmp.TooBig, Variables: completeTail}, nil},
		{"unexpected-error-index", &gosnmp.SnmpPacket{ErrorIndex: 1, Variables: completeTail}, nil},
		{"no-such-object", &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: one.Name, Type: gosnmp.NoSuchObject}}}, nil},
		{"no-such-instance", &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: one.Name, Type: gosnmp.NoSuchInstance}}}, nil},
		{"repeated-oid", &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{one}}, nil},
		{"backward-oid", &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: oidIPAddressPrefixOnLink + ".1", Type: gosnmp.Integer, Value: 1}}}, nil},
		{"invalid-outside-oid", &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: ".9.1", Type: gosnmp.Integer, Value: 1}}}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls, rows := 0, 0
			err := walkSNMPInterfacePrefixPackets(context.Background(), func(string) (*gosnmp.SnmpPacket, error) {
				calls++
				if calls == 1 {
					return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{one}}, nil
				}
				if calls > 2 {
					t.Fatal("walk continued after protocol failure")
				}
				return test.packet, test.err
			}, func(gosnmp.SnmpPDU) error { rows++; return nil })
			if !errors.Is(err, errSNMPInterfacePrefixIncomplete) || calls != 2 || rows != 1 {
				t.Fatal("late protocol failure became successful prefix completion", err, calls, rows)
			}
		})
	}
}

func TestSNMPInterfacePrefixPacketsPreserveCancellationAndCallbackRefusal(t *testing.T) {
	one := snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1)
	for _, phase := range []string{"before-request", "during-request", "callback"} {
		ctx, cancel := context.WithCancel(context.Background())
		calls, rows := 0, 0
		if phase == "before-request" {
			cancel()
		}
		refused := errors.New("collector input budget refused row")
		err := walkSNMPInterfacePrefixPackets(ctx, func(string) (*gosnmp.SnmpPacket, error) {
			calls++
			if phase == "during-request" {
				cancel()
			}
			return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{one}}, nil
		}, func(gosnmp.SnmpPDU) error { rows++; return refused })
		cancel()
		if phase == "callback" {
			if !errors.Is(err, refused) || calls != 1 || rows != 1 {
				t.Fatal("packet walk lost collector refusal", err, calls, rows)
			}
		} else if !errors.Is(err, context.Canceled) || rows != 0 || phase == "before-request" && calls != 0 {
			t.Fatal("cancelled walk performed or accepted prefix IO", err, calls, rows)
		}
	}
	if err := (gosnmpConn{}).walkInterfacePrefixes(context.Background(), func(gosnmp.SnmpPDU) error { return nil }); !errors.Is(err, errSNMPInterfacePrefixIncomplete) {
		t.Fatal("missing real client returned successful completion", err)
	}
}

func TestSNMPPrefixOIDFollowsNumericCanonicalOrder(t *testing.T) {
	for _, test := range []struct {
		previous, next string
		want           bool
	}{
		{".1.3.9", ".1.3.10", true},
		{".1.3.10", ".1.3.9", false},
		{"1.3.9", ".1.3.9.0", true},
		{".1.3.9.0", "1.3.9", false},
		{".1.3.9", "1.3.9", false},
		{".1.3.9", ".1.3.10.x", false},
		{".1.3.9", ".1.3.010", false},
		{".1.3.9", ".1.3.4294967296", false},
		{".1.3.9", ".3.1", false},
		{".1.3.9", ".1.40", false},
		{".1.3.9", ".2.999", true},
		{".1.3.9", "..1.3.10", false},
		{".1.3.9", ".1.3" + strings.Repeat(".1", 129), false},
		{".1.3.9", ".1.3." + strings.Repeat("1", 1024), false},
	} {
		if got := snmpPrefixOIDFollows(test.previous, test.next); got != test.want {
			t.Fatal("OID comparison accepted malformed/order-changing data", test.previous, test.next, got)
		}
	}
}
