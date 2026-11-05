// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func snmpPrefixPDUForTest(index string, prefix netip.Prefix, value any) gosnmp.SnmpPDU {
	kind := "2"
	address := prefix.Addr().AsSlice()
	if prefix.Addr().Is4() {
		kind = "1"
	}
	parts := []string{index, kind, strconv.Itoa(len(address))}
	for _, octet := range address {
		parts = append(parts, strconv.Itoa(int(octet)))
	}
	parts = append(parts, strconv.Itoa(prefix.Bits()))
	return gosnmp.SnmpPDU{Name: oidIPAddressPrefixOnLink + "." + strings.Join(parts, "."), Type: gosnmp.Integer, Value: value}
}

// Protocol-only fixture proof. A decoded index is not a tenant/canonical
// interface binding and does not replace authenticated real SNMP source proof.
func TestSNMPInterfacePrefixDecodesExactStandardIndicesAndTruth(t *testing.T) {
	for _, text := range []string{"192.0.2.0/24", "192.0.2.0/31", "192.0.2.7/32", "0.0.0.0/0", "2001:db8:1::/64", "2001:db8::/127", "2001:db8::1/128", "::/0"} {
		prefix := netip.MustParsePrefix(text)
		for _, onLink := range []bool{false, true} {
			value := 2
			if onLink {
				value = 1
			}
			pdu := snmpPrefixPDUForTest("2147483647", prefix, value)
			for _, name := range []string{pdu.Name, strings.TrimPrefix(pdu.Name, ".")} {
				pdu.Name = name
				got, err := parseSNMPInterfacePrefix(pdu)
				if err != nil || got.IfIndex != 2147483647 || got.Prefix != prefix || got.OnLink != onLink {
					t.Fatal("prefix index/family/host bits or TruthValue changed", text, got, err)
				}
			}
		}
	}
	for _, value := range []any{int(1), int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1)} {
		got, err := parseSNMPInterfacePrefix(snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), value))
		if err != nil || !got.OnLink {
			t.Fatal("integer TruthValue was lost", err)
		}
	}
}

func TestSNMPInterfacePrefixRejectsMalformedRowsWithoutPartialIdentity(t *testing.T) {
	valid := snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1)
	for name, edit := range map[string]func(*gosnmp.SnmpPDU){
		"wrong-column":       func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".32.1.6.", ".32.1.7.", 1) },
		"wrong-root":         func(p *gosnmp.SnmpPDU) { p.Name = "9" + p.Name },
		"short":              func(p *gosnmp.SnmpPDU) { p.Name = oidIPAddressPrefixOnLink + ".7.1" },
		"long":               func(p *gosnmp.SnmpPDU) { p.Name = oidIPAddressPrefixOnLink + strings.Repeat(".1", 256) },
		"zero-interface":     func(p *gosnmp.SnmpPDU) { *p = snmpPrefixPDUForTest("0", netip.MustParsePrefix("192.0.2.0/24"), 1) },
		"negative-interface": func(p *gosnmp.SnmpPDU) { *p = snmpPrefixPDUForTest("-1", netip.MustParsePrefix("192.0.2.0/24"), 1) },
		"overflow-interface": func(p *gosnmp.SnmpPDU) {
			*p = snmpPrefixPDUForTest("2147483648", netip.MustParsePrefix("192.0.2.0/24"), 1)
		},
		"padded-interface":   func(p *gosnmp.SnmpPDU) { *p = snmpPrefixPDUForTest("07", netip.MustParsePrefix("192.0.2.0/24"), 1) },
		"signed-interface":   func(p *gosnmp.SnmpPDU) { *p = snmpPrefixPDUForTest("+7", netip.MustParsePrefix("192.0.2.0/24"), 1) },
		"unknown-family":     func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".7.1.4.", ".7.3.4.", 1) },
		"wrong-address-size": func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".7.1.4.", ".7.1.3.", 1) },
		"overflow-octet":     func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".192.0.2.0.", ".256.0.2.0.", 1) },
		"negative-octet":     func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".192.0.2.0.", ".-1.0.2.0.", 1) },
		"nondecimal-octet":   func(p *gosnmp.SnmpPDU) { p.Name = strings.Replace(p.Name, ".192.0.2.0.", ".x.0.2.0.", 1) },
		"host-bits":          func(p *gosnmp.SnmpPDU) { *p = snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.7/24"), 1) },
		"v4-length":          func(p *gosnmp.SnmpPDU) { p.Name = strings.TrimSuffix(p.Name, ".24") + ".33" },
		"v6-length": func(p *gosnmp.SnmpPDU) {
			*p = snmpPrefixPDUForTest("7", netip.MustParsePrefix("2001:db8::/64"), 1)
			p.Name = strings.TrimSuffix(p.Name, ".64") + ".129"
		},
		"trailing-index": func(p *gosnmp.SnmpPDU) { p.Name += ".0" },
		"octet-value":    func(p *gosnmp.SnmpPDU) { p.Type = gosnmp.OctetString },
	} {
		t.Run(name, func(t *testing.T) {
			pdu := valid
			edit(&pdu)
			if got, err := parseSNMPInterfacePrefix(pdu); err == nil || got != (snmpInterfacePrefix{}) {
				t.Fatal("malformed prefix returned partial identity", got, err)
			}
		})
	}
	for _, value := range []any{nil, 0, 3, -1, int64(1<<63 - 1), uint64(1<<64 - 1), "1", 1.0, true} {
		pdu := valid
		pdu.Value = value
		if got, err := parseSNMPInterfacePrefix(pdu); err == nil || got != (snmpInterfacePrefix{}) {
			t.Fatal("invalid TruthValue returned a usable prefix", got, err)
		}
	}
}

func FuzzSNMPInterfacePrefix(f *testing.F) {
	f.Add(snmpPrefixPDUForTest("7", netip.MustParsePrefix("192.0.2.0/24"), 1).Name, int64(1))
	f.Add(snmpPrefixPDUForTest("19", netip.MustParsePrefix("2001:db8::/64"), 2).Name, int64(2))
	f.Add("", int64(-1))
	f.Fuzz(func(t *testing.T, name string, value int64) {
		got, err := parseSNMPInterfacePrefix(gosnmp.SnmpPDU{Name: name, Type: gosnmp.Integer, Value: value})
		if err == nil {
			if got.IfIndex == 0 || !got.Prefix.IsValid() || got.Prefix != got.Prefix.Masked() {
				t.Fatal("malformed index was accepted")
			}
		} else if got != (snmpInterfacePrefix{}) {
			t.Fatal("rejected prefix retained partial identity")
		}
	})
}
