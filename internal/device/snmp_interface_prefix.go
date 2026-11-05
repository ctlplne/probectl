// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// RFC4293 IP-MIB: prefix Entry6 is the on-link TruthValue. The instance index
// is (ifIndex, address type, address octet-string, prefix length).
const oidIPAddressPrefixOnLink = ".1.3.6.1.2.1.4.32.1.6"

var errSNMPInterfacePrefix = errors.New("invalid SNMP interface prefix row")

type snmpInterfacePrefix struct {
	IfIndex uint32
	Prefix  netip.Prefix
	OnLink  bool
}

// parseSNMPInterfacePrefix treats every MIB value/index as untrusted
// (docs/guardrails.md G7-12). A successful decoded row confers no tenant,
// canonical-interface or routing authority. Default prefixes remain protocol
// data; association code must independently reject wildcard/ambiguous matches.
func parseSNMPInterfacePrefix(pdu gosnmp.SnmpPDU) (snmpInterfacePrefix, error) {
	zero := snmpInterfacePrefix{}
	// Supported IPv4/IPv6 instances fit below256 text bytes, including the
	// largest InterfaceIndex and all decimal octets. Bound before splitting.
	if pdu.Type != gosnmp.Integer || len(pdu.Name) > 256 {
		return zero, errSNMPInterfacePrefix
	}
	suffix, ok := strings.CutPrefix(strings.TrimPrefix(pdu.Name, "."), strings.TrimPrefix(oidIPAddressPrefixOnLink, ".")+".")
	if !ok {
		return zero, errSNMPInterfacePrefix
	}
	fields := strings.Split(suffix, ".")
	if len(fields) < 4 {
		return zero, errSNMPInterfacePrefix
	}
	index, err := snmpPrefixOIDNumber(fields[0], 31)
	if err != nil || index == 0 || index > 2147483647 {
		return zero, errSNMPInterfacePrefix
	}
	var size int
	var maxBits uint64
	switch fields[1] {
	case "1":
		size, maxBits = 4, 32
	case "2":
		size, maxBits = 16, 128
	default:
		return zero, errSNMPInterfacePrefix
	}
	if fields[2] != strconv.Itoa(size) || len(fields) != size+4 {
		return zero, errSNMPInterfacePrefix
	}
	var bytes [16]byte
	for i := 0; i < size; i++ {
		value, err := snmpPrefixOIDNumber(fields[i+3], 8)
		if err != nil || value > 255 {
			return zero, errSNMPInterfacePrefix
		}
		bytes[i] = byte(value)
	}
	length, err := snmpPrefixOIDNumber(fields[size+3], 8)
	if err != nil || length > maxBits || length > 128 {
		return zero, errSNMPInterfacePrefix
	}
	address := netip.AddrFrom16(bytes)
	if size == 4 {
		address = netip.AddrFrom4([4]byte{bytes[0], bytes[1], bytes[2], bytes[3]})
	}
	prefix := netip.PrefixFrom(address, int(length))
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return zero, errSNMPInterfacePrefix
	}
	onLink, err := snmpPrefixTruthValue(pdu.Value)
	if err != nil {
		return zero, err
	}
	return snmpInterfacePrefix{IfIndex: uint32(index), Prefix: prefix, OnLink: onLink}, nil
}

func snmpPrefixOIDNumber(text string, bits int) (uint64, error) {
	if text == "" || len(text) > 10 || len(text) > 1 && text[0] == '0' {
		return 0, errSNMPInterfacePrefix
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, errSNMPInterfacePrefix
		}
	}
	value, err := strconv.ParseUint(text, 10, bits)
	if err != nil {
		return 0, errSNMPInterfacePrefix
	}
	return value, nil
}

type snmpPrefixInteger interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

func snmpPrefixTruth[T snmpPrefixInteger](value T) (bool, error) {
	switch value {
	case 1:
		return true, nil
	case 2:
		return false, nil
	default:
		return false, errSNMPInterfacePrefix
	}
}
func snmpPrefixTruthValue(value any) (bool, error) {
	switch v := value.(type) {
	case int:
		return snmpPrefixTruth(v)
	case int8:
		return snmpPrefixTruth(v)
	case int16:
		return snmpPrefixTruth(v)
	case int32:
		return snmpPrefixTruth(v)
	case int64:
		return snmpPrefixTruth(v)
	case uint:
		return snmpPrefixTruth(v)
	case uint8:
		return snmpPrefixTruth(v)
	case uint16:
		return snmpPrefixTruth(v)
	case uint32:
		return snmpPrefixTruth(v)
	case uint64:
		return snmpPrefixTruth(v)
	default:
		return false, errSNMPInterfacePrefix
	}
}
