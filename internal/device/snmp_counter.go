// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import "github.com/gosnmp/gosnmp"

// snmpExactCounter never reconstructs an integer from a float, textual value or
// wrong ASN.1 type. Such legacy samples remain available to the legacy TSDB but
// are explicitly unavailable as exact billing evidence.
func snmpExactCounter(p gosnmp.SnmpPDU, width uint32) *CounterValue {
	if (width != 32 && width != 64) || (width == 32 && p.Type != gosnmp.Counter32) || (width == 64 && p.Type != gosnmp.Counter64) {
		return nil
	}
	var value uint64
	switch v := p.Value.(type) {
	case uint64:
		value = v
	case uint32:
		value = uint64(v)
	case uint:
		value = uint64(v)
	case int:
		if v < 0 {
			return nil
		}
		value = uint64(v)
	case int64:
		if v < 0 {
			return nil
		}
		value = uint64(v)
	default:
		return nil
	}
	if width == 32 && value > 1<<32-1 {
		return nil
	}
	return &CounterValue{Value: value, Width: width}
}
