// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

const oidIfCounterDiscontinuity = ".1.3.6.1.2.1.31.1.1.1.19"

// snmpExactCounter never reconstructs an integer from a float, textual value or
// wrong ASN.1 type. Such legacy samples remain available to the legacy TSDB but
// are explicitly unavailable as exact billing evidence.
func snmpExactCounter(p gosnmp.SnmpPDU, width uint32) *CounterValue {
	if (width != 32 && width != 64) || (width == 32 && p.Type != gosnmp.Counter32) || (width == 64 && p.Type != gosnmp.Counter64) {
		return nil
	}
	value, ok := snmpExactUnsigned(p.Value, width)
	if !ok {
		return nil
	}
	return &CounterValue{Value: value, Width: width}
}

func snmpExactUnsigned(input any, width uint32) (uint64, bool) {
	if width != 32 && width != 64 {
		return 0, false
	}
	var value uint64
	switch v := input.(type) {
	case uint64:
		value = v
	case uint32:
		value = uint64(v)
	case uint:
		value = uint64(v)
	case int:
		if v < 0 {
			return 0, false
		}
		value = uint64(v)
	case int64:
		if v < 0 {
			return 0, false
		}
		value = uint64(v)
	default:
		return 0, false
	}
	if width == 32 && value > 1<<32-1 {
		return 0, false
	}
	return value, true
}

// A partial/ambiguous discontinuity walk cannot qualify earlier rows as a
// complete poll. Existing legacy metrics still degrade gracefully; exact
// counter values remain raw observations, with continuity explicitly unknown.
func snmpCounterDiscontinuities(ctx context.Context, conn snmpConn, interfaces map[uint32]Interface) (map[uint32]uint32, bool) {
	values := make(map[uint32]uint32)
	invalid := errors.New("incomplete or ambiguous interface counter clock")
	err := conn.BulkWalk(oidIfCounterDiscontinuity, func(p gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		suffix, present := strings.CutPrefix(p.Name, oidIfCounterDiscontinuity+".")
		index, err := strconv.ParseUint(suffix, 10, 32)
		if !present || err != nil || index == 0 || strconv.FormatUint(index, 10) != suffix || p.Type != gosnmp.TimeTicks {
			return invalid
		}
		value, ok := snmpExactUnsigned(p.Value, 32)
		if !ok {
			return invalid
		}
		if _, owned := interfaces[uint32(index)]; !owned {
			return nil // Never allocate extra metadata for an unobserved interface.
		}
		if _, duplicate := values[uint32(index)]; duplicate {
			return invalid
		}
		values[uint32(index)] = uint32(value)
		return nil
	})
	if err != nil || ctx.Err() != nil {
		return nil, false
	}
	return values, true
}
