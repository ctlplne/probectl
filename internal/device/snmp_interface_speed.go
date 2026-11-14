// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

const oidIfSpeed = ".1.3.6.1.2.1.2.2.1.5"

// A speed is observed in this poll, not a claim that the link kept the same
// rate between polls. Positive ifHighSpeed takes precedence; zero or missing
// values use ifSpeed's finer units. Partial columns never attest their prefix.
func snmpInterfaceSpeeds(ctx context.Context, conn snmpConn, interfaces map[uint32]Interface, observe func(uint32, gosnmp.SnmpPDU)) map[uint32]uint64 {
	high, complete := snmpSpeedColumn(ctx, conn, oidIfHighSpeed, interfaces, observe)
	if !complete {
		return nil
	}
	result := make(map[uint32]uint64, len(high))
	for index, value := range high {
		if value != 0 {
			result[index] = uint64(value) * 1000000
		}
	}
	if len(result) == len(interfaces) {
		return result
	}
	low, complete := snmpSpeedColumn(ctx, conn, oidIfSpeed, interfaces, nil)
	if !complete {
		return result // Complete high-speed observations remain independently valid.
	}
	for index := range interfaces {
		if _, known := result[index]; known {
			continue
		}
		if value, known := low[index]; known {
			result[index] = uint64(value)
		} else if value, known := high[index]; known && value == 0 {
			result[index] = 0 // Preserve a returned zero, never invent one for absence.
		}
	}
	return result
}

func snmpSpeedColumn(ctx context.Context, conn snmpConn, root string, interfaces map[uint32]Interface, observe func(uint32, gosnmp.SnmpPDU)) (map[uint32]uint32, bool) {
	result := make(map[uint32]uint32)
	validColumn := true
	err := conn.BulkWalk(root, func(p gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || p.Type == gosnmp.EndOfMibView {
			return nil
		}
		suffix, found := strings.CutPrefix(p.Name, root+".")
		index, err := strconv.ParseUint(suffix, 10, 32)
		if found && err == nil && index > 0 && observe != nil {
			observe(uint32(index), p)
		}
		if !found || err != nil || index == 0 || strconv.FormatUint(index, 10) != suffix || p.Type != gosnmp.Gauge32 {
			validColumn = false
			return nil
		}
		value, valid := snmpExactUnsigned(p.Value, 32)
		if !valid {
			validColumn = false
			return nil
		}
		if _, owned := interfaces[uint32(index)]; !owned {
			return nil
		}
		if _, duplicate := result[uint32(index)]; duplicate {
			validColumn = false
			return nil
		}
		result[uint32(index)] = uint32(value)
		return nil
	})
	return result, validColumn && err == nil && ctx.Err() == nil
}
