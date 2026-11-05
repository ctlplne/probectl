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
	"sort"

	"github.com/gosnmp/gosnmp"
)

var (
	errSNMPInterfacePrefixBudget     = errors.New("SNMP interface prefix input budget exceeded")
	errSNMPInterfacePrefixIncomplete = errors.New("SNMP interface prefix snapshot incomplete")
)

// These are input/work budgets, not measurements of allocator or process RSS.
// No source-specific protocol limit or silent truncation is implied. The
// caller supplies its remaining collection budget before starting the walk.
type snmpInterfacePrefixLimits struct {
	Rows       uint64
	IndexBytes uint64
}

type snmpInterfacePrefixKey struct {
	IfIndex uint32
	Prefix  netip.Prefix
}

// snmpInterfacePrefixWalker must report protocol errors as errors, including
// those after accepted rows. The library's ordinary BulkWalk does not do so.
type snmpInterfacePrefixWalker interface {
	walkInterfacePrefixes(context.Context, gosnmp.WalkFunc) error
}

// collectSNMPInterfacePrefixes retains a complete supported table or no table.
// An empty walk cannot prove MIB support and is unavailable, never a clear.
// Neither result grants authority over a tenant, router or interface. Default
// and non-on-link prefixes remain observations; association must reject them
// independently. This component is not yet enabled by the steady-state poller.
func collectSNMPInterfacePrefixes(ctx context.Context, conn snmpInterfacePrefixWalker, limits snmpInterfacePrefixLimits) ([]snmpInterfacePrefix, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if conn == nil || limits.Rows == 0 || limits.IndexBytes == 0 {
		return nil, errSNMPInterfacePrefixBudget
	}
	rows := make([]snmpInterfacePrefix, 0)
	seen := make(map[snmpInterfacePrefixKey]struct{})
	var count, indexBytes uint64
	var callbackErr error
	walkErr := conn.walkInterfacePrefixes(ctx, func(pdu gosnmp.SnmpPDU) error {
		// Retain the first refusal even if a transport adapter ignores a
		// callback error and later returns success.
		if callbackErr != nil {
			return callbackErr
		}
		if callbackErr = ctx.Err(); callbackErr != nil {
			return callbackErr
		}
		cost := uint64(len(pdu.Name))
		if count >= limits.Rows || cost > limits.IndexBytes-indexBytes {
			callbackErr = errSNMPInterfacePrefixBudget
			return callbackErr
		}
		count++
		indexBytes += cost
		row, err := parseSNMPInterfacePrefix(pdu)
		if err != nil {
			callbackErr = err
			return callbackErr
		}
		key := snmpInterfacePrefixKey{IfIndex: row.IfIndex, Prefix: row.Prefix}
		if _, duplicate := seen[key]; duplicate {
			callbackErr = errSNMPInterfacePrefixIncomplete
			return callbackErr
		}
		seen[key] = struct{}{}
		rows = append(rows, row)
		return nil
	})
	if callbackErr != nil {
		return nil, callbackErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if walkErr != nil || len(rows) == 0 {
		// Transport errors can contain untrusted peer/credential text. The
		// typed outcome needs no copy of that text in provenance or logs.
		return nil, errSNMPInterfacePrefixIncomplete
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].IfIndex != rows[j].IfIndex {
			return rows[i].IfIndex < rows[j].IfIndex
		}
		if compared := rows[i].Prefix.Addr().Compare(rows[j].Prefix.Addr()); compared != 0 {
			return compared < 0
		}
		return rows[i].Prefix.Bits() < rows[j].Prefix.Bits()
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}
