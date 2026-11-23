// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/ctlplne/probectl/internal/entity"
)

const (
	snmpEntityPhysical = ".1.3.6.1.2.1.47.1.1.1.1"
	snmpEntityClass    = snmpEntityPhysical + ".5"
)

var errSNMPPhysicalInventory = errors.New("SNMP physical inventory has incomplete or invalid entity evidence")

type snmpPhysicalTextColumn struct {
	suffix   string
	maxBytes int
	store    func(*entity.SNMPPhysicalComponent, string)
}

var snmpPhysicalTextColumns = []snmpPhysicalTextColumn{
	{".8", 255, func(c *entity.SNMPPhysicalComponent, value string) { c.Hardware = value }},
	{".9", 255, func(c *entity.SNMPPhysicalComponent, value string) { c.Firmware = value }},
	{".10", 255, func(c *entity.SNMPPhysicalComponent, value string) { c.Software = value }},
	{".11", 32, func(c *entity.SNMPPhysicalComponent, value string) { c.Serial = value }},
	{".12", 255, func(c *entity.SNMPPhysicalComponent, value string) { c.Manufacturer = value }},
	{".13", 255, func(c *entity.SNMPPhysicalComponent, value string) { c.Model = value }},
}

type snmpPhysicalColumnWalker interface {
	walkEvidenceColumn(context.Context, string, gosnmp.WalkFunc) error
}

// pollSNMPPhysicalInventory builds one original ENTITY-MIB snapshot. Each
// component keeps only the leaves at its own entity index. The packet walker
// verifies completion, including device status after an initial valid row.
func pollSNMPPhysicalInventory(ctx context.Context, conn snmpConn) ([]entity.SNMPPhysicalComponent, error) {
	walker, ok := conn.(snmpPhysicalColumnWalker)
	if !ok {
		return nil, errSNMPPhysicalInventory
	}
	components := make(map[uint32]*entity.SNMPPhysicalComponent)
	if err := walkSNMPPhysicalColumn(ctx, walker, snmpEntityClass, func(index uint32, pdu gosnmp.SnmpPDU) error {
		value, valid := snmpExactUnsigned(pdu.Value, 32)
		if !valid || pdu.Type != gosnmp.Integer || value < 1 || value > 14 {
			return errSNMPPhysicalInventory
		}
		components[index] = &entity.SNMPPhysicalComponent{Index: index, Class: uint32(value)}
		return nil
	}); err != nil || len(components) == 0 {
		return nil, err
	}

	if err := walkSNMPPhysicalColumn(ctx, walker, snmpEntityPhysical+".4", func(index uint32, pdu gosnmp.SnmpPDU) error {
		if component := components[index]; component != nil {
			value, valid := snmpExactUnsigned(pdu.Value, 32)
			if !valid || pdu.Type != gosnmp.Integer || value > 1<<31-1 || value == uint64(index) {
				return errSNMPPhysicalInventory
			}
			parent := uint32(value)
			component.Parent = &parent
		}
		return nil
	}); err != nil {
		return nil, err
	}
	for _, column := range snmpPhysicalTextColumns {
		err := walkSNMPPhysicalColumn(ctx, walker, snmpEntityPhysical+column.suffix, func(index uint32, pdu gosnmp.SnmpPDU) error {
			if component := components[index]; component != nil {
				text, valid := snmpPhysicalText(pdu, column.maxBytes)
				if !valid {
					return errSNMPPhysicalInventory
				}
				column.store(component, text)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	rows := make([]entity.SNMPPhysicalComponent, 0, len(components))
	for _, component := range components {
		rows = append(rows, *component)
	}
	slices.SortFunc(rows, func(a, b entity.SNMPPhysicalComponent) int {
		return cmp.Compare(a.Index, b.Index)
	})
	return rows, ctx.Err()
}

func walkSNMPPhysicalColumn(ctx context.Context, conn snmpPhysicalColumnWalker, oid string, consume func(uint32, gosnmp.SnmpPDU) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	seen := make(map[uint32]bool)
	err := conn.walkEvidenceColumn(ctx, oid, func(pdu gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		parts, valid := trailingIndex(pdu.Name, oid, 1)
		if !valid || parts[0] == 0 || parts[0] > 1<<31-1 || seen[parts[0]] || len(seen) >= entity.MaxSNMPPhysicalComponents {
			return errSNMPPhysicalInventory
		}
		seen[parts[0]] = true
		return consume(parts[0], pdu)
	})
	if errors.Is(err, errors.ErrUnsupported) && len(seen) == 0 {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("ENTITY-MIB column %s: %w", oid, err)
	}
	return ctx.Err()
}

func snmpPhysicalText(pdu gosnmp.SnmpPDU, maxBytes int) (string, bool) {
	if pdu.Type != gosnmp.OctetString {
		return "", false
	}
	text, ok := pdu.Value.([]byte)
	if !ok || len(text) > maxBytes || !utf8.Valid(text) {
		return "", false
	}
	for _, value := range string(text) {
		if !unicode.IsPrint(value) {
			return "", false
		}
	}
	return string(text), true
}
