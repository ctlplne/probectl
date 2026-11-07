// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"errors"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// This connection is owned by one poll. Preserve its previous context while
// bounding every request by the caller's cancellation/deadline. The normal
// library BulkWalk maps several packet errors to nil and is unsuitable for
// evidence that must distinguish complete from partial snapshots.
func (c gosnmpConn) walkInterfacePrefixes(ctx context.Context, fn gosnmp.WalkFunc) error {
	err := c.walkInterfaceColumn(ctx, oidIPAddressPrefixOnLink, fn)
	if errors.Is(err, errors.ErrUnsupported) {
		return errSNMPInterfacePrefixIncomplete
	}
	return err
}

func (c gosnmpConn) walkInterfaceAddresses(ctx context.Context, fn gosnmp.WalkFunc) error {
	return c.walkInterfaceColumn(ctx, oidIPAddressIfIndex, fn)
}

func (c gosnmpConn) walkInterfaceAddressTypes(ctx context.Context, fn gosnmp.WalkFunc) error {
	return c.walkInterfaceColumn(ctx, oidIPAddressType, fn)
}

func (c gosnmpConn) walkInterfaceColumn(ctx context.Context, root string, fn gosnmp.WalkFunc) error {
	if c.g == nil {
		return errSNMPInterfacePrefixIncomplete
	}
	previous := c.g.Context
	c.g.Context = ctx
	defer func() { c.g.Context = previous }()
	return walkSNMPColumnPackets(ctx, root, func(oid string) (*gosnmp.SnmpPacket, error) {
		return c.g.GetBulk([]string{oid}, 0, 32)
	}, fn)
}

// The only successful terminators are a verified increasing OID outside the
// requested column, or EndOfMibView. NoSuchObject/Instance, packet errors and
// empty packets are unavailable even after valid rows have been received.
func walkSNMPInterfacePrefixPackets(ctx context.Context, get func(string) (*gosnmp.SnmpPacket, error), fn gosnmp.WalkFunc) error {
	err := walkSNMPColumnPackets(ctx, oidIPAddressPrefixOnLink, get, fn)
	if errors.Is(err, errors.ErrUnsupported) {
		return errSNMPInterfacePrefixIncomplete
	}
	return err
}

func walkSNMPColumnPackets(ctx context.Context, root string, get func(string) (*gosnmp.SnmpPacket, error), fn gosnmp.WalkFunc) error {
	current := root
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		packet, err := get(current)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil || packet == nil || packet.Error != gosnmp.NoError || packet.ErrorIndex != 0 || len(packet.Variables) == 0 {
			return errSNMPInterfacePrefixIncomplete
		}
		for _, pdu := range packet.Variables {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch pdu.Type {
			case gosnmp.EndOfMibView:
				return nil
			case gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
				if current == root {
					return errors.ErrUnsupported
				}
				return errSNMPInterfacePrefixIncomplete
			}
			if !snmpPrefixOIDFollows(current, pdu.Name) {
				return errSNMPInterfacePrefixIncomplete
			}
			if !strings.HasPrefix(strings.TrimPrefix(pdu.Name, "."), strings.TrimPrefix(root, ".")+".") {
				return nil
			}
			if err := fn(pdu); err != nil {
				return err
			}
			current = pdu.Name
		}
	}
}

// Compare canonical numeric subidentifiers, not text (9 sorts before10).
// Bound hostile names before splitting and reject invalid OIDs rather than
// accepting them as an apparent out-of-column completion.
func snmpPrefixOIDFollows(previous, next string) bool {
	if len(previous) > 1024 || len(next) > 1024 {
		return false
	}
	a := strings.Split(strings.TrimPrefix(previous, "."), ".")
	b := strings.Split(strings.TrimPrefix(next, "."), ".")
	if len(a) < 2 || len(a) > 128 || len(b) < 2 || len(b) > 128 {
		return false
	}
	comparison := 0
	var firstA, firstB uint64
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv uint64
		var err error
		if i < len(a) {
			av, err = snmpPrefixOIDNumber(a[i], 32)
			if err != nil {
				return false
			}
		}
		if i < len(b) {
			bv, err = snmpPrefixOIDNumber(b[i], 32)
			if err != nil {
				return false
			}
		}
		if i == 0 {
			firstA, firstB = av, bv
			if firstA > 2 || firstB > 2 {
				return false
			}
		}
		if i == 1 && (firstA < 2 && av > 39 || firstB < 2 && bv > 39) {
			return false
		}
		if comparison == 0 {
			switch {
			case i >= len(a), bv > av:
				comparison = 1
			case i >= len(b), bv < av:
				comparison = -1
			}
		}
	}
	return comparison > 0
}
