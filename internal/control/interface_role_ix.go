// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) interfaceRoleIXSnapshot(at time.Time) opendata.IXPrefixSnapshot {
	return s.openDataEnricher.IXPrefixes(at)
}

// Only the storage-authorized canonical interface addresses reach the shared
// public index. A public prefix is evidence, never identity or authorization.
func matchInterfaceRoleIXInputs(ctx context.Context, in store.InterfaceRoleInputs, snapshot opendata.IXPrefixSnapshot, budget interfaceRoleBudget) ([]interfaceRoleIXPrefix, error) {
	tenant, present := tenancy.FromContext(ctx)
	scope, err := in.Scope.Normalize()
	if err != nil || scope != in.Scope || !present || tenant.String() != scope.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	if in.SNMP == nil {
		return nil, ctx.Err()
	}
	matches, err := snapshot.Match(ctx, in.SNMP.Addresses, budget.MemoryBytes, budget.WorkUnits)
	if errors.Is(err, opendata.ErrIXPrefixBudget) {
		return nil, errInterfaceRoleBudget
	}
	if err != nil {
		return nil, err
	}
	out := make([]interfaceRoleIXPrefix, 0, len(matches))
	for _, match := range matches {
		out = append(out, interfaceRoleIXPrefix{SourceID: match.SourceID, Prefix: match.Prefix,
			Clock: interfaceRoleClock{ObservedAt: snapshot.ObservedAt, ValidUntil: snapshot.ValidUntil}})
	}
	return out, nil
}
