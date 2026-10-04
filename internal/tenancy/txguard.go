// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import "context"

// TxGuard runs at the start of a tenancy transaction (InTenant / InProvider /
// InTenantProviderMaintenance), on that transaction's own connection, before
// the callback. A non-nil error aborts and rolls the transaction back.
//
// It exists for the cluster singleton fence (PLAT-19): a background singleton
// task carries a lease-epoch guard in its context, so every write transaction
// it opens verifies — transactionally, FOR SHARE against the lease row — that
// its leadership term is still current before committing. No guard in context
// (the default for all request-path and single-node work) is a no-op, so this
// never adds a query to ordinary traffic.
type TxGuard func(ctx context.Context, q Querier) error

type txGuardKey struct{}

// WithTxGuard returns a context whose tenancy transactions run g first. A nil g
// clears any inherited guard.
func WithTxGuard(ctx context.Context, g TxGuard) context.Context {
	return context.WithValue(ctx, txGuardKey{}, g)
}

// runTxGuard invokes the context's guard, if any, on the transaction's querier.
func runTxGuard(ctx context.Context, q Querier) error {
	g, _ := ctx.Value(txGuardKey{}).(TxGuard)
	if g == nil {
		return nil
	}
	return g(ctx, q)
}
