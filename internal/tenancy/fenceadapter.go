// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"errors"
)

// ErrWriterFenceUnavailable is returned by the fence adapters when a plane's
// decorator was constructed without a fence: an external-store write with no
// erasure barrier fails closed rather than proceeding unfenced.
var ErrWriterFenceUnavailable = errors.New("tenancy: tenant writer fence is unavailable")

// FencedWrite is the ONE erasure-fence adapter every plane's write decorator
// builds on (Foundation-Loop S-a9f9db46). Per-plane behavior is reduced to
// declared policy: the plane supplies its row→tenant projection and its own
// missing-tenant error; everything else — empty batches passing through,
// every row required to carry a tenant, the fence error RETURNED to the
// caller, a nil fence failing closed — is the house semantics, identical on
// every plane by construction instead of by seven hand-stitched copies.
func FencedWrite[T any](
	ctx context.Context,
	fence WriterFence,
	rows []T,
	tenantOf func(T) string,
	missingTenant error,
	write func(context.Context) error,
) error {
	if len(rows) == 0 {
		return write(ctx)
	}
	tenantIDs := make([]string, 0, len(rows))
	for i := range rows {
		id := tenantOf(rows[i])
		if id == "" {
			return missingTenant
		}
		tenantIDs = append(tenantIDs, id)
	}
	return fencedTenants(ctx, fence, tenantIDs, write)
}

// PartitionedFencedWrite is FencedWrite for a BATCHING writer that coalesces
// the independent writes of many tenants into one shared mutation. Where
// FencedWrite fails the whole coalesced batch when any tenant is fenced,
// PartitionedFencedWrite stores every eligible tenant's rows and rejects ONLY
// the fenced tenants' rows, so one tenant's lifecycle state never decides
// another tenant's write (docs/guardrails.md G7-1). It returns a map of exactly
// the tenants that were fenced (keyed by the id as it appears on the row, so a
// caller can attribute the rejection to its own series) and NEVER surfaces one
// tenant's fence error to another tenant's rows. When the fence does not
// implement PartitionedWriterFence it falls back to the all-or-nothing
// WithTenantWrites — correct, only coarser. A nil fence fails closed.
func PartitionedFencedWrite[T any](
	ctx context.Context,
	fence WriterFence,
	rows []T,
	tenantOf func(T) string,
	missingTenant error,
	write func(ctx context.Context, eligible []T) error,
) (map[string]error, error) {
	if len(rows) == 0 {
		return nil, write(ctx, rows)
	}
	if fence == nil {
		return nil, ErrWriterFenceUnavailable
	}
	tenantIDs := make([]string, 0, len(rows))
	for i := range rows {
		id := tenantOf(rows[i])
		if id == "" {
			return nil, missingTenant
		}
		tenantIDs = append(tenantIDs, id)
	}
	pf, ok := fence.(PartitionedWriterFence)
	if !ok {
		// No per-tenant verdict available: preserve correctness with the
		// coarser all-or-nothing fence (one fenced tenant fails the batch).
		return nil, fence.WithTenantWrites(ctx, tenantIDs, func(ctx context.Context) error {
			return write(ctx, rows)
		})
	}
	var fencedOut map[string]error
	err := pf.WithPartitionedTenantWrites(ctx, tenantIDs,
		func(ctx context.Context, fenced map[string]error) error {
			fencedOut = fenced
			if len(fenced) == 0 {
				return write(ctx, rows)
			}
			eligible := make([]T, 0, len(rows))
			for i := range rows {
				if _, bad := fenced[tenantOf(rows[i])]; bad {
					continue
				}
				eligible = append(eligible, rows[i])
			}
			return write(ctx, eligible)
		})
	if err != nil {
		return nil, err
	}
	return fencedOut, nil
}

// FencedTenantWrite is FencedWrite for a mutation already scoped to exactly
// one tenant.
func FencedTenantWrite(
	ctx context.Context,
	fence WriterFence,
	tenantID string,
	missingTenant error,
	write func(context.Context) error,
) error {
	if tenantID == "" {
		return missingTenant
	}
	return fencedTenants(ctx, fence, []string{tenantID}, write)
}

func fencedTenants(ctx context.Context, fence WriterFence, tenantIDs []string, write func(context.Context) error) error {
	if fence == nil {
		return ErrWriterFenceUnavailable
	}
	return fence.WithTenantWrites(ctx, tenantIDs, write)
}
