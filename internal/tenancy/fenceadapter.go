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
