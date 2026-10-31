// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import "context"

// BootstrapDispatch authenticates only encrypted original provenance, then
// requires fresh current authorization. It returns no source or stored grant.
// Unlike CheckHeader it cannot authenticate the payload digest: the caller must
// subsequently load/check the complete ciphertext pair, all ancestor headers,
// current privacy/dependencies and exact original authority before any payload.
// It grants no claim, lease, confirmation or execution permission.
func (c *Codec) BootstrapDispatch(ctx context.Context, candidate DispatchCandidate, operational AuthorizeDispatch, authorize AuthorizeMessage) error {
	if candidate.value == nil || authorize == nil {
		return messageError(ctx, ErrMessageIntegrity)
	}
	// Snapshot the opaque value across external crypto/authorization callbacks.
	value := *candidate.value
	if err := value.scope.validate(ctx); err != nil {
		return err
	}
	id, err := dispatchIdentityFor(ctx, value.scope.OwnerID)
	if err != nil {
		return err
	}
	if err := id.authorize(ctx, operational); err != nil {
		return err
	}
	if err := c.available(); err != nil {
		return err
	}
	if len(value.header) > c.budget.StoredBytes {
		return ErrMessageBudget
	}
	if !c.hasScheme(value.header) {
		return ErrMessageIntegrity
	}
	header, err := c.open(ctx, value.scope.TenantID, value.header, value.scope.aad('h'))
	if err != nil {
		clear(header)
		return messageError(ctx, ErrMessageIntegrity)
	}
	defer clear(header)
	if len(header) > c.budget.HeaderBytes {
		return ErrMessageBudget
	}
	origin, requirements, _, err := decodeMessageHeader(header)
	if err != nil {
		return err
	}
	if _, _, err := origin.ScopedID(value.scope.TenantID, value.scope.OwnerID); err != nil {
		return ErrMessageIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authorize(ctx, value.scope, origin, requirements); err != nil {
		return messageError(ctx, ErrMessageDenied)
	}
	return id.authorize(ctx, operational)
}
