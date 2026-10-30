// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"slices"

	"github.com/ctlplne/probectl/internal/auth"
)

// Rewrap replaces both envelopes using the current tenant sealer while preserving
// the exact source, immutable scope, stored origin and complete requirements.
// Payload and header cannot be rotated independently: the header authenticates
// the payload ciphertext's digest. No replacement is returned on partial failure.
//
// authorize must independently check current key-maintenance authority before
// source decryption and again before returning the pair. The historical origin
// is authenticated provenance, not that maintenance operation's credential. The
// caller must still atomically compare-and-swap the original pair and generation
// with its audit under lifecycle/write fences. This primitive persists nothing.
func (c *Codec) Rewrap(ctx context.Context, scope MessageScope, record SealedMessage, authorize AuthorizeMessage) (SealedMessage, error) {
	if authorize == nil {
		return SealedMessage{}, ErrMessageIntegrity
	}
	var origin auth.WorkerCredentialRef
	var requirements []string
	body, err := c.Open(ctx, scope, record, func(ctx context.Context, scope MessageScope, stored auth.WorkerCredentialRef, required []string) error {
		origin = stored
		requirements = slices.Clone(required)
		return authorize(ctx, scope, stored, slices.Clone(required))
	})
	if err != nil {
		return SealedMessage{}, err
	}
	defer clear(body)
	replacement, err := c.Seal(ctx, scope, origin, requirements, body)
	if err != nil {
		return SealedMessage{}, err
	}
	if err := authorize(ctx, scope, origin, slices.Clone(requirements)); err != nil {
		return SealedMessage{}, messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return SealedMessage{}, err
	}
	return replacement, nil
}
