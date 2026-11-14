// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import "context"

type currentEvidenceKey struct{}
type currentEvidenceCheck func(context.Context) error

// WithCurrentEvidence binds a trusted source's current-authority check to one
// admitted analysis. No wire argument or model can supply this callback.
func WithCurrentEvidence(ctx context.Context, check func(context.Context) error) context.Context {
	return context.WithValue(ctx, currentEvidenceKey{}, currentEvidenceCheck(check))
}

// CheckCurrentEvidence runs before model dispatch and answer publication.
// Existing sources without an additional retained snapshot keep their current
// behavior; a configured check can only refuse, never widen source authority.
func CheckCurrentEvidence(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if check, ok := ctx.Value(currentEvidenceKey{}).(currentEvidenceCheck); ok && check != nil {
		return check(ctx)
	}
	return nil
}
