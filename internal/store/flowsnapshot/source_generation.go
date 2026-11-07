// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"context"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SourceGenerationInScope preserves the established snapshot API while the
// existing publication epoch is shared by independent retained-state writers.
func SourceGenerationInScope(ctx context.Context, sc tenancy.Scope) (int64, error) {
	return sourceepoch.SourceGenerationInScope(ctx, sc)
}

// MatchSourceGenerationInScope requires the canonical tenant audit lock.
func MatchSourceGenerationInScope(ctx context.Context, sc tenancy.Scope, captured int64) error {
	return sourceepoch.MatchSourceGenerationInScope(ctx, sc, captured)
}

// InvalidateSourceGenerationInScope preserves the existing lifecycle protocol.
func InvalidateSourceGenerationInScope(ctx context.Context, sc tenancy.Scope) error {
	return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
}
