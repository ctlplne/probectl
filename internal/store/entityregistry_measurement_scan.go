// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Memory bounds the current complete decoded document plus source selection.
// Read bytes/rows independently bound the whole scan. Exceeding any admission
// returns an error, never a successful prefix. Callers discard partial totals.
type ConfiguredMeasurementScanBudget struct {
	MemoryBytes, ReadBytes, ReadRows int64
}

// WalkConfiguredTestMeasurementsInScope shares the original-document decoder,
// tenant snapshot and current source/definition/sender checks with incident
// readers. The callback is request-local calculation only: no publication or
// further query on this connection may occur while the cursor is open.
func (*EntityRegistry) WalkConfiguredTestMeasurementsInScope(ctx context.Context, sc tenancy.Scope, sources []IncidentConfiguredTest, from, to time.Time, budget ConfiguredMeasurementScanBudget, visit func(IncidentTestMeasurement) error) error {
	return walkIncidentTestMeasurementsInScope(ctx, sc, sources, from, to, budget, false, false, visit)
}
