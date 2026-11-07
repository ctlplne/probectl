// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
)

// WithRoutingCaptureStore records first-ingestion metadata in the routed
// tenant store. Raw sender claims may stage private candidates; only the
// independently authenticated evidence channel can finalize route evidence.
func (c *FlowConsumer) WithRoutingCaptureStore(pool *pgxpool.Pool, budget store.BGPRoutingBudget) *FlowConsumer {
	captures := store.NewBGPRoutingFlowCaptures(pool)
	return c.WithRoutingCaptures(func(ctx context.Context, sender string, witnesses []entity.FlowCaptureWitness) ([]entity.FlowCaptureReference, error) {
		return captures.StageRaw(ctx, sender, witnesses, budget)
	}, budget.MemoryBytes, budget.WorkUnits)
}
