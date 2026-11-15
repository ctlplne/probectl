// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Replay retains the complete original test population and inventory identity
// under current authority. Extraction keeps capture assembly separate from its
// existing security-sensitive final publication check.
func (s *Server) revalidateClientReportOriginalCapture(ctx context.Context, actor *auth.Principal, result *clientReportCapture, budget flowstore.ExplorerBudget) error {
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.revalidateClientReportTestsInScope(ctx, sc, actor, result.Sources, budget.MemoryBytes/8); err != nil {
			return err
		}
		accumulator, err := newClientReportSLIAccumulator(ctx, result.TenantID, result.Sources, result.Definitions, result.From, result.To, budget.MemoryBytes/8, budget.ReadBytes)
		if err != nil {
			return err
		}
		limits := store.ConfiguredMeasurementScanBudget{MemoryBytes: budget.MemoryBytes / 8, ReadBytes: budget.ReadBytes, ReadRows: int64(budget.ReadRows)}
		if err := store.NewEntityRegistry(s.pool).WalkConfiguredTestMeasurementsInScope(ctx, sc, result.Sources, accumulator.first, result.To, limits, func(item store.IncidentTestMeasurement) error { return accumulator.observe(ctx, item) }); err != nil {
			return err
		}
		availability, objectives, err := accumulator.finish(ctx)
		if err != nil {
			return err
		}
		original, err := json.Marshal([]any{result.Availability, result.SLOs})
		if err != nil {
			return err
		}
		current, err := json.Marshal([]any{availability, objectives})
		if err != nil {
			return err
		}
		if !bytes.Equal(original, current) {
			return apierror.Conflict("monthly original availability or SLO population changed during generation; retry")
		}
		if err := store.NewEntityRegistry(s.pool).RecheckReportInventoryInScope(ctx, sc, assessmentInventoryRefs(result.Inventory), budget.MemoryBytes/32); err != nil {
			return err
		}
		if err := store.NewEntityRegistry(s.pool).RecheckReportPhysicalLinksInScope(ctx, sc, store.ClientReportPhysicalLinkRefs(result.PhysicalLinks), budget.MemoryBytes/32); err != nil {
			return err
		}
		return ctx.Err()
	})
}
