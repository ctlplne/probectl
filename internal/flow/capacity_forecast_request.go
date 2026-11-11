// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type CapacityForecastRequest struct {
	Target         CapacityTarget          `json:"target"`
	From           string                  `json:"from"`
	To             string                  `json:"to"`
	Until          string                  `json:"until"`
	Direction      string                  `json:"direction"`
	CapacityBPS    string                  `json:"capacity_bps"`
	MaximumPollGap string                  `json:"maximum_poll_gap"`
	PhysicalBounds []CapacityPhysicalBound `json:"physical_bounds"`
}

type CapacityForecastMeasurement struct {
	Target           CapacityTarget           `json:"target"`
	Members          []CapacityBillMember     `json:"members"`
	Forecasts        []CapacityForecastResult `json:"forecasts"`
	MaximumPollGap   string                   `json:"maximum_poll_gap"`
	MembershipBasis  string                   `json:"membership_basis"`
	AsOf             time.Time                `json:"as_of"`
	SourceValidUntil time.Time                `json:"source_valid_until"`
}

// ValidateCapacityForecastThreshold performs the same exact decimal and finite
// arithmetic admission as training, before storage work starts. A forecast
// threshold is independent of physical wrap bounds and recorded financial terms.
func ValidateCapacityForecastThreshold(ctx context.Context, value string, memoryBytes, workUnits int64) error {
	if _, bound := tenancy.FromContext(ctx); !bound {
		return tenancy.ErrNoTenant
	}
	budget := capacityGridAdmission{memoryBytes, workUnits}
	if !budget.debit(int64(len(value)), 128, 128) {
		return errCapacityCounterInput
	}
	words := int64(len(value))/8 + 1
	if words > budget.work/512 || words > (budget.work/512)/words || !budget.debit(words, 128, words*512) {
		return errCapacityCounterInput
	}
	parsed, err := capacityContractDecimal(ctx, value)
	if err != nil || parsed.Sign() <= 0 {
		return errCapacityCounterInput
	}
	return ctx.Err()
}
