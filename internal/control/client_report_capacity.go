// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientReportCapacityCapture struct {
	Input           flow.CapacityForecastRequest
	Measurement     flow.CapacityForecastMeasurement
	OriginalRows    string
	OriginalsDigest string
	publication     incidentEvidenceFinalizer
}

func (s *Server) captureClientReportCapacity(ctx context.Context, actor *auth.Principal, capture *clientReportCapture, definitions []reporting.ClientReportCapacityTarget, budget flowstore.ExplorerBudget, remaining *int64) ([]clientReportCapacityCapture, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || capture == nil || bound.String() != actor.TenantID || actor.TenantID != capture.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	if len(definitions) == 0 {
		return []clientReportCapacityCapture{}, ctx.Err()
	}
	if s.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("multi-factor authentication required")
	}
	if remaining == nil || *remaining <= 0 || int64(len(definitions)) > *remaining/8192 {
		return nil, store.ErrClientReportBudget
	}
	results := make([]clientReportCapacityCapture, 0, len(definitions))
	starting := *remaining
	for _, definition := range definitions {
		input, err := clientReportCapacityInput(definition, capture.From, capture.To)
		if err != nil {
			return nil, err
		}
		if *remaining < 1<<20 {
			return nil, store.ErrClientReportBudget
		}
		operation := budget
		// The engine already apportions transient work among rows, receipts
		// and grids. Use the operation's actually unretained memory for that
		// work, while separately charging every retained target. A second
		// half-share rejects full31-day histories inside an adequate envelope.
		operation.MemoryBytes = budget.MemoryBytes - capture.retainedBytes - (starting - *remaining)
		if operation.MemoryBytes <= 0 {
			return nil, store.ErrClientReportBudget
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/capacity/forecast", nil)
		if err != nil {
			return nil, err
		}
		var publication incidentEvidenceFinalizer
		var retained *capacityForecastSourceCapture
		measurement, err := s.measureRetainedCapacityForecast(capacityForecastOperation{request: request, actor: actor, budget: operation}, input, &publication, &retained)
		if err != nil {
			return nil, err
		}
		if retained == nil || publication == nil {
			return nil, apierror.Unavailable("monthly capacity original-source validation is unavailable")
		}
		for _, member := range retained.plan.members {
			target := member.target
			capture.sourceKeys = append(capture.sourceKeys, store.ReportSourceKey{ContextID: target.Source.ContextID, AgentID: target.Source.AgentID, Kind: "device_target", Ref: target.Source.SourceRef})
		}
		body, err := clientReportCapacityOriginals(retained, input, measurement)
		if err != nil {
			return nil, err
		}
		cost := 8192 + 8*int64(len(body))
		if cost > *remaining {
			return nil, store.ErrClientReportBudget
		}
		*remaining -= cost
		if err := publication(ctx); err != nil {
			return nil, err
		}
		results = append(results, clientReportCapacityCapture{Input: input, Measurement: measurement, OriginalRows: strconv.Itoa(len(retained.rows)), OriginalsDigest: hex.EncodeToString(crypto.Hash(body)), publication: publication})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func clientReportCapacityInput(definition reporting.ClientReportCapacityTarget, from, to time.Time) (flow.CapacityForecastRequest, error) {
	months := definition.ForecastMonths
	if months == 0 {
		months = 1
	}
	if months < 1 || months > (9999-to.Year())*12 {
		return flow.CapacityForecastRequest{}, apierror.Validation("monthly capacity requires a positive representable calendar-month forecast horizon")
	}
	input := flow.CapacityForecastRequest{Target: flow.CapacityTarget{Kind: definition.Target.Kind, ContextID: definition.Target.ContextID, InterfaceID: definition.Target.InterfaceID, TagID: definition.Target.TagID, TagValue: definition.Target.TagValue},
		From: from.UTC().Format(time.RFC3339Nano), To: to.UTC().Format(time.RFC3339Nano), Until: to.AddDate(0, months, 0).UTC().Format(time.RFC3339Nano), Direction: definition.Direction, CapacityBPS: definition.CapacityBPS, MaximumPollGap: definition.MaximumPollGap, PhysicalBounds: []flow.CapacityPhysicalBound{}}
	for _, bound := range definition.PhysicalBounds {
		input.PhysicalBounds = append(input.PhysicalBounds, flow.CapacityPhysicalBound{ContextID: bound.ContextID, InterfaceID: bound.InterfaceID, MaxBPS: bound.MaxBPS})
	}
	return input, nil
}

func clientReportCapacityOriginals(retained *capacityForecastSourceCapture, input flow.CapacityForecastRequest, result flow.CapacityForecastMeasurement) ([]byte, error) {
	members := make([]any, 0, len(retained.plan.members))
	for _, member := range retained.plan.members {
		members = append(members, struct {
			Target  store.DeviceCounterInterface
			Maximum uint64
		}{member.target, member.maximum})
	}
	return json.Marshal(struct {
		Domain  string
		Tenant  string
		Input   flow.CapacityForecastRequest
		Period  flow.CapacityBillingPeriod
		Members []any
		Circuit *store.CapacityCircuitSnapshot
		Rows    []flowstore.CounterRow
		Result  flow.CapacityForecastMeasurement
	}{"probectl.client-report.capacity-originals.v1", retained.plan.tenant, input, retained.plan.period, members, retained.plan.circuit, retained.rows, result})
}
