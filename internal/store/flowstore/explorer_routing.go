// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrRoutingQueryScope = errors.New("flow routing lookup requires current tenant context and source authority")

// RoutingProjection is selected by the current-authority reader, never query
// JSON. Empty values represent unavailable/ambiguous metadata without removing
// any traffic. Complete path sets use a canonical JSON array of full paths.
type RoutingProjection struct {
	entity.Scope
	Key       [32]byte
	Clock     int64
	Fields    map[string]string
	SourceIDs []string
}

type routingQueryKey struct {
	key   [32]byte
	clock int64
}

type routingQueryData struct {
	tenant string
	asOf   time.Time
	byKey  map[routingQueryKey]map[string]string
	rows   []RoutingProjection
	digest string
}

func newRoutingQueryData(ctx context.Context, tenant string, at time.Time, rows []RoutingProjection, memory int64) (*routingQueryData, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !validTagProjectionID(tenant) || at.IsZero() {
		return nil, ErrRoutingQueryScope
	}
	if memory < 4096 || int64(len(rows)) > (memory-4096)/4096 {
		return nil, ErrExplorerBudget
	}
	used := int64(4096)
	data := &routingQueryData{tenant: tenant, asOf: at.UTC(), byKey: map[routingQueryKey]map[string]string{}}
	seen := map[[32]byte]bool{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		scope, err := row.Normalize()
		if err != nil || scope != row.Scope || row.TenantID != tenant || row.Key == ([32]byte{}) || row.Clock <= 0 || len(row.SourceIDs) == 0 {
			return nil, ErrRoutingQueryScope
		}
		used += 4096
		for name, value := range row.Fields {
			definition, ok := flow.RoutingQueryField(name)
			if !ok {
				return nil, ErrRoutingQueryScope
			}
			used += 256 + int64(len(name)+len(value))*12
			if used > memory {
				return nil, ErrExplorerBudget
			}
			if definition.Type == flow.QueryUnsigned && value != "" {
				parsed, err := strconv.ParseUint(value, 10, 32)
				if err != nil || strconv.FormatUint(parsed, 10) != value {
					return nil, ErrRoutingQueryScope
				}
			}
		}
		fields := make(map[string]string, len(row.Fields))
		for name, value := range row.Fields {
			fields[name] = value
		}
		row.SourceIDs = slices.Clone(row.SourceIDs)
		slices.Sort(row.SourceIDs)
		row.SourceIDs = slices.Compact(row.SourceIDs)
		for _, source := range row.SourceIDs {
			used += 256 + int64(len(source))*12
			if used > memory {
				return nil, ErrExplorerBudget
			}
			if source == "" {
				return nil, ErrRoutingQueryScope
			}
		}
		row.Fields = fields
		key := routingQueryKey{row.Key, row.Clock}
		if seen[row.Key] {
			return nil, ErrRoutingQueryScope
		}
		seen[row.Key] = true
		data.byKey[key] = fields
		data.rows = append(data.rows, row)
	}
	slices.SortFunc(data.rows, func(a, b RoutingProjection) int {
		return slices.Compare(a.Key[:], b.Key[:])
	})
	body, err := json.Marshal(struct {
		Tenant string              `json:"tenant_id"`
		Rows   []RoutingProjection `json:"rows"`
	}{tenant, data.rows})
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > memory-used {
		return nil, ErrExplorerBudget
	}
	data.digest = hex.EncodeToString(crypto.Hash(body))
	return data, nil
}

func (data *routingQueryData) validate(ctx context.Context, tenant string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if data == nil || !ok || bound.String() != tenant || data.tenant != tenant || data.asOf.IsZero() || data.digest == "" {
		return ErrRoutingQueryScope
	}
	return nil
}

func planUsesRouting(plan flow.QueryPlan) bool {
	for _, names := range [][]string{plan.GroupBy, plan.MatrixWith, flow.QueryFilterFields(plan.Filter)} {
		for _, name := range names {
			if _, ok := flow.RoutingQueryField(name); ok {
				return true
			}
		}
	}
	return false
}

func validatePlanRouting(ctx context.Context, query PlanQuery, plan flow.QueryPlan) error {
	if !planUsesRouting(plan) {
		return nil
	}
	return query.Routing.validate(ctx, query.TenantID)
}

func (data *routingQueryData) valueForRow(row Row, field string) string {
	if data == nil || row.TenantID != data.tenant || row.RoutingCaptureKey == "" {
		return routingMissingField(field)
	}
	if err := validateRoutingCaptureRow(row); err != nil {
		return routingMissingField(field)
	}
	body, _ := hex.DecodeString(row.RoutingCaptureKey)
	var key [32]byte
	copy(key[:], body)
	if fields, exists := data.byKey[routingQueryKey{key, row.RoutingCapturedUnixNanos}]; exists {
		if value, exists := fields[field]; exists {
			return value
		}
	}
	return routingMissingField(field)
}

func routingMissingField(field string) string {
	for _, side := range []string{"src", "dst"} {
		switch field {
		case side + "_bgp_provenance":
			return "unavailable"
		case side + "_bgp_rpki":
			return "unknown"
		}
	}
	return ""
}
