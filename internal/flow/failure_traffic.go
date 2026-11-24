// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrFailureTrafficInput  = errors.New("invalid failure traffic evidence")
	ErrFailureTrafficBudget = errors.New("failure traffic exceeds its calculation budget")
)

// FailurePort identifies a direction on a canonical interface. Full-duplex
// ports have separate baselines and compete only with traffic in that direction.
type FailurePort struct {
	InterfaceID string `json:"interface_id"`
	Direction   string `json:"direction"`
}

type FailureTrafficBaseline struct {
	FailurePort
	BPS         *big.Rat // nil if the counter window is incomplete
	CapacityBPS uint64   // zero if no verified speed covers the window
}

type FailureTrafficDisposition string

const (
	FailureTrafficRerouted   FailureTrafficDisposition = "rerouted"
	FailureTrafficUnrouted   FailureTrafficDisposition = "unrouted"
	FailureTrafficUnresolved FailureTrafficDisposition = "unresolved"
)

// FailureTrafficDemand is one deduplicated observed rate, attributed to its
// directed pre-failure route. For unrouted demand, After is the surviving
// prefix through which traffic still travels before it reaches the break.
// An unresolved route has no modeled After path.
type FailureTrafficDemand struct {
	BPS         *big.Rat
	Before      []FailurePort
	After       []FailurePort
	Disposition FailureTrafficDisposition
}

// FailureTrafficSample uses one common interval for flow rates and interface
// baselines. An incomplete demand population cannot support a total projection.
type FailureTrafficSample struct {
	TenantID       string
	From, To       time.Time
	DemandComplete bool
	Failed         []FailurePort
	Baselines      []FailureTrafficBaseline
	Demands        []FailureTrafficDemand
}

type FailureTrafficPortProjection struct {
	FailurePort
	Status           string `json:"status"`
	CapacityBPS      string `json:"capacity_bps,omitempty"`
	MeasuredBPS      string `json:"measured_bps,omitempty"`
	AddedBPS         string `json:"added_bps"`
	RemovedBPS       string `json:"removed_bps"`
	ProjectedBPS     string `json:"projected_bps,omitempty"`
	UtilizationRatio string `json:"utilization_ratio,omitempty"`
}

type FailureTrafficProjection struct {
	From          time.Time                      `json:"from"`
	To            time.Time                      `json:"to"`
	Complete      bool                           `json:"complete"`
	AffectedBPS   string                         `json:"affected_bps"`
	ReroutedBPS   string                         `json:"rerouted_bps"`
	UnroutedBPS   string                         `json:"unrouted_bps"`
	UnresolvedBPS string                         `json:"unresolved_bps"`
	Ports         []FailureTrafficPortProjection `json:"ports"`
}

type failureTrafficPort struct {
	baseline FailureTrafficBaseline
	failed   bool
	added    big.Rat
	removed  big.Rat
}

func projectFailureTrafficSample(ctx context.Context, sample FailureTrafficSample, budget *capacityGridAdmission) (FailureTrafficProjection, error) {
	none := FailureTrafficProjection{}
	tenant, found := tenancy.FromContext(ctx)
	if !found || tenant.String() != sample.TenantID {
		return none, tenancy.ErrNoTenant
	}
	if sample.From.IsZero() || !sample.To.After(sample.From) || len(sample.Failed) == 0 {
		return none, ErrFailureTrafficInput
	}
	if !budget.debit(int64(len(sample.Baselines)), 2048, 1024) ||
		!budget.debit(int64(len(sample.Failed)), 256, 256) ||
		!budget.debit(int64(len(sample.Demands)), 512, 512) {
		return none, ErrFailureTrafficBudget
	}
	ports := make(map[FailurePort]*failureTrafficPort, len(sample.Baselines))
	for _, base := range sample.Baselines {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if base.InterfaceID == "" || base.Direction != "in" && base.Direction != "out" || ports[base.FailurePort] != nil ||
			base.BPS != nil && base.BPS.Sign() < 0 {
			return none, ErrFailureTrafficInput
		}
		if !budget.debit(int64(len(base.InterfaceID)), 1, 1) || base.BPS != nil && !budget.arithmetic(base.BPS) {
			return none, ErrFailureTrafficBudget
		}
		ports[base.FailurePort] = &failureTrafficPort{baseline: base}
	}
	for _, port := range sample.Failed {
		value := ports[port]
		if value == nil || value.failed {
			return none, ErrFailureTrafficInput
		}
		value.failed = true
	}

	var affected, rerouted, unrouted, unresolved big.Rat
	for _, demand := range sample.Demands {
		if err := applyFailureDemand(ctx, ports, demand, budget); err != nil {
			return none, err
		}
		var outcome *big.Rat
		switch demand.Disposition {
		case FailureTrafficRerouted:
			outcome = &rerouted
		case FailureTrafficUnrouted:
			outcome = &unrouted
		case FailureTrafficUnresolved:
			outcome = &unresolved
		default:
			return none, ErrFailureTrafficInput
		}
		if !budget.arithmetic(&affected, outcome, demand.BPS) {
			return none, ErrFailureTrafficBudget
		}
		affected.Add(&affected, demand.BPS)
		outcome.Add(outcome, demand.BPS)
	}

	complete := sample.DemandComplete && unresolved.Sign() == 0
	for _, key := range sample.Failed {
		if !complete || key.Direction != "out" {
			continue
		}
		port := ports[key]
		measured := port.baseline.BPS
		if measured == nil {
			complete = false
			continue
		}
		if !budget.arithmetic(measured, &port.removed) {
			return none, ErrFailureTrafficBudget
		}
		// Reconcile the covered offers against independent egress octets. A
		// five-percent tolerance allows small framing and sampling differences.
		var difference big.Rat
		difference.Sub(measured, &port.removed)
		difference.Abs(&difference).Mul(&difference, big.NewRat(20, 1))
		complete = difference.Cmp(measured) <= 0
	}
	result := FailureTrafficProjection{From: sample.From.UTC(), To: sample.To.UTC(),
		Complete: complete, AffectedBPS: affected.RatString(), ReroutedBPS: rerouted.RatString(),
		UnroutedBPS: unrouted.RatString(), UnresolvedBPS: unresolved.RatString(),
		Ports: make([]FailureTrafficPortProjection, 0, len(ports))}
	for _, port := range ports {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		row, err := projectFailureTrafficPort(port, complete, budget)
		if err != nil {
			return none, err
		}
		if port.baseline.BPS == nil || row.Status != "failed" && row.Status != "projected" {
			result.Complete = false
		}
		result.Ports = append(result.Ports, row)
	}
	sort.Slice(result.Ports, func(i, j int) bool {
		a, b := result.Ports[i], result.Ports[j]
		if a.InterfaceID != b.InterfaceID {
			return a.InterfaceID < b.InterfaceID
		}
		return a.Direction < b.Direction
	})
	return result, ctx.Err()
}

func applyFailureDemand(ctx context.Context, ports map[FailurePort]*failureTrafficPort, demand FailureTrafficDemand, budget *capacityGridAdmission) error {
	if demand.BPS == nil || demand.BPS.Sign() <= 0 || len(demand.Before) == 0 {
		return ErrFailureTrafficInput
	}
	switch demand.Disposition {
	case FailureTrafficRerouted:
		if len(demand.After) == 0 {
			return ErrFailureTrafficInput
		}
	case FailureTrafficUnrouted:
		if len(demand.After) >= len(demand.Before) || !slices.Equal(demand.After, demand.Before[:len(demand.After)]) {
			return ErrFailureTrafficInput
		}
	case FailureTrafficUnresolved:
		if len(demand.After) != 0 {
			return ErrFailureTrafficInput
		}
	default:
		return ErrFailureTrafficInput
	}
	before, err := failureRoutePortSet(ctx, ports, demand.Before, budget)
	if err != nil {
		return err
	}
	after, err := failureRoutePortSet(ctx, ports, demand.After, budget)
	if err != nil {
		return err
	}
	affected := false
	for _, port := range before {
		affected = affected || port.failed
	}
	if !affected {
		return ErrFailureTrafficInput
	}
	for _, port := range after {
		if port.failed {
			return ErrFailureTrafficInput
		}
	}
	if demand.Disposition == FailureTrafficUnresolved {
		return nil // a possible transfer is not a measured or modeled delta
	}
	for key, port := range before {
		if after[key] != nil {
			continue // preserve demand on a shared route segment
		}
		if !budget.arithmetic(&port.removed, demand.BPS) {
			return ErrFailureTrafficBudget
		}
		port.removed.Add(&port.removed, demand.BPS)
	}
	for key, port := range after {
		if before[key] != nil {
			continue
		}
		if !budget.arithmetic(&port.added, demand.BPS) {
			return ErrFailureTrafficBudget
		}
		port.added.Add(&port.added, demand.BPS)
	}
	return nil
}

func failureRoutePortSet(ctx context.Context, ports map[FailurePort]*failureTrafficPort, route []FailurePort, budget *capacityGridAdmission) (map[FailurePort]*failureTrafficPort, error) {
	if !budget.debit(int64(len(route)), 256, 256) {
		return nil, ErrFailureTrafficBudget
	}
	set := make(map[FailurePort]*failureTrafficPort, len(route))
	for _, key := range route {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		port := ports[key]
		if port == nil || set[key] != nil {
			return nil, ErrFailureTrafficInput
		}
		set[key] = port
	}
	return set, nil
}

func projectFailureTrafficPort(port *failureTrafficPort, complete bool, budget *capacityGridAdmission) (FailureTrafficPortProjection, error) {
	baseline := port.baseline
	out := FailureTrafficPortProjection{FailurePort: baseline.FailurePort, AddedBPS: port.added.RatString(), RemovedBPS: port.removed.RatString()}
	if baseline.BPS != nil {
		out.MeasuredBPS = baseline.BPS.RatString()
	}
	if baseline.CapacityBPS != 0 {
		out.CapacityBPS = strconv.FormatUint(baseline.CapacityBPS, 10)
	}
	switch {
	case port.failed:
		out.Status = "failed"
	case !complete:
		out.Status = "traffic_unresolved"
	case baseline.BPS == nil:
		out.Status = "baseline_unavailable"
	case baseline.BPS.Cmp(&port.removed) < 0:
		out.Status = "baseline_below_displaced"
	default:
		if !budget.arithmetic(baseline.BPS, &port.added, &port.removed) {
			return FailureTrafficPortProjection{}, ErrFailureTrafficBudget
		}
		projected := new(big.Rat).Sub(baseline.BPS, &port.removed)
		projected.Add(projected, &port.added)
		out.ProjectedBPS = projected.RatString()
		out.Status = "capacity_unavailable"
		if baseline.CapacityBPS != 0 {
			capacity := new(big.Rat).SetInt(new(big.Int).SetUint64(baseline.CapacityBPS))
			out.UtilizationRatio = projected.Quo(projected, capacity).RatString()
			out.Status = "projected"
		}
	}
	return out, nil
}
