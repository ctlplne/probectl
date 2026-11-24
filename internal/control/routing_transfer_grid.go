// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"math/big"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type routingTransferGridAdmission struct {
	retained, work int64
}

// Whole-egress calibration includes records outside the prefix. A recorded zero
// for the moved prefix is valid only when the complete signed flow population
// reconciles against independently captured out-octets in the same interval.
func buildRoutingTransferGrid(ctx context.Context, scope entity.Scope, port store.DeviceCounterInterface, route routingTransferRoute,
	handoff flow.RoutingTransferHandoff, input routingTransferFlowInput, window flow.CapacityMeasurementWindow) ([]flow.RoutingTransferInterval, string, error) {
	span := window.To.Sub(window.From)
	if window.From.IsZero() || span <= 0 || !window.From.Add(span).Equal(window.To) {
		return nil, "", flow.ErrFailureTrafficInput
	}
	count := int64(1 + (span-1)/topologyFailureInterval)
	admission := routingTransferGridAdmission{retained: window.MemoryBytes / 4, work: window.WorkUnits / 4}
	if count > admission.retained/4096 || int64(len(input.rows)) > (admission.retained-count*4096)/512 {
		return nil, "", flow.ErrFailureTrafficBudget
	}
	admission.retained -= count*4096 + int64(len(input.rows))*512
	intervals := make([]flow.RoutingTransferInterval, int(count))
	for i := range intervals {
		from := window.From.Add(time.Duration(i) * topologyFailureInterval)
		intervals[i] = flow.RoutingTransferInterval{From: from,
			To: from.Add(min(topologyFailureInterval, window.To.Sub(from))), MovedBPS: new(big.Rat)}
	}
	totals := make([]big.Rat, int(count))
	seen := map[[32]byte]bool{}
	for _, row := range input.rows {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		if row.TenantID != scope.TenantID || row.OutIf != port.IfIndex {
			return nil, "", entity.ErrScopeMismatch
		}
		key, err := topologyFailureCaptureKey(row.RoutingCaptureKey)
		if err != nil {
			return nil, "", err
		}
		if seen[key] {
			continue
		}
		owner := input.originals.owners[key]
		if !incidentTrafficOwnerMatches(row, owner) || owner.Owner.Scope != scope || owner.Owner.RouterID != port.Source.DeviceID ||
			row.StartTS.Before(port.CreatedAt) || !routingTransferFlowClockValid(row) {
			return nil, "original_egress_ownership_incomplete", nil
		}
		seen[key] = true
		move, known := routingTransferPrefixMembership(row, key, input.originals, route)
		if !known {
			return nil, "retained_prefix_route_changed_or_unavailable", nil
		}
		err = walkTopologyFlowRates(ctx, window.From, window.To, row, &admission.retained, func(i int, rate *big.Rat) error {
			if !admission.add(&totals[i], rate) || move && !admission.add(intervals[i].MovedBPS, rate) {
				return flow.ErrFailureTrafficBudget
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
	}
	if !reconcileRoutingTransferEgress(scope, handoff, intervals, totals) {
		return nil, "flow_egress_does_not_reconcile_with_original_counters", nil
	}
	return intervals, "", ctx.Err()
}

func (admission *routingTransferGridAdmission) add(accumulated, value *big.Rat) bool {
	words := int64(1 + accumulated.Num().BitLen()/64 + accumulated.Denom().BitLen()/64 + value.Num().BitLen()/64 + value.Denom().BitLen()/64)
	if words > admission.work/512 || words > (admission.work/512)/words || words > admission.retained/32 {
		return false
	}
	admission.work -= words * words * 512
	admission.retained -= words * 32
	accumulated.Add(accumulated, value)
	return true
}

func routingTransferFlowClockValid(row flowstore.Row) bool {
	if row.StartTS.UnixNano() <= 0 || row.RoutingCapturedUnixNanos <= 0 || row.TS.UnixNano() > row.RoutingCapturedUnixNanos || row.Sampling == 0 {
		return false
	}
	switch row.ClockBasis {
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL:
		return row.Protocol != flow.ProtoSFlow5 && row.StartTS.Before(row.TS)
	case flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_COLLECTOR_SAMPLE:
		return row.Protocol == flow.ProtoSFlow5 && row.StartTS.Equal(row.TS)
	default:
		return false
	}
}

func routingTransferPrefixMembership(row flowstore.Row, key [32]byte, evidence routingTransferFlowEvidence, route routingTransferRoute) (move, known bool) {
	address, err := netip.ParseAddr(row.DstAddr)
	if err != nil || address.Zone() != "" {
		return false, false
	}
	address = address.Unmap()
	if !route.prefix.Contains(address) {
		return false, true
	}
	capture, present := evidence.selected[key]
	if !present || row.StartTS.Before(capture.RouteBorn) || !capture.RouteLease.After(capture.Reference.CapturedAt) ||
		capture.Prefix != evidence.destinations[address] || capture.Prefix.Bits() < route.prefix.Bits() {
		return false, false
	}
	if capture.Prefix != route.prefix {
		return false, true // this exact policy leaves the more-specific route alone
	}
	if !slices.Contains(capture.NextHops, route.selected) {
		return false, false
	}
	if row.NextHop == "" {
		return true, true
	}
	observed, err := netip.ParseAddr(row.NextHop)
	known = err == nil && observed.Zone() == "" && (observed.IsUnspecified() || observed.Unmap() == route.selected)
	return known, known
}

func reconcileRoutingTransferEgress(scope entity.Scope, handoff flow.RoutingTransferHandoff, intervals []flow.RoutingTransferInterval, totals []big.Rat) bool {
	for _, member := range handoff.Members {
		source := member.Source()
		if source.TenantID != scope.TenantID || source.ContextID != scope.ContextID || source.InterfaceID != handoff.EgressID {
			continue
		}
		actual := member.Samples("out")
		if len(actual) != len(intervals) {
			return false
		}
		for i, interval := range intervals {
			sample := actual[i]
			if !sample.Observed || !sample.From.Equal(interval.From) || !sample.To.Equal(interval.To) {
				return false
			}
			measured, ok := new(big.Rat).SetString(sample.BPSNumerator + "/" + sample.BPSDenominator)
			if !ok || measured.Sign() < 0 {
				return false
			}
			difference := new(big.Rat).Sub(&totals[i], measured)
			if difference.Abs(difference).Mul(difference, big.NewRat(20, 1)).Cmp(measured) > 0 {
				return false
			}
		}
		return true
	}
	return false
}
