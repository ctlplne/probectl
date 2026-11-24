// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"net/netip"
	"slices"
)

// FailureRouteCandidate carries either an independently mapped route or a
// prefix whose path is unknown. An empty path still competes at its prefix
// length, so missing physical evidence cannot favor another exit.
type FailureRouteCandidate struct {
	Prefix netip.Prefix
	Ports  []FailurePort
}

// FailureRouteEvidence keeps routes that were selected before the simulated
// failure distinct from routes seen only in a complete eligible view.
type FailureRouteEvidence struct {
	Selected         []FailureRouteCandidate
	Eligible         []FailureRouteCandidate
	EligibleComplete bool
}

// ChooseFailureTrafficRoute models a unique surviving selected route first.
// After the selected routes fail, use the longest prefix with a unique
// surviving path in the eligible views. Conflicting exits cannot establish a
// traffic share or which router policy will win.
func ChooseFailureTrafficRoute(ctx context.Context, address netip.Addr, before []FailurePort, failed map[FailurePort]bool,
	evidence FailureRouteEvidence) (FailureTrafficDisposition, []FailurePort, error) {
	if !address.IsValid() || address.Zone() != "" {
		return "", nil, ErrFailureTrafficInput
	}
	address = address.Unmap()
	breakAt := slices.IndexFunc(before, func(port FailurePort) bool { return failed[port] })
	if breakAt < 0 {
		return "", nil, ErrFailureTrafficInput
	}
	selected, complete, err := survivingFailureRoute(ctx, address, failed, evidence.Selected)
	if err != nil {
		return "", nil, err
	}
	if !complete || !slices.ContainsFunc(evidence.Selected, func(route FailureRouteCandidate) bool { return route.Prefix.Contains(address) }) {
		return FailureTrafficUnresolved, nil, nil
	}
	if selected != nil {
		return FailureTrafficRerouted, selected, nil
	}
	if !evidence.EligibleComplete {
		return FailureTrafficUnresolved, nil, nil
	}
	eligible, complete, err := survivingFailureRoute(ctx, address, failed, evidence.Eligible)
	if err != nil {
		return "", nil, err
	}
	if !complete {
		return FailureTrafficUnresolved, nil, nil
	}
	if eligible == nil {
		return FailureTrafficUnrouted, before[:breakAt], nil
	}
	return FailureTrafficRerouted, eligible, nil
}

func survivingFailureRoute(ctx context.Context, address netip.Addr, failed map[FailurePort]bool,
	candidates []FailureRouteCandidate) ([]FailurePort, bool, error) {
	longest, complete := -1, true
	var path []FailurePort
	for _, route := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if !route.Prefix.IsValid() || route.Prefix != route.Prefix.Masked() {
			return nil, false, ErrFailureTrafficInput
		}
		bits := route.Prefix.Bits()
		if bits < longest || !route.Prefix.Contains(address) {
			continue
		}
		if slices.ContainsFunc(route.Ports, func(port FailurePort) bool { return failed[port] }) {
			continue
		}
		if bits > longest {
			longest, path, complete = bits, nil, true
		}
		switch {
		case len(route.Ports) == 0:
			complete = false
		case path == nil:
			path = route.Ports
		case !slices.Equal(path, route.Ports):
			complete = false
		}
	}
	return path, complete, ctx.Err()
}
