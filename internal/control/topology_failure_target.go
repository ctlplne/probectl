// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
)

type topologyFailureTarget struct {
	ports    []flow.FailurePort
	complete bool
	reason   string
}

// topologyFailurePorts resolves the graph's address labels against the exact
// routing context. A graph edge collapses parallel physical links, so that
// case needs a specific interface confirmed by the owned link observations.
func (s *Server) topologyFailurePorts(ctx context.Context, scope entity.Scope, sources topologyFailureSourcePlan,
	target, kind, selectedInterface string, memory int64) (topologyFailureTarget, error) {
	none := topologyFailureTarget{}
	labels := []string{target}
	if kind == "edge" {
		parts := strings.Split(target, "|")
		if len(parts) != 3 || parts[1] != "physical" && parts[1] != "path" {
			return topologyFailureTarget{reason: "physical_link_unresolved"}, nil
		}
		labels = []string{parts[0], parts[2]}
	} else if selectedInterface != "" {
		return none, apierror.Validation("select an interface only for a simulated link failure")
	}
	addresses := make([]string, 0, len(labels))
	for _, label := range labels {
		kind, address, split := strings.Cut(label, ":")
		ip, err := netip.ParseAddr(address)
		if !split || err != nil || ip.Zone() != "" || kind != "device" && kind != "hop" {
			return topologyFailureTarget{reason: "canonical_device_unresolved"}, nil
		}
		addresses = append(addresses, ip.Unmap().String())
	}
	resolved, err := store.NewEntityRegistry(s.pool).ResolveAddressesWithBudget(ctx, scope, addresses, memory)
	if err != nil {
		return none, err
	}
	devices := make([]string, 0, len(addresses))
	for _, address := range addresses {
		r := resolved[address]
		if r.Status != entity.Resolved || r.EntityID == "" || !slices.ContainsFunc(r.Candidates, func(candidate entity.Claim) bool {
			return candidate.EntityID == r.EntityID && candidate.EntityKind == entity.Device
		}) {
			return topologyFailureTarget{reason: "canonical_device_unresolved"}, nil
		}
		devices = append(devices, r.EntityID)
	}
	if len(devices) == 2 && devices[0] == devices[1] {
		return topologyFailureTarget{reason: "physical_link_unresolved"}, nil
	}
	selected := make([]topologyFailureLink, 0)
	for _, link := range sources.links {
		a, b := link.fromDevice, link.original.ToEntityID
		if len(devices) == 1 && (a == devices[0] || b == devices[0]) ||
			len(devices) == 2 && a == devices[0] && b == devices[1] {
			selected = append(selected, link)
		}
	}
	if len(devices) == 2 {
		var reason string
		selected, reason, err = topologyFailureSelectLink(selected, selectedInterface)
		if err != nil || reason != "" {
			return topologyFailureTarget{reason: reason}, err
		}
	}
	if len(selected) == 0 {
		return topologyFailureTarget{reason: "physical_link_unresolved"}, nil
	}
	return topologyFailurePortSet(ctx, sources.links, selected)
}

func topologyFailureSelectLink(links []topologyFailureLink, interfaceID string) ([]topologyFailureLink, string, error) {
	byIndex := map[uint32][]topologyFailureLink{}
	for _, link := range links {
		if interfaceID == "" || link.port.InterfaceID == interfaceID {
			byIndex[link.original.LocalIfIndex] = append(byIndex[link.original.LocalIfIndex], link)
		}
	}
	switch {
	case len(byIndex) == 0 && interfaceID != "":
		return nil, "", apierror.NotFound("interface is outside the selected physical link")
	case len(byIndex) > 1:
		return nil, "parallel_link_requires_interface", nil
	case len(byIndex) == 1:
		for _, items := range byIndex {
			if _, unique := uniqueTopologyFailureLink(items); unique {
				return items[:1], "", nil
			}
		}
	}
	return nil, "physical_link_unresolved", nil
}

func topologyFailurePortSet(ctx context.Context, all, selected []topologyFailureLink) (topologyFailureTarget, error) {
	type linkIdentity struct {
		from, to, local, remote string
	}
	corresponding := map[linkIdentity][]topologyFailureLink{}
	for _, link := range all {
		a := link.original
		key := linkIdentity{link.fromDevice, a.ToEntityID, a.LocalPort, a.RemotePort}
		corresponding[key] = append(corresponding[key], link)
	}
	out := topologyFailureTarget{complete: true}
	interfaces := map[string]bool{}
	for _, link := range selected {
		if err := ctx.Err(); err != nil {
			return topologyFailureTarget{}, err
		}
		if link.port.InterfaceID == "" {
			out.complete = false
		} else {
			interfaces[link.port.InterfaceID] = true
		}
		a := link.original
		reciprocal := corresponding[linkIdentity{a.ToEntityID, link.fromDevice, a.RemotePort, a.LocalPort}]
		if _, unique := uniqueTopologyFailureLink(reciprocal); !unique || a.LocalPort == "" || a.RemotePort == "" || reciprocal[0].port.InterfaceID == "" {
			out.complete = false
		} else {
			interfaces[reciprocal[0].port.InterfaceID] = true
		}
	}
	for id := range interfaces {
		out.ports = append(out.ports, flow.FailurePort{InterfaceID: id, Direction: "in"}, flow.FailurePort{InterfaceID: id, Direction: "out"})
	}
	slices.SortFunc(out.ports, func(a, b flow.FailurePort) int {
		if a.InterfaceID != b.InterfaceID {
			return strings.Compare(a.InterfaceID, b.InterfaceID)
		}
		return strings.Compare(a.Direction, b.Direction)
	})
	if !out.complete {
		out.reason = "physical_port_evidence_incomplete"
	}
	return out, ctx.Err()
}
