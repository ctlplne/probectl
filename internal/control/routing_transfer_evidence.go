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
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// Bind the actual observations before they can authorize a configuration
// review. An equal projection can come from different captures, assignments,
// paths, or circuit membership. None of these private inputs leave the server.
func routingTransferEvidenceIdentity(ctx context.Context, scope entity.Scope, route routingTransferRoute,
	plans routingTransferBillPlans, counters []flowstore.CounterRow, originals routingTransferFlowEvidence, budget flowstore.ExplorerBudget) ([32]byte, error) {
	count := 1 + len(counters) + len(originals.all) + len(plans.plan[0].members) + len(plans.plan[1].members)
	memory, work := budget.MemoryBytes/8, budget.ReadBytes/8
	if int64(count) > memory/512 || int64(count) > work/1024 {
		return [32]byte{}, flow.ErrFailureTrafficBudget
	}
	records := make([][32]byte, 0, count)
	add := func(kind string, record any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		size := int64(len(encoded) + len(kind) + 1)
		if size > memory/4 || size > work {
			return flow.ErrFailureTrafficBudget
		}
		work -= size
		var digest [32]byte
		copy(digest[:], crypto.Hash(append([]byte(kind+"\n"), encoded...)))
		records = append(records, digest)
		return nil
	}
	if err := add("route", struct {
		Scope               entity.Scope
		Selected, Candidate store.BGPRoutingViewRef
		Paths               [32]byte
	}{scope, route.selectedView, route.candidateView, route.pathsFingerprint}); err != nil {
		return [32]byte{}, err
	}
	for side, plan := range plans.plan {
		var circuitRevision int64
		if plan.circuit != nil {
			circuitRevision = plan.circuit.Revision
		}
		for _, member := range plan.members {
			target := member.target
			target.ValidUntil = time.Time{} // A renewed lease leaves the same assignment in place.
			if err := add("handoff", struct {
				Side            int
				CircuitRevision int64
				Interface       store.DeviceCounterInterface
				MaximumBPS      uint64
			}{side, circuitRevision, target, member.maximum}); err != nil {
				return [32]byte{}, err
			}
		}
	}
	for _, row := range counters {
		if err := add("counter", row); err != nil {
			return [32]byte{}, err
		}
	}
	for _, read := range originals.all {
		owner := originals.owners[read.Ref.Key]
		selected := originals.selected[read.Ref.Key]
		if err := add("flow", struct {
			Read             flowstore.RoutingCaptureRead
			OriginalOwner    store.InterfaceRoleFlowBinding
			OwnerSince       time.Time
			HistoricalRoute  store.BGPRoutingViewRef
			HistoricalPrefix netip.Prefix
			NextHops         []netip.Addr
			RouteBorn        time.Time
			RouteLease       time.Time
		}{read, owner.Owner, owner.CurrentOwnerSince, selected.View, selected.Prefix, selected.NextHops, selected.RouteBorn, selected.RouteLease}); err != nil {
			return [32]byte{}, err
		}
	}
	slices.SortFunc(records, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	body := make([]byte, 0, len("probectl/routing-transfer/evidence/v1\n")+len(records)*32)
	body = append(body, "probectl/routing-transfer/evidence/v1\n"...)
	for _, record := range records {
		body = append(body, record[:]...)
	}
	var digest [32]byte
	copy(digest[:], crypto.Hash(body))
	return digest, ctx.Err()
}
