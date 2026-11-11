// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"math/big"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
)

// PeeringTrafficQuery is a private, server-authorized aggregation. Data and
// Roles come from current tenant readers, never public query JSON.
type PeeringTrafficQuery struct {
	Data          *PeeringQueryData
	Roles         *InterfaceRoleQueryData
	From, To      time.Time
	BucketSeconds int
	DataSeries    string
}

// PeeringTrafficBucket retains every observed owned-router flow, including
// unknown interfaces and all four path states. Missing buckets are absent,
// never zero-filled into a claim of complete network observation.
type PeeringTrafficBucket struct {
	Start, End   time.Time
	InterfaceID  string
	Role         entity.InterfaceRole
	State        string
	Bytes, Flows string
}

type PeeringTrafficResult struct {
	Buckets                 []PeeringTrafficBucket
	Source                  string
	InputDigest, RoleDigest string
}

// PeeringTrafficStore aggregates all states from one storage snapshot. It
// confers no authority and does not assert that a hypothetical peer is live.
type PeeringTrafficStore interface {
	PeeringTraffic(context.Context, PeeringTrafficQuery) (PeeringTrafficResult, error)
}

func PeeringTrafficStoreOf(store Store) (PeeringTrafficStore, bool) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		default:
			result, ok := store.(PeeringTrafficStore)
			return result, ok
		}
	}
}

func normalizePeeringTraffic(ctx context.Context, query PeeringTrafficQuery) (flow.QueryPlan, error) {
	if query.Data == nil {
		return flow.QueryPlan{}, ErrRoutingQueryScope
	}
	tenant := query.Data.target.TenantID
	if _, err := query.Data.Digest(ctx, tenant); err != nil {
		return flow.QueryPlan{}, err
	}
	if err := query.Roles.validate(ctx, tenant, time.Now().UTC()); err != nil {
		return flow.QueryPlan{}, err
	}
	if len(query.Roles.rows) == 0 {
		return flow.QueryPlan{}, ErrInterfaceRoleQueryScope
	}
	for _, role := range query.Roles.rows {
		if err := ctx.Err(); err != nil {
			return flow.QueryPlan{}, err
		}
		if role.Scope != query.Data.target.Scope || role.RouterID != query.Data.target.RouterID {
			return flow.QueryPlan{}, ErrInterfaceRoleQueryScope
		}
	}
	// These code-owned selectors also require complete retained routing and
	// interface inputs when the existing source chooser considers old history.
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: query.From, To: query.To,
		BucketSeconds: query.BucketSeconds, DataSeries: query.DataSeries,
		GroupBy: []string{"in_if_role", "src_bgp_provenance"},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total"}}}, time.Now().UTC())
	if err != nil {
		return flow.QueryPlan{}, err
	}
	if !time.Unix(0, plan.From.UnixNano()).Equal(plan.From) || !time.Unix(0, plan.To.UnixNano()).Equal(plan.To) || !plan.From.Add(plan.To.Sub(plan.From)).Equal(plan.To) {
		return flow.QueryPlan{}, ErrRoutingQueryScope
	}
	return plan, nil
}

type peeringTrafficGroup struct {
	bucket      int64
	interfaceID string
	role        entity.InterfaceRole
	state       string
}

type peeringTrafficTotal struct{ bytes, flows big.Int }

func peeringTrafficBounds(plan flow.QueryPlan, index int64) (time.Time, time.Time, error) {
	width := time.Duration(plan.BucketSeconds) * time.Second
	span := plan.To.Sub(plan.From)
	if index < 0 || index > int64((span-1)/width) {
		return time.Time{}, time.Time{}, ErrRoutingQueryScope
	}
	start := plan.From.Add(time.Duration(index) * width)
	// Preserve an arbitrary final partial interval without duration overflow.
	end := plan.To
	if plan.To.Sub(start) > width {
		end = start.Add(width)
	}
	return start, end, nil
}

func sortPeeringTraffic(buckets []PeeringTrafficBucket) {
	slices.SortFunc(buckets, func(a, b PeeringTrafficBucket) int {
		if order := a.Start.Compare(b.Start); order != 0 {
			return order
		}
		return slices.Compare([]string{a.InterfaceID, string(a.Role), a.State}, []string{b.InterfaceID, string(b.Role), b.State})
	})
}

func (m *Memory) PeeringTraffic(ctx context.Context, query PeeringTrafficQuery) (PeeringTrafficResult, error) {
	plan, err := normalizePeeringTraffic(ctx, query)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	tenant := query.Data.target.TenantID
	budget, err := explorerPlanBudget(ctx, m, tenant, m)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	snapshotBudget := budget
	snapshotBudget.MemoryBytes -= budget.MemoryBytes / 4
	rows, err := m.explorerSnapshot(withExplorerBudget(ctx, snapshotBudget), tenant, plan)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	// Ownership is the complete exporter/protocol/domain tuple, independently
	// of whether this particular flow's interface index can be mapped.
	type owner struct {
		exporter, protocol string
		domain             uint32
	}
	owners := map[owner]bool{}
	workspace := budget.MemoryBytes / 4
	for _, role := range query.Roles.rows {
		if workspace < 512 {
			return PeeringTrafficResult{}, ErrExplorerBudget
		}
		workspace -= 512
		owners[owner{role.Exporter, role.Protocol, role.Domain}] = true
	}
	totals := map[peeringTrafficGroup]*peeringTrafficTotal{}
	for _, entry := range rows {
		if err := ctx.Err(); err != nil {
			return PeeringTrafficResult{}, err
		}
		row := entry.row
		address, addressErr := netip.ParseAddr(row.Exporter)
		if addressErr != nil || address.Zone() != "" || !owners[owner{address.Unmap().String(), row.Protocol, row.ObsDomain}] {
			continue
		}
		index := row.InIf
		if query.Data.target.Direction == "outbound" {
			index = row.OutIf
		}
		key := peeringTrafficGroup{bucket: int64(row.TS.Sub(plan.From) / (time.Duration(plan.BucketSeconds) * time.Second)), role: entity.InterfaceRoleOther, state: query.Data.stateForRow(row)}
		if found, ok := query.Roles.byKey[interfaceRoleQueryKey{address.Unmap().String(), row.Protocol, row.ObsDomain, index}]; ok {
			role := query.Roles.rows[found]
			key.interfaceID, key.role = role.InterfaceID, role.Role
		}
		total := totals[key]
		if total == nil {
			if len(totals) >= budget.IntermediateGroups || workspace < 2048 {
				return PeeringTrafficResult{}, ErrExplorerBudget
			}
			workspace -= 2048
			total = &peeringTrafficTotal{}
			totals[key] = total
		}
		total.bytes.Add(&total.bytes, new(big.Int).SetUint64(row.BytesScaled))
		total.flows.Add(&total.flows, big.NewInt(1))
	}
	result := PeeringTrafficResult{Source: "memory", InputDigest: query.Data.digest, RoleDigest: query.Roles.digest, Buckets: make([]PeeringTrafficBucket, 0, len(totals))}
	for key, total := range totals {
		start, end, err := peeringTrafficBounds(plan, key.bucket)
		if err != nil {
			return PeeringTrafficResult{}, err
		}
		result.Buckets = append(result.Buckets, PeeringTrafficBucket{Start: start, End: end, InterfaceID: key.interfaceID, Role: key.role, State: key.state, Bytes: total.bytes.String(), Flows: total.flows.String()})
	}
	if err := query.Roles.validate(ctx, tenant, time.Now().UTC()); err != nil {
		return PeeringTrafficResult{}, err
	}
	sortPeeringTraffic(result.Buckets)
	return result, nil
}
