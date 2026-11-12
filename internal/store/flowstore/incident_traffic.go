// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

// IncidentTrafficSource is a server-selected measurement point, never source
// authority. The caller must authorize its canonical owner and validate each
// returned original capture before attributing a row to an incident/customer.
type IncidentTrafficSource struct {
	AgentID          string
	Exporter         netip.Addr
	Protocol         string
	Domain           uint32
	WholeDevice      bool
	InterfaceIndices []uint32
}

type IncidentTrafficQuery struct {
	TenantID string
	From, To time.Time
	Series   string
	Sources  []IncidentTrafficSource
}

// IncidentTrafficCaptureReferences derives lookup selectors from complete
// server-read rows. Legacy observations without a capture remain explicitly
// unverified; malformed or contradictory retained identities fail the read.
func IncidentTrafficCaptureReferences(ctx context.Context, tenant string, rows []Row, maxBytes int64) ([]RoutingCaptureRead, error) {
	seen := map[[32]byte]RoutingCaptureRead{}
	remaining := maxBytes
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.TenantID != tenant {
			return nil, ErrNoTenant
		}
		if row.RoutingCaptureKey == "" {
			continue
		}
		read, err := routingReadFromRow(row)
		if err != nil {
			return nil, err
		}
		if old, found := seen[read.Ref.Key]; found {
			if old != read {
				return nil, errIncidentTrafficRow
			}
			continue
		}
		cost := int64(1024 + len(read.Sender))
		if cost > remaining {
			return nil, ErrExplorerBudget
		}
		remaining -= cost
		seen[read.Ref.Key] = read
	}
	out := make([]RoutingCaptureRead, 0, len(seen))
	for _, read := range seen {
		out = append(out, read)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Ref.Key[:], out[j].Ref.Key[:]) < 0 })
	return out, nil
}

// IncidentTrafficRows consumes one plan slot and the same cumulative tenant
// read/deadline envelope as the other comparison period. There is no display
// limit, ranking or Other group; any incomplete read returns no usable prefix.
func (b *PlanBatch) IncidentTrafficRows(query IncidentTrafficQuery) ([]Row, error) {
	b.queryMu.Lock()
	defer b.queryMu.Unlock()
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	if query.TenantID != b.tenant {
		b.failed = true
		return nil, ErrNoTenant
	}
	if b.failed || b.queries == 0 {
		b.failed = true
		return nil, ErrExplorerBudget
	}
	b.queries--
	var out []Row
	var err error
	switch backend := b.backend.(type) {
	case *Memory:
		out, err = backend.incidentTrafficRows(b.queryContext(), query)
	case *ClickHouse:
		out, err = backend.incidentTrafficRows(b.queryContext(), query)
	default:
		err = ErrExplorerBudget
	}
	if err != nil {
		b.failed = true
		return nil, err
	}
	return out, nil
}

type incidentTrafficSelector struct {
	Tenant   string `json:"impact_tenant"`
	Agent    string `json:"impact_agent"`
	Exporter string `json:"impact_exporter"`
	Protocol string `json:"impact_protocol"`
	Domain   uint32 `json:"impact_domain"`
	Index    uint32 `json:"impact_index"`
}

func incidentTrafficSelectors(ctx context.Context, query IncidentTrafficQuery, maxBytes int64) ([]incidentTrafficSelector, []byte, error) {
	if len(query.Sources) == 0 || maxBytes <= 0 || int64(len(query.Sources)) > maxBytes/1024 {
		return nil, nil, ErrExplorerBudget
	}
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	selectors := []incidentTrafficSelector{}
	seen := map[incidentTrafficSelector]bool{}
	remaining := maxBytes
	for _, source := range query.Sources {
		key, err := (entity.SourceKey{AgentID: source.AgentID, Kind: entity.FlowExporter, SourceRef: source.Exporter.String()}).Normalize()
		if err != nil || key.AgentID != source.AgentID || !source.Exporter.IsValid() || source.Exporter.Is4In6() || source.Exporter.Zone() != "" || source.Exporter.IsUnspecified() || source.Exporter.IsMulticast() {
			return nil, nil, ErrExplorerBudget
		}
		switch source.Protocol {
		case "netflow5", "netflow9", "ipfix", "sflow5":
		default:
			return nil, nil, ErrExplorerBudget
		}
		indices := source.InterfaceIndices
		if source.WholeDevice {
			indices = []uint32{0}
		} else if len(indices) == 0 {
			return nil, nil, ErrExplorerBudget
		}
		for _, index := range indices {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			if !source.WholeDevice && index == 0 {
				return nil, nil, ErrExplorerBudget
			}
			selector := incidentTrafficSelector{query.TenantID, source.AgentID, source.Exporter.String(), source.Protocol, source.Domain, index}
			if seen[selector] {
				continue
			}
			cost := int64(512+len(selector.Tenant)+len(selector.Agent)+len(selector.Exporter)+len(selector.Protocol)) * 4
			if cost > remaining {
				return nil, nil, ErrExplorerBudget
			}
			remaining -= cost
			seen[selector] = true
			selectors = append(selectors, selector)
			if err := encoder.Encode(selector); err != nil {
				return nil, nil, err
			}
		}
	}
	return selectors, data.Bytes(), nil
}

type incidentTrafficSourceKey struct {
	tenant, agent, exporter, protocol string
	domain                            uint32
}

func incidentTrafficMembership(selectors []incidentTrafficSelector) map[incidentTrafficSourceKey]map[uint32]bool {
	out := make(map[incidentTrafficSourceKey]map[uint32]bool)
	for _, selector := range selectors {
		key := incidentTrafficSourceKey{selector.Tenant, selector.Agent, selector.Exporter, selector.Protocol, selector.Domain}
		if out[key] == nil {
			out[key] = map[uint32]bool{}
		}
		out[key][selector.Index] = true
	}
	return out
}

func incidentTrafficMatches(row Row, membership map[incidentTrafficSourceKey]map[uint32]bool) bool {
	indices := membership[incidentTrafficSourceKey{row.TenantID, row.AgentID, row.Exporter, row.Protocol, row.ObsDomain}]
	return indices[0] || indices[row.InIf] || indices[row.OutIf]
}

func projectIncidentTrafficRow(row Row) Row {
	return Row{TenantID: row.TenantID, AgentID: row.AgentID, Exporter: row.Exporter, Protocol: row.Protocol, ObsDomain: row.ObsDomain,
		TS: row.TS, StartTS: row.StartTS, SrcAddr: row.SrcAddr, DstAddr: row.DstAddr, InIf: row.InIf, OutIf: row.OutIf,
		Bytes: row.Bytes, Packets: row.Packets, Sampling: row.Sampling, RawFlowDigest: row.RawFlowDigest,
		RoutingCaptureKey: row.RoutingCaptureKey, RoutingCapturedUnixNanos: row.RoutingCapturedUnixNanos}
}

func (m *Memory) incidentTrafficRows(ctx context.Context, query IncidentTrafficQuery) ([]Row, error) {
	plan, err := routingReferencePlan(ctx, query.TenantID, query.From, query.To, query.Series)
	if err != nil {
		return nil, err
	}
	budget, err := explorerPlanBudget(ctx, m, query.TenantID, m)
	if err != nil {
		return nil, err
	}
	selectors, _, err := incidentTrafficSelectors(ctx, query, budget.MemoryBytes/8)
	if err != nil {
		return nil, err
	}
	membership := incidentTrafficMembership(selectors)
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Row{}
	used := int64(0)
	for _, entry := range m.rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := entry.row
		if row.TenantID != query.TenantID || row.TS.Before(plan.From) || !row.TS.Before(plan.To) || !incidentTrafficMatches(row, membership) {
			continue
		}
		if row.Sampling == 0 || row.StartTS.After(row.TS) || validateRoutingCaptureRow(row) != nil {
			return nil, errIncidentTrafficRow
		}
		cost := int64(1024 + len(row.AgentID) + len(row.Exporter) + len(row.SrcAddr) + len(row.DstAddr) + len(row.Protocol))
		if len(out) >= budget.ReadRows || cost > min(budget.MemoryBytes, budget.ReadBytes)-used {
			return nil, ErrExplorerBudget
		}
		if err := chargeBatchRead(ctx, query.TenantID, 1, cost); err != nil {
			return nil, err
		}
		used += cost
		out = append(out, projectIncidentTrafficRow(row))
	}
	return out, nil
}
