// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

func (c *ClickHouse) incidentTrafficRows(ctx context.Context, query IncidentTrafficQuery) ([]Row, error) {
	plan, err := routingReferencePlan(ctx, query.TenantID, query.From, query.To, query.Series)
	if err != nil {
		return nil, err
	}
	budget, err := explorerPlanBudget(ctx, c, query.TenantID, c)
	if err != nil {
		return nil, err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	_, selection, err := incidentTrafficSelectors(ctx, query, budget.MemoryBytes/8)
	if err != nil {
		return nil, err
	}
	target, err := c.route(ctx, query.TenantID)
	if err != nil {
		return nil, err
	}
	lane, err := c.readLane(target, query.TenantID)
	if err != nil {
		return nil, err
	}
	if !lane.Reader {
		return nil, chclient.ErrReaderRequired
	}
	source, err := c.planSourceFor(ctx, target, lane, query.TenantID, plan)
	if err != nil {
		return nil, err
	}
	params := chParams{"tenant": query.TenantID, "from": plan.From.UTC().Format("2006-01-02 15:04:05.999999999"), "to": plan.To.UTC().Format("2006-01-02 15:04:05.999999999")}
	// The external set contains only server-selected source identities. IN,
	// rather than a multiplying JOIN, counts each original record once even
	// when a router and both of its interfaces are selected together.
	sql := `SELECT tenant_id,agent_id,exporter,protocol,toString(obs_domain) AS obs_domain,
	 src_addr,dst_addr,toString(in_if) AS in_if,toString(out_if) AS out_if,
	 toString(bytes) AS raw_bytes,toString(packets) AS raw_packets,toString(sampling) AS sampling,
	 toString(toUnixTimestamp64Nano(ts)) AS time_nanos,toString(toUnixTimestamp64Nano(start_ts)) AS start_nanos,
	 raw_flow_digest,routing_capture_key,toString(routing_captured_unix_nanos) AS routing_captured_unix_nanos
	 FROM ` + source.table + ` FINAL
	 WHERE tenant_id={tenant:String} AND ts>={from:DateTime64(9,'UTC')} AND ts<{to:DateTime64(9,'UTC')}
	 AND (
	 (tenant_id,agent_id,exporter,protocol,obs_domain) GLOBAL IN
	 (SELECT impact_tenant,impact_agent,impact_exporter,impact_protocol,impact_domain FROM incident_source_lookup WHERE impact_index=0)
	 OR (tenant_id,agent_id,exporter,protocol,obs_domain,in_if) GLOBAL IN
	 (SELECT impact_tenant,impact_agent,impact_exporter,impact_protocol,impact_domain,impact_index FROM incident_source_lookup WHERE impact_index>0)
	 OR (tenant_id,agent_id,exporter,protocol,obs_domain,out_if) GLOBAL IN
	 (SELECT impact_tenant,impact_agent,impact_exporter,impact_protocol,impact_domain,impact_index FROM incident_source_lookup WHERE impact_index>0))`
	settings, err := budget.settings()
	if err != nil {
		return nil, err
	}
	rows, err := c.explorerQueryRows(ctx, target, lane, query.TenantID, sql+settings, params,
		explorerExternalData{kind: externalIncidentSources, rows: selection})
	if err != nil {
		return nil, err
	}
	return decodeIncidentTrafficRows(ctx, query.TenantID, rows, budget.MemoryBytes)
}

var errIncidentTrafficRow = errors.New("flowstore: incomplete incident traffic row")

func decodeIncidentTrafficRows(ctx context.Context, tenant string, values []map[string]any, maxBytes int64) ([]Row, error) {
	if maxBytes <= 0 || int64(len(values)) > maxBytes/1024 {
		return nil, ErrExplorerBudget
	}
	out := make([]Row, 0, len(values))
	remaining := maxBytes
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := decodeIncidentTrafficRow(tenant, value)
		if err != nil {
			return nil, err
		}
		cost := int64(1024 + len(row.AgentID) + len(row.Exporter) + len(row.Protocol) + len(row.SrcAddr) + len(row.DstAddr))
		if cost > remaining {
			return nil, ErrExplorerBudget
		}
		remaining -= cost
		out = append(out, row)
	}
	return out, nil
}

func decodeIncidentTrafficRow(tenant string, value map[string]any) (Row, error) {
	row := Row{TenantID: chToString(value["tenant_id"]), AgentID: chToString(value["agent_id"]),
		Exporter: chToString(value["exporter"]), Protocol: chToString(value["protocol"]), SrcAddr: chToString(value["src_addr"]), DstAddr: chToString(value["dst_addr"]),
		RawFlowDigest: chToString(value["raw_flow_digest"]), RoutingCaptureKey: chToString(value["routing_capture_key"])}
	if row.TenantID != tenant || row.AgentID == "" || row.Exporter == "" || row.Protocol == "" || row.SrcAddr == "" || row.DstAddr == "" {
		return Row{}, errIncidentTrafficRow
	}
	for _, column := range []struct {
		name string
		bits int
		set  func(uint64)
	}{
		{"obs_domain", 32, func(v uint64) { row.ObsDomain = uint32(v) }},
		{"in_if", 32, func(v uint64) { row.InIf = uint32(v) }},
		{"out_if", 32, func(v uint64) { row.OutIf = uint32(v) }},
		{"raw_bytes", 64, func(v uint64) { row.Bytes = v }},
		{"raw_packets", 64, func(v uint64) { row.Packets = v }},
		{"sampling", 64, func(v uint64) { row.Sampling = v }},
	} {
		number, err := strconv.ParseUint(chToString(value[column.name]), 10, column.bits)
		if err != nil {
			return Row{}, errIncidentTrafficRow
		}
		column.set(number)
	}
	for _, column := range []struct {
		name string
		set  func(int64)
	}{
		{"time_nanos", func(v int64) { row.TS = time.Unix(0, v).UTC() }},
		{"start_nanos", func(v int64) { row.StartTS = time.Unix(0, v).UTC() }},
		{"routing_captured_unix_nanos", func(v int64) { row.RoutingCapturedUnixNanos = v }},
	} {
		number, err := strconv.ParseInt(chToString(value[column.name]), 10, 64)
		if err != nil {
			return Row{}, errIncidentTrafficRow
		}
		column.set(number)
	}
	if row.Sampling == 0 || row.StartTS.After(row.TS) || validateRoutingCaptureRow(row) != nil {
		return Row{}, errIncidentTrafficRow
	}
	return row, nil
}
