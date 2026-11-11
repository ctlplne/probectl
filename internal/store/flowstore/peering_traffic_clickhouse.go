// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

func peeringTrafficExternal(ctx context.Context, query PeeringTrafficQuery, maxBytes int64) ([]explorerExternalData, error) {
	var interfaces, captures bytes.Buffer
	write := func(buffer *bytes.Buffer, row any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := json.Marshal(row)
		if err != nil {
			return err
		}
		if int64(len(body)+1) > maxBytes {
			return ErrExplorerBudget
		}
		maxBytes -= int64(len(body) + 1)
		buffer.Write(body)
		buffer.WriteByte('\n')
		return nil
	}
	for _, row := range query.Roles.rows {
		if err := write(&interfaces, struct {
			Tenant    string               `json:"peer_tenant"`
			Exporter  string               `json:"peer_exporter"`
			Protocol  string               `json:"peer_protocol"`
			Domain    uint32               `json:"peer_domain"`
			Index     uint32               `json:"peer_index"`
			Interface string               `json:"peer_interface"`
			Role      entity.InterfaceRole `json:"peer_role"`
		}{row.TenantID, row.Exporter, row.Protocol, row.Domain, row.IfIndex, row.InterfaceID, row.Role}); err != nil {
			return nil, err
		}
	}
	// Admit sorting and encoded buffers together before allocating the keys.
	if maxBytes < 0 || int64(len(query.Data.states)) > maxBytes/128 {
		return nil, ErrExplorerBudget
	}
	maxBytes -= int64(len(query.Data.states)) * 128
	keys := make([]routingQueryKey, 0, len(query.Data.states))
	for key := range query.Data.states {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b routingQueryKey) int { return slices.Compare(a.key[:], b.key[:]) })
	for _, key := range keys {
		state := query.Data.states[key].Source
		if query.Data.target.Direction == "outbound" {
			state = query.Data.states[key].Destination
		}
		if err := write(&captures, struct {
			Tenant string `json:"peer_capture_tenant"`
			Key    string `json:"peer_key"`
			Clock  string `json:"peer_clock"`
			State  string `json:"peer_state"`
		}{query.Data.target.TenantID, hex.EncodeToString(key.key[:]), strconv.FormatInt(key.clock, 10), state}); err != nil {
			return nil, err
		}
	}
	return []explorerExternalData{{kind: externalPeeringInterfaces, rows: interfaces.Bytes()}, {kind: externalPeeringCaptures, rows: captures.Bytes()}}, nil
}

func peeringTrafficSQL(query PeeringTrafficQuery, plan flow.QueryPlan, table string, budget ExplorerBudget) (string, chParams, error) {
	if !explorerTablePattern.MatchString(table) || query.Data == nil {
		return "", nil, ErrRoutingQueryScope
	}
	settings, err := budget.settings()
	if err != nil {
		return "", nil, err
	}
	index := "in_if"
	if query.Data.target.Direction == "outbound" {
		index = "out_if"
	}
	params := chParams{"tenant": query.Data.target.TenantID, "from": plan.From.Format("2006-01-02 15:04:05.999999999"), "to": plan.To.Format("2006-01-02 15:04:05.999999999"),
		"from_ns": strconv.FormatInt(plan.From.UnixNano(), 10), "width_ns": strconv.FormatInt(int64(time.Duration(plan.BucketSeconds)*time.Second), 10)}
	// Tenant/time scoping precedes every ownership and capture join. Ownership
	// does not depend on an interface match, keeping unmapped traffic visible.
	input := "(SELECT * FROM " + table + " FINAL WHERE tenant_id={tenant:String} AND ts>={from:DateTime64(9,'UTC')} AND ts<{to:DateTime64(9,'UTC')}) AS peer_input"
	tuple := "peer_owner.peer_tenant=tenant_id AND toIPv6OrNull(peer_owner.peer_exporter)=toIPv6OrNull(if(position(exporter,'%')=0,exporter,'')) AND peer_owner.peer_protocol=protocol AND peer_owner.peer_domain=obs_domain"
	from := input + " ANY INNER JOIN (SELECT DISTINCT peer_tenant,peer_exporter,peer_protocol,peer_domain FROM peering_interface_lookup) AS peer_owner ON " + tuple
	from += " ANY LEFT JOIN peering_interface_lookup AS peer_iface ON peer_iface.peer_tenant=tenant_id AND peer_iface.peer_exporter=peer_owner.peer_exporter AND peer_iface.peer_protocol=protocol AND peer_iface.peer_domain=obs_domain AND peer_iface.peer_index=" + index
	from += " ANY LEFT JOIN peering_capture_lookup AS peer_capture ON peer_capture.peer_capture_tenant=tenant_id AND peer_capture.peer_key=routing_capture_key AND peer_capture.peer_clock=routing_captured_unix_nanos"
	sql := "SELECT toString(intDiv(toUnixTimestamp64Nano(ts)-{from_ns:Int64},{width_ns:Int64})) AS bucket,ifNull(peer_iface.peer_interface,'') AS interface_id," +
		"ifNull(nullIf(peer_iface.peer_role,''),'other') AS role,ifNull(nullIf(peer_capture.peer_state,''),'unavailable') AS state," +
		"toString(sum(toUInt256(bytes_scaled))) AS bytes,toString(count()) AS flows FROM " + from +
		" GROUP BY bucket,interface_id,role,state\n" + settings
	return sql, params, nil
}

func decodePeeringTraffic(ctx context.Context, query PeeringTrafficQuery, plan flow.QueryPlan, source string, rows []map[string]any, budget ExplorerBudget) (PeeringTrafficResult, error) {
	if len(rows) > budget.IntermediateGroups || int64(len(rows)) > budget.MemoryBytes/2048 {
		return PeeringTrafficResult{}, ErrExplorerBudget
	}
	result := PeeringTrafficResult{Source: source, InputDigest: query.Data.digest, RoleDigest: query.Roles.digest, Buckets: make([]PeeringTrafficBucket, 0, len(rows))}
	seen := map[peeringTrafficGroup]bool{}
	interfaces := map[string]entity.InterfaceRole{}
	for _, row := range query.Roles.rows {
		if previous, exists := interfaces[row.InterfaceID]; exists && previous != row.Role {
			return PeeringTrafficResult{}, ErrInterfaceRoleQueryScope
		}
		interfaces[row.InterfaceID] = row.Role
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return PeeringTrafficResult{}, err
		}
		index, err := strconv.ParseInt(chToString(row["bucket"]), 10, 64)
		if err != nil || strconv.FormatInt(index, 10) != chToString(row["bucket"]) {
			return PeeringTrafficResult{}, ErrRoutingQueryScope
		}
		start, end, err := peeringTrafficBounds(plan, index)
		if err != nil {
			return PeeringTrafficResult{}, err
		}
		group := peeringTrafficGroup{index, chToString(row["interface_id"]), entity.InterfaceRole(chToString(row["role"])), chToString(row["state"])}
		if seen[group] || !validPeeringQueryState(group.state) || !validInterfaceRoleProjection(group.role) || (group.interfaceID != "" && !validTagProjectionID(group.interfaceID)) || (group.interfaceID == "" && group.role != entity.InterfaceRoleOther) {
			return PeeringTrafficResult{}, ErrRoutingQueryScope
		}
		if group.interfaceID != "" && interfaces[group.interfaceID] != group.role {
			return PeeringTrafficResult{}, ErrInterfaceRoleQueryScope
		}
		seen[group] = true
		counter := func(name string) (string, error) {
			value := chToString(row[name])
			n, ok := new(big.Int).SetString(value, 10)
			if !ok || n.Sign() < 0 || n.String() != value {
				return "", ErrRoutingQueryScope
			}
			return value, nil
		}
		bytesValue, err := counter("bytes")
		if err != nil {
			return PeeringTrafficResult{}, err
		}
		flows, err := counter("flows")
		if err != nil || flows == "0" {
			return PeeringTrafficResult{}, ErrRoutingQueryScope
		}
		result.Buckets = append(result.Buckets, PeeringTrafficBucket{Start: start, End: end, InterfaceID: group.interfaceID, Role: group.role, State: group.state, Bytes: bytesValue, Flows: flows})
	}
	if err := query.Roles.validate(ctx, query.Data.target.TenantID, time.Now().UTC()); err != nil {
		return PeeringTrafficResult{}, err
	}
	sortPeeringTraffic(result.Buckets)
	return result, nil
}

func (c *ClickHouse) PeeringTraffic(ctx context.Context, query PeeringTrafficQuery) (PeeringTrafficResult, error) {
	plan, err := normalizePeeringTraffic(ctx, query)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	tenant := query.Data.target.TenantID
	budget, err := explorerPlanBudget(ctx, c, tenant, c)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	external, err := peeringTrafficExternal(ctx, query, budget.MemoryBytes/4)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	target, err := c.route(ctx, tenant)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	lane, err := c.readLane(target, tenant)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	if !lane.Reader {
		return PeeringTrafficResult{}, chclient.ErrReaderRequired
	}
	source, err := c.planSourceFor(ctx, target, lane, tenant, plan)
	if err != nil {
		return PeeringTrafficResult{}, err
	}
	for {
		if source.coverage == nil || !source.coverage.CompleteInputs {
			return PeeringTrafficResult{}, &PlanCoverageError{Reason: "peering requires original flow and routing inputs", ResolutionSeconds: 3600}
		}
		sql, params, err := peeringTrafficSQL(query, plan, source.table, budget)
		if err != nil {
			return PeeringTrafficResult{}, err
		}
		rows, err := c.explorerQueryRows(ctx, target, lane, tenant, sql, params, external...)
		if err != nil {
			return PeeringTrafficResult{}, err
		}
		if source.kind == "raw" {
			current, err := c.planSourceFor(ctx, target, lane, tenant, plan)
			if err != nil {
				return PeeringTrafficResult{}, err
			}
			if current.kind != source.kind {
				source = current
				continue
			}
		}
		return decodePeeringTraffic(ctx, query, plan, source.kind, rows, budget)
	}
}
