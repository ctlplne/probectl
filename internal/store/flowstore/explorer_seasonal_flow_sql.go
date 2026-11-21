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
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const seasonalMembershipBudgetMessage = "seasonal flow membership budget exceeded"

const seasonalPeriodGroup = "g,c,o,p,period_index"

type seasonalFlowSQLRead struct {
	sql    string
	params chParams
	clocks []explorerExternalData
}

// Use the same typed filters, source columns and decimal calculations as
// Explorer. A tenant-keyed ASOF join finds the clock tuple for each input;
// range(first, after) is the complete set of windows containing that input.
func buildSeasonalFlowSQL(ctx context.Context, budget ExplorerBudget, query PlanQuery, plan flow.QueryPlan, table string,
	names map[string]map[uint32]string, vocabulary flow.QueryVocabulary, clocks seasonalFlowClockRange, membershipLimit, topKeys int) (seasonalFlowSQLRead, error) {
	var empty seasonalFlowSQLRead
	if membershipLimit <= 0 {
		return empty, ErrExplorerBudget
	}
	if !explorerTablePattern.MatchString(table) {
		return empty, errors.New("invalid flow query table")
	}
	settings, err := budget.settings()
	if err != nil {
		return empty, err
	}
	external, err := seasonalClockExternal(ctx, query.TenantID, clocks, budget.MemoryBytes/8)
	if err != nil {
		return empty, err
	}
	params := chParams{
		"tenant": query.TenantID,
		"from":   plan.From.UTC().Format("2006-01-02 15:04:05.999999999"), "to": plan.To.UTC().Format("2006-01-02 15:04:05.999999999"),
		"clock_membership_limit": strconv.Itoa(membershipLimit),
		"prefix4":                strconv.Itoa(*plan.IPv4PrefixLength), "prefix6": strconv.Itoa(*plan.IPv6PrefixLength),
		"interfaces": planInterfaceNamesJSON(names), "window_ns": strconv.FormatInt(int64(clocks.lookback), 10),
		"width_ns": strconv.FormatInt(int64(time.Duration(plan.BucketSeconds)*time.Second), 10),
	}
	readWindows, err := clocks.exactReadWindows(ctx)
	if err != nil {
		return empty, err
	}
	filtered, err := planFilteredCTE(plan, table, params, vocabulary, query.Tags != nil, readWindows, query.DDoSProjection)
	if err != nil {
		return empty, err
	}
	columns, groups, order := planSQLColumns, seasonalPeriodGroup, "g,c"
	admissionColumns, admissionSelect := "", ""
	if usesDDoSWindowClock(query, clocks.lookback) {
		columns += ",start_ts,clock_basis"
		groups += ",crosses_window_start"
		order += ",crosses_window_start"
		exporter := strconv.Itoa(int(flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL))
		admissionColumns = ",toUInt8(expanded.clock_basis=" + exporter +
			" AND toUnixTimestamp64Nano(expanded.start_ts)<windows.window_start) AS crosses_window_start"
		admissionSelect = ",toString(crosses_window_start) AS crosses_window_start"
	}
	if query.DDoSVerifySampling {
		columns += ",bytes,packets,sampling"
		groups += ",invalid_sampling_counters"
		order += ",invalid_sampling_counters"
		// A product of two UInt64 inputs fits in UInt128. Comparing the
		// widened result also rejects a corrected value that wrapped.
		admissionColumns += ",toUInt8(expanded.sampling=0" +
			" OR toUInt128(expanded.bytes)*toUInt128(expanded.sampling)!=toUInt128(expanded.bytes_scaled)" +
			" OR toUInt128(expanded.packets)*toUInt128(expanded.sampling)!=toUInt128(expanded.packets_scaled)) AS invalid_sampling_counters"
		admissionSelect += ",toString(invalid_sampling_counters) AS invalid_sampling_counters"
	}
	joined := "clock_inputs AS (SELECT flow_input.tenant_id AS window_owner,__probectl_source_row AS g,__probectl_source_column AS c,toUInt8(0) AS o,toUInt8(0) AS p," + columns +
		",ifNull(periods.clock_first,toUInt64(0)) AS member_first,ifNull(periods.clock_after,toUInt64(0)) AS member_after FROM " +
		"(SELECT *,toUnixTimestamp64Nano(event_time) AS event_clock FROM filtered) AS flow_input ASOF LEFT JOIN seasonal_clock_lookup AS periods" +
		" ON flow_input.tenant_id=periods.clock_tenant AND flow_input.event_clock>=periods.clock_at)"
	// Materialize only original input rows for this check. The limit is
	// evaluated in the range argument before one row expands into its windows.
	const admitted = "clock_admitted AS (SELECT *,sum(toUInt128(member_after-member_first)) OVER () AS member_total FROM clock_inputs WHERE member_after>member_first)"
	const expanded = "clock_expanded AS (SELECT *,arrayJoin(range(member_first,member_after+" +
		"toUInt64(throwIf(member_total>{clock_membership_limit:UInt64},'" + seasonalMembershipBudgetMessage + "')))) AS period_index FROM clock_admitted)"
	// Every original membership survives the join to its unique clock.
	input := "period_inputs AS (SELECT expanded.*,windows.window_start AS period_start" + admissionColumns + " FROM clock_expanded AS expanded" +
		" ALL INNER JOIN seasonal_window_lookup AS windows ON expanded.window_owner=windows.window_tenant AND expanded.period_index=windows.window_index)"
	ctes := []string{filtered, joined, admitted, expanded, input}
	ctes = append(ctes, partitionedPlanStatsSQL("seasonal", "period_inputs", plan, planStatsPartition{
		groups: groups, start: "period_start", observed: true,
	})...)
	metrics := make([]string, 0, len(plan.Metrics))
	for i := range plan.Metrics {
		metrics = append(metrics, "toString(m"+strconv.Itoa(i)+")")
	}
	selectPopulation := ""
	if topKeys > 0 {
		primary := -1
		for i, metric := range plan.Metrics {
			if metric.Role == "primary" {
				primary = i
				break
			}
		}
		if primary < 0 {
			return empty, ErrExplorerBudget
		}
		selectPopulation = ",toString(count() OVER (PARTITION BY period_index)) AS total_groups"
		params["rank_read_limit"] = strconv.Itoa(topKeys + 1)
		order = "m" + strconv.Itoa(primary) + " DESC,g,c LIMIT {rank_read_limit:UInt64} BY period_index"
	}
	return seasonalFlowSQLRead{
		sql: "WITH " + strings.Join(ctes, ",") + " SELECT toString(period_index) AS clock_index,g,c,[" + strings.Join(metrics, ",") +
			"] AS metrics,toString(oldest_input,'UTC') AS oldest_input,toString(total_memberships) AS membership" + selectPopulation + admissionSelect +
			" FROM seasonal_stats ORDER BY period_index," + order + " " + settings,
		params: params, clocks: external,
	}, ctx.Err()
}

func seasonalClockExternal(ctx context.Context, tenant string, clocks seasonalFlowClockRange, memory int64) ([]explorerExternalData, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || tenant == "" || bound.String() != tenant {
		return nil, ErrNoTenant
	}
	transitions, err := clocks.transitions(ctx)
	if err != nil {
		return nil, err
	}
	type change struct {
		Tenant string `json:"clock_tenant"`
		At     int64  `json:"clock_at"`
		First  int    `json:"clock_first"`
		After  int    `json:"clock_after"`
	}
	type period struct {
		Tenant string `json:"window_tenant"`
		Index  int    `json:"window_index"`
		Start  int64  `json:"window_start"`
	}
	var boundaries, windows bytes.Buffer
	appendRow := func(target *bytes.Buffer, values any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		row, err := json.Marshal(values)
		if err != nil || int64(len(row)+1) > memory {
			return ErrExplorerBudget
		}
		target.Write(row)
		target.WriteByte('\n')
		memory -= int64(len(row) + 1)
		return nil
	}
	for _, item := range transitions {
		if err := appendRow(&boundaries, change{Tenant: tenant, At: item.at.UnixNano(), First: item.first, After: item.after}); err != nil {
			return nil, err
		}
	}
	for i, end := range clocks.ends {
		if err := appendRow(&windows, period{Tenant: tenant, Index: i, Start: end.Add(-clocks.lookback).UnixNano()}); err != nil {
			return nil, err
		}
	}
	return []explorerExternalData{{kind: externalSeasonalClocks, rows: boundaries.Bytes()}, {kind: externalSeasonalWindows, rows: windows.Bytes()}}, ctx.Err()
}
