// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

const planCostSettings = "SETTINGS max_execution_time=60,timeout_overflow_mode='throw',max_bytes_to_read=268435456,max_rows_to_read=5000000,read_overflow_mode='throw',max_rows_to_group_by=500000,group_by_overflow_mode='throw',max_result_rows=500000,result_overflow_mode='throw',max_memory_usage=2147483648,max_threads=2"

const planSQLColumns = "event_time,bytes_scaled,packets_scaled,canonical_src,canonical_dst,src_port,dst_port,src_asn,dst_asn,src_country,dst_country"
const planSQLGroup = "g,c,o,p"

// Keep address normalization inside the tenant/time-bounded input. Named
// computed columns preserve the full predicate reach without expanding one
// formatter thousands of times or increasing ClickHouse parser limits.
func planInputSQL(table, eventTime string, prefixSides ...string) string {
	fields := make([]string, 0, 3)
	for _, field := range flow.QueryFields() {
		if field.Type != flow.QueryAddress {
			continue
		}
		column := field.Column
		fields = append(fields, explorerCanonicalAddressSQL(column)+" AS "+explorerAddressExpr(column))
	}
	for _, side := range prefixSides {
		family, number := prefixTagAddressSQL(prefixTagColumn(side))
		fields = append(fields, family+" AS "+prefixTagFamilyColumn(side), number+" AS "+prefixTagPointColumn(side))
	}
	return "(SELECT *, " + strings.Join(fields, ",") + " FROM " + table + " FINAL WHERE tenant_id={tenant:String} AND " + eventTime + ">={from:DateTime64(9,'UTC')} AND " + eventTime + "<{to:DateTime64(9,'UTC')}) AS flow_input"
}

// No public value contributes SQL structure: dimensions/operators/metrics all
// come from the shared registry. Literal values, including metadata, are bound.
func planSQL(plan flow.QueryPlan, table string, names map[string]map[uint32]string, membership ...[][]string) (string, chParams, error) {
	return planSQLWithBudget(DefaultExplorerBudget(), plan, table, names, membership...)
}

func planSQLWithBudget(budget ExplorerBudget, plan flow.QueryPlan, table string, names map[string]map[uint32]string, membership ...[][]string) (string, chParams, error) {
	return planSQLWithTags(budget, plan, table, names, "", nil, membership...)
}

func planSQLWithTags(budget ExplorerBudget, plan flow.QueryPlan, table string,
	names map[string]map[uint32]string, tenantID string, tagData *TagQueryData,
	membership ...[][]string) (string, chParams, error) {
	return planSQLWithRoleMetadata(budget, plan, table, names, tenantID, tagData, nil, membership...)
}

func planSQLWithRoleMetadata(budget ExplorerBudget, plan flow.QueryPlan, table string,
	names map[string]map[uint32]string, tenantID string, tagData *TagQueryData, roleData *InterfaceRoleQueryData,
	membership ...[][]string) (string, chParams, error) {
	return planSQLWithRoutingMetadata(budget, plan, table, names, tenantID, tagData, roleData, nil, membership...)
}

func planSQLWithRoutingMetadata(budget ExplorerBudget, plan flow.QueryPlan, table string,
	names map[string]map[uint32]string, tenantID string, tagData *TagQueryData, roleData *InterfaceRoleQueryData,
	routing *routingQueryData, membership ...[][]string) (string, chParams, error) {
	settings, err := budget.settings()
	if err != nil {
		return "", nil, err
	}
	var vocabulary flow.QueryVocabulary
	if tagData != nil {
		vocabulary, err = tagData.Vocabulary(tenantID)
		if err != nil {
			return "", nil, err
		}
	}
	plan, err = flow.NormalizeQueryPlanWithVocabulary(plan, time.Now(), vocabulary)
	if err != nil {
		return "", nil, err
	}
	if planUsesInterfaceRoles(plan) && (roleData == nil || roleData.tenantID != tenantID) {
		return "", nil, ErrInterfaceRoleQueryScope
	}
	if planUsesRouting(plan) && (routing == nil || routing.tenant != tenantID) {
		return "", nil, ErrRoutingQueryScope
	}
	if !explorerTablePattern.MatchString(table) {
		return "", nil, errors.New("invalid flow query table")
	}
	params := chParams{"from": plan.From.Format("2006-01-02 15:04:05.999999999"), "to": plan.To.Format("2006-01-02 15:04:05.999999999"), "prefix4": strconv.Itoa(*plan.IPv4PrefixLength), "prefix6": strconv.Itoa(*plan.IPv6PrefixLength), "width_ns": strconv.FormatInt(int64(time.Duration(plan.BucketSeconds)*time.Second), 10), "window_ns": strconv.FormatInt(int64(plan.To.Sub(plan.From)), 10)}
	params["detail_limit"] = strconv.Itoa(plan.RowLimit)
	params["series_limit"] = strconv.Itoa(plan.SeriesDepth)
	params["matrix_depth"] = strconv.Itoa(plan.MatrixDepth)

	params["interfaces"] = planInterfaceNamesJSON(names)
	filter, err := explorerFilterSQLWithVocabulary(plan.Filter, params, vocabulary)
	if err != nil {
		return "", nil, err
	}
	key := func(fields []string) string {
		parts := []string{}
		for _, name := range fields {
			field, _ := vocabulary.Lookup(name)
			parts = append(parts, explorerGroupExprWithParams(field, params))
		}
		if len(parts) == 0 {
			return "CAST([],'Array(String)')"
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	eventTime := "ts"
	if strings.HasSuffix(table, sharedFlowRollupsTable) {
		eventTime = "if(coverage_version=0,toDateTime64(bucket,3),ts)"
	}
	sides := planTagPrefixSides(plan)
	from := planInputSQL(table, eventTime, sides...)
	if tagData != nil {
		from += " ANY LEFT JOIN tag_lookup ON tag_lookup.lookup_tenant=tenant_id AND toIPv6OrNull(tag_lookup.lookup_exporter)=toIPv6OrNull(if(position(exporter,'%')=0,exporter,''))"
		for _, side := range sides {
			from += prefixTagJoinSQL(side)
		}
		from = prefixTagProjectionSQL(from, sides)
	}
	from = planInterfaceRoleJoinsSQL(from, plan)
	from = planRoutingJoinsSQL(from, plan)

	// Original keys have names distinct from the transformed g/c aliases below.
	// In particular column_input remaps the original column into g and clears c;
	// nested scalar expansion must keep referring to the original source keys.
	ctes := []string{"filtered AS (SELECT " + key(plan.GroupBy) + " AS __probectl_source_row," + key(plan.MatrixWith) + " AS __probectl_source_column," + eventTime + " AS event_time,bytes_scaled,packets_scaled," + explorerAddressExpr("src_addr") + " AS canonical_src," + explorerAddressExpr("dst_addr") + " AS canonical_dst,src_port,dst_port,src_asn,dst_asn,src_country,dst_country FROM " + from + " WHERE tenant_id={tenant:String} AND " + eventTime + ">={from:DateTime64(9,'UTC')} AND " + eventTime + "<{to:DateTime64(9,'UTC')} AND (" + filter + "))"}
	empty := "CAST([],'Array(String)')"
	input := func(name, g, c, o, p, condition string) {
		sql := name + " AS (SELECT " + g + " AS g," + c + " AS c,toUInt8(" + o + ") AS o,toUInt8(" + p + ") AS p," + planSQLColumns + " FROM filtered"
		if condition != "" {
			sql += " WHERE " + condition
		}
		ctes = append(ctes, sql+")")
	}
	input("full_input", "filtered.__probectl_source_row", empty, "0", "0", "")
	ctes = append(ctes, planStatsSQL("full", "full_input", plan)...)
	primary := 0
	for i, metric := range plan.Metrics {
		if metric.Role == "primary" {
			primary = i
			break
		}
	}
	rank := func(name, source string) {
		ctes = append(ctes, name+" AS (SELECT *,row_number() OVER (ORDER BY m"+strconv.Itoa(primary)+" DESC,g,c,o,p) AS rk,count() OVER () AS ng FROM "+source+")")
	}
	var selected, selectedColumns, selectedChart, selectedMatrixRows [][]string
	if len(membership) > 4 {
		return "", nil, errors.New("invalid comparison membership")
	}
	if len(membership) >= 1 {
		selected, err = normalizePlanGroupsWithVocabulary(membership[0], plan, vocabulary, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) >= 2 {
		selectedColumns, err = normalizePlanColumnsWithVocabulary(membership[1], plan, vocabulary, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) >= 3 {
		selectedChart, err = normalizePlanChartGroupsWithVocabulary(membership[2], plan, vocabulary, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) == 4 {
		selectedMatrixRows, err = normalizePlanMatrixRowsWithVocabulary(membership[3], plan, vocabulary, budget)
		if err != nil {
			return "", nil, err
		}
	}
	globalRank := "ranked"
	if selected == nil {
		rank("ranked", "full_stats")
	} else {
		globalRank = "all_ranked"
		encoded, err := json.Marshal(selected)
		if err != nil {
			return "", nil, err
		}
		params["selected"] = string(encoded)
		rank("all_ranked", "full_stats")
		fields := []string{planSQLGroup}
		for i := range plan.Metrics {
			fields = append(fields, "m"+strconv.Itoa(i))
		}
		ctes = append(ctes, "ranked AS (SELECT "+strings.Join(fields, ",")+",indexOf(JSONExtract({selected:String},'Array(Array(String))'),g) AS rk,ng FROM all_ranked WHERE g IN (SELECT arrayJoin(JSONExtract({selected:String},'Array(Array(String))'))))")
	}
	projection := func(prefix string) string {
		items := []string{}
		for i := range plan.Metrics {
			items = append(items, "toString("+prefix+"m"+strconv.Itoa(i)+")")
		}
		return "[" + strings.Join(items, ",") + "]"
	}
	output := func(kind, source, where, bi, duration, total string) string {
		sql := "SELECT '" + kind + "' AS kind,g,c,o,p," + bi + " AS bi," + duration + " AS duration," + projection("") + " AS metrics," + total + " AS total_groups,'' AS oldest_input FROM " + source
		if where != "" {
			sql += " WHERE " + where
		}
		return sql
	}
	outputs := []string{output("detail", "ranked", "rk<={detail_limit:UInt64}", "toInt64(-1)", "'0'", "ng")}
	zeroMetrics := make([]string, len(plan.Metrics))
	for i := range zeroMetrics {
		zeroMetrics[i] = "'0'"
	}
	outputs = append(outputs, "SELECT 'counts' AS kind,"+empty+" AS g,"+empty+" AS c,toUInt8(0) AS o,toUInt8(0) AS p,toInt64(-1) AS bi,'0' AS duration,["+strings.Join(zeroMetrics, ",")+"] AS metrics,toUInt64(uniqExact(filtered.__probectl_source_row)) AS total_groups,if(count()=0,'',toString(min(event_time),'UTC')) AS oldest_input FROM filtered")
	input("other_input", empty, empty, "1", "0", "filtered.__probectl_source_row NOT IN (SELECT g FROM ranked WHERE rk<={detail_limit:UInt64})")
	ctes = append(ctes, planStatsSQL("other", "other_input", plan)...)
	outputs = append(outputs, output("other", "other_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
	input("total_input", empty, empty, "0", "0", "")
	ctes = append(ctes, planStatsSQL("total", "total_input", plan)...)
	outputs = append(outputs, output("totals", "total_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
	pointProjection := func(prefix string) string {
		fields := []string{}
		_, measureIndices := planSQLMeasures(plan)
		for i, metric := range plan.Metrics {
			fields = append(fields, planSampleSQL(metric.Measure, "v"+strconv.Itoa(measureIndices[metric.Measure]), "duration_ns")+" AS m"+strconv.Itoa(i))
		}
		return prefix + "_points AS (SELECT *," + strings.Join(fields, ",") + " FROM " + prefix + "_buckets)"
	}
	if plan.View != "table" {
		ctes = append(ctes, pointProjection("total"))
		outputs = append(outputs, output("total_point", "total_points", "", "bucket_index", "toString(duration_ns)", "toUInt64(0)"))
	}
	if plan.View != "table" && plan.View != "matrix" {
		chartTop := "SELECT g FROM " + globalRank + " WHERE rk<={series_limit:UInt64}"
		if selectedChart != nil {
			encoded, err := json.Marshal(selectedChart)
			if err != nil {
				return "", nil, err
			}
			params["selected_chart"] = string(encoded)
			chartTop = "SELECT arrayJoin(JSONExtract({selected_chart:String},'Array(Array(String))'))"
		}
		outputs = append(outputs, output("chart_detail", "full_stats", "g IN ("+chartTop+")", "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("chart_other_input", empty, empty, "1", "0", "filtered.__probectl_source_row NOT IN ("+chartTop+")")
		ctes = append(ctes, planStatsSQL("chart_other", "chart_other_input", plan)...)
		outputs = append(outputs, output("chart_other", "chart_other_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("chart_input", "if(filtered.__probectl_source_row IN ("+chartTop+"),filtered.__probectl_source_row,"+empty+")", empty, "filtered.__probectl_source_row NOT IN ("+chartTop+")", "0", "")
		ctes = append(ctes, planBucketSQL("chart", "chart_input", plan))
		ctes = append(ctes, pointProjection("chart"))
		outputs = append(outputs, output("point", "chart_points", "", "bucket_index", "toString(duration_ns)", "toUInt64(0)"))
	}
	if plan.View == "matrix" {
		rowGroups := "tupleElement(__probectl_matrix_rows,2)"
		if selectedMatrixRows != nil {
			encoded, err := json.Marshal(selectedMatrixRows)
			if err != nil {
				return "", nil, err
			}
			params["selected_matrix_rows"] = string(encoded)
			rowGroups = "JSONExtract({selected_matrix_rows:String},'Array(Array(String))')"
		} else {
			// Scalar folding is query-local. Referencing a ranked table CTE at
			// every membership site repeatedly analyzes its complete input,
			// including owned prefix joins; compute the exact top set once.
			// Keep row and conditioned-column scalar domains explicit: their
			// arrays have the same type but must never share a cached binding.
			ctes = append(ctes, planMatrixMembersSQL(plan, primary, false)...)
		}
		rowMember := func(group string) string { return "has(" + rowGroups + "," + group + ")" }
		outputs = append(outputs, output("matrix_row", "full_stats", rowMember("g"), "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("column_input", "filtered.__probectl_source_column", empty, "0", "0", rowMember("filtered.__probectl_source_row"))
		ctes = append(ctes, planStatsSQL("column", "column_input", plan)...)
		if selectedColumns == nil {
			rank("column_ranked", "column_stats")
		} else {
			encoded, err := json.Marshal(selectedColumns)
			if err != nil {
				return "", nil, err
			}
			params["selected_columns"] = string(encoded)
			ctes = append(ctes, "column_ranked AS (SELECT *,indexOf(JSONExtract({selected_columns:String},'Array(Array(String))'),g) AS rk FROM column_stats WHERE g IN (SELECT arrayJoin(JSONExtract({selected_columns:String},'Array(Array(String))'))))")
		}
		columnGroups := "tupleElement(__probectl_matrix_columns,2)"
		if selectedColumns != nil {
			// Preserve pinned membership even when a column occurs only in
			// this period's Other rows and has no conditioned statistics.
			columnGroups = "JSONExtract({selected_columns:String},'Array(Array(String))')"
		} else {
			ctes = append(ctes, planMatrixMembersSQL(plan, primary, true)...)
		}
		outputs = append(outputs, output("matrix_column", "column_ranked", "rk<={matrix_depth:UInt64}", "toInt64(-1)", "'0'", "toUInt64(0)"))
		// Keep complete Array(String) group keys as elements of the scalar
		// Array(Array(String)); avoid constructing an IN subquery/set here.
		columnMember := func(group string) string { return "has(" + columnGroups + "," + group + ")" }
		input("matrix_input", "if("+rowMember("filtered.__probectl_source_row")+",filtered.__probectl_source_row,"+empty+")", "if("+columnMember("filtered.__probectl_source_column")+",filtered.__probectl_source_column,"+empty+")", "NOT "+rowMember("filtered.__probectl_source_row"), "NOT "+columnMember("filtered.__probectl_source_column"), "")
		ctes = append(ctes, planStatsSQL("matrix", "matrix_input", plan)...)
		outputs = append(outputs, output("matrix", "matrix_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
	}
	// Throw on every cost limit: no silently truncated or approximate response.
	sql := "WITH " + strings.Join(ctes, ",\n") + "\n" + strings.Join(outputs, "\nUNION ALL\n") + "\n" + settings
	return sql, params, nil
}

// Automatic top-set membership needs only the primary metric, while public
// output retains every metric. Preserve each axis's exact compiler-owned CTE,
// source, member alias and scalar domain through this decomposition.
func planMatrixMembersSQL(plan flow.QueryPlan, primary int, columns bool) []string {
	name, source, member := "matrix_row_members", "full_input", "row_members"
	domain, scalar := "matrix_rows", "__probectl_matrix_rows"
	if columns {
		name, source, member = "matrix_column_members", "column_input", "column_members"
		domain, scalar = "matrix_columns", "__probectl_matrix_columns"
	}
	plan.Metrics = []flow.QueryMetric{plan.Metrics[primary]}
	ctes := planStatsSQL(name, source, plan)
	ranked := name + "_ranked"
	ctes = append(ctes, ranked+" AS (SELECT *,row_number() OVER (ORDER BY m0 DESC,g,c,o,p) AS rk FROM "+name+"_stats)")
	ctes = append(ctes, "(SELECT tuple('"+domain+"',groupArray("+member+".g)) FROM "+ranked+" AS "+member+" WHERE "+member+".rk<={matrix_depth:UInt64}) AS "+scalar)
	return ctes
}

func planAggregateSQL(measure string) string {
	switch measure {
	case "bytes", "bps":
		return "sum(toDecimal256(bytes_scaled,0))"
	case "packets", "pps":
		return "sum(toDecimal256(packets_scaled,0))"
	case "flows", "fps":
		return "toDecimal256(count(),0)"
	}
	column := map[string]string{"unique_src": "canonical_src", "unique_dst": "canonical_dst", "unique_src_port": "src_port", "unique_dst_port": "dst_port", "unique_src_asn": "src_asn", "unique_dst_asn": "dst_asn", "unique_src_country": "src_country", "unique_dst_country": "dst_country"}[measure]
	condition := column + "!=''"
	if strings.HasSuffix(measure, "_port") {
		condition = "1"
	}
	if strings.HasSuffix(measure, "_asn") {
		condition = column + "!=0"
	}
	return "toDecimal256(uniqExactIf(" + column + "," + condition + "),0)"
}

func planSampleSQL(measure, value, duration string) string {
	factor := "1000000000"
	if measure == "bps" {
		factor = "8000000000"
	}
	if measure == "bps" || measure == "pps" || measure == "fps" {
		return "divideDecimal(" + value + "*toDecimal256(" + factor + ",0),toDecimal256(" + duration + ",0),18)"
	}
	return "toDecimal256(" + value + ",18)"
}

func planBucketSQL(prefix, input string, plan flow.QueryPlan) string {
	values := []string{}
	measures, _ := planSQLMeasures(plan)
	for i, measure := range measures {
		values = append(values, planAggregateSQL(measure)+" AS v"+strconv.Itoa(i))
	}
	return prefix + "_buckets AS (SELECT " + planSQLGroup + ",intDiv(toUnixTimestamp64Nano(event_time)-toUnixTimestamp64Nano({from:DateTime64(9,'UTC')}),{width_ns:Int64}) AS bucket_index,least({width_ns:Int64},{window_ns:Int64}-bucket_index*{width_ns:Int64}) AS duration_ns," + strings.Join(values, ",") + " FROM " + input + " GROUP BY " + planSQLGroup + ",bucket_index)"
}

func planStatsSQL(prefix, input string, plan flow.QueryPlan) []string {
	totals := []string{}
	measures, indices := planSQLMeasures(plan)
	for i, measure := range measures {
		totals = append(totals, planAggregateSQL(measure)+" AS t"+strconv.Itoa(i))
	}
	ctes := []string{planBucketSQL(prefix, input, plan)}
	source := prefix + "_buckets"
	wholeTotals := planNeedsWholeTotals(plan)
	if wholeTotals {
		ctes = append(ctes, prefix+"_totals AS (SELECT "+planSQLGroup+","+strings.Join(totals, ",")+" FROM "+input+" GROUP BY "+planSQLGroup+")")
		source += " INNER JOIN " + prefix + "_totals USING (" + planSQLGroup + ")"
	}
	calculations := []string{}
	bucketCount := "toUInt64(intDiv({window_ns:Int64}-1,{width_ns:Int64})+1)"
	for i, metric := range plan.Metrics {
		value := "v" + strconv.Itoa(indices[metric.Measure])
		// Additive bucket sums are the exact underlying whole-window total.
		// Distinct identities may span buckets and require their separate set.
		total := "sum(" + value + ")"
		if wholeTotals {
			total = "any(t" + strconv.Itoa(indices[metric.Measure]) + ")"
		}
		sample := planSampleSQL(metric.Measure, value, "duration_ns")
		expression := ""
		switch metric.Calculation {
		case "bucket_total":
			expression = "toDecimal256(sum(" + value + "),18)"
		case "total":
			expression = "toDecimal256(" + total + ",18)"
		case "avg":
			if metric.Measure == "bps" || metric.Measure == "pps" || metric.Measure == "fps" {
				expression = planSampleSQL(metric.Measure, total, "{window_ns:Int64}")
			} else {
				expression = "divideDecimal(sum(" + value + "),toDecimal256(" + bucketCount + ",0),18)"
			}
		case "max":
			expression = "max(" + sample + ")"
		case "p95", "p99":
			level := "0.95"
			if metric.Calculation == "p99" {
				level = "0.99"
			}
			expression = "arrayReduce('quantileExactWeighted(" + level + ")',arrayConcat(groupArray(" + sample + "),[toDecimal256(0,18)]),arrayConcat(groupArray(toUInt64(1)),[toUInt64(" + bucketCount + "-count())]))"
		default:
			expression = "toDecimal256(throwIf(1,'invalid metric calculation'),18)"
		}
		calculations = append(calculations, expression+" AS m"+strconv.Itoa(i))
	}
	ctes = append(ctes, prefix+"_stats AS (SELECT "+planSQLGroup+","+strings.Join(calculations, ",")+" FROM "+source+" GROUP BY "+planSQLGroup+")")
	return ctes
}

func planNeedsWholeTotals(plan flow.QueryPlan) bool {
	for _, metric := range plan.Metrics {
		if metric.Calculation != "total" {
			continue
		}
		switch metric.Measure {
		case "bytes", "packets", "flows", "bps", "pps", "fps":
			// Disjoint time buckets partition these exact additive measures.
		default:
			return true
		}
	}
	return false
}

func planSQLMeasures(plan flow.QueryPlan) ([]string, map[string]int) {
	measures := []string{}
	indices := map[string]int{}
	for _, metric := range plan.Metrics {
		if _, exists := indices[metric.Measure]; !exists {
			indices[metric.Measure] = len(measures)
			measures = append(measures, metric.Measure)
		}
	}
	return measures, indices
}

func planInterfaceRoleJoinsSQL(from string, plan flow.QueryPlan) string {
	if planUsesInterfaceRoles(plan) {
		for _, side := range []string{"in", "out"} {
			alias := side + "_roles"
			from += " ANY LEFT JOIN interface_role_lookup AS " + alias + " ON " + alias + ".role_tenant=tenant_id AND toIPv6OrNull(" + alias + ".role_exporter)=toIPv6OrNull(if(position(exporter,'%')=0,exporter,'')) AND " + alias + ".role_protocol=protocol AND " + alias + ".role_domain=obs_domain AND " + alias + ".role_index=" + side + "_if"
		}
	}
	return from
}

func planInterfaceNamesJSON(names map[string]map[uint32]string) string {
	tuples := []any{}
	exporters := make([]string, 0, len(names))
	for exporter := range names {
		exporters = append(exporters, exporter)
	}
	sort.Strings(exporters)
	for _, exporter := range exporters {
		indices := make([]int, 0, len(names[exporter]))
		for index := range names[exporter] {
			indices = append(indices, int(index))
		}
		sort.Ints(indices)
		for _, index := range indices {
			tuples = append(tuples, []any{exporter, uint32(index), names[exporter][uint32(index)]})
		}
	}
	encoded, _ := json.Marshal(tuples)
	return string(encoded)
}
