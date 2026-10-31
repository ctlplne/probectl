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

const planCostSettings = "SETTINGS max_execution_time=5,timeout_overflow_mode='throw',max_bytes_to_read=268435456,max_rows_to_read=5000000,read_overflow_mode='throw',max_rows_to_group_by=500000,group_by_overflow_mode='throw',max_result_rows=500000,result_overflow_mode='throw',max_memory_usage=536870912,max_threads=2"

const planSQLColumns = "event_time,bytes_scaled,packets_scaled,canonical_src,canonical_dst,src_port,dst_port,src_asn,dst_asn,src_country,dst_country"
const planSQLGroup = "g,c,o,p"

// No public value contributes SQL structure: dimensions/operators/metrics all
// come from the shared registry. Literal values, including metadata, are bound.
func planSQL(plan flow.QueryPlan, table string, names map[string]map[uint32]string, membership ...[][]string) (string, chParams, error) {
	return planSQLWithBudget(DefaultExplorerBudget(), plan, table, names, membership...)
}

func planSQLWithBudget(budget ExplorerBudget, plan flow.QueryPlan, table string, names map[string]map[uint32]string, membership ...[][]string) (string, chParams, error) {
	settings, err := budget.settings()
	if err != nil {
		return "", nil, err
	}
	plan, err = flow.NormalizeQueryPlan(plan, time.Now())
	if err != nil {
		return "", nil, err
	}
	if !explorerTablePattern.MatchString(table) {
		return "", nil, errors.New("invalid flow query table")
	}
	params := chParams{"from": plan.From.Format("2006-01-02 15:04:05.999999999"), "to": plan.To.Format("2006-01-02 15:04:05.999999999"), "prefix4": strconv.Itoa(*plan.IPv4PrefixLength), "prefix6": strconv.Itoa(*plan.IPv6PrefixLength), "width_ns": strconv.FormatInt(int64(time.Duration(plan.BucketSeconds)*time.Second), 10), "window_ns": strconv.FormatInt(int64(plan.To.Sub(plan.From)), 10)}
	params["detail_limit"] = strconv.Itoa(plan.RowLimit)
	params["series_limit"] = strconv.Itoa(plan.SeriesDepth)
	params["matrix_depth"] = strconv.Itoa(plan.MatrixDepth)

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
	params["interfaces"] = string(encoded)
	filter, err := explorerFilterSQL(plan.Filter, params)
	if err != nil {
		return "", nil, err
	}
	key := func(fields []string) string {
		parts := []string{}
		for _, name := range fields {
			field, _ := flow.LookupQueryField(name)
			parts = append(parts, explorerGroupExpr(field))
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
	ctes := []string{"filtered AS (SELECT " + key(plan.GroupBy) + " AS g," + key(plan.MatrixWith) + " AS c," + eventTime + " AS event_time,bytes_scaled,packets_scaled," + explorerAddressExpr("src_addr") + " AS canonical_src," + explorerAddressExpr("dst_addr") + " AS canonical_dst,src_port,dst_port,src_asn,dst_asn,src_country,dst_country FROM " + table + " FINAL WHERE tenant_id={tenant:String} AND " + eventTime + ">={from:DateTime64(9,'UTC')} AND " + eventTime + "<{to:DateTime64(9,'UTC')} AND (" + filter + "))"}
	empty := "CAST([],'Array(String)')"
	input := func(name, g, c, o, p, condition string) {
		sql := name + " AS (SELECT " + g + " AS g," + c + " AS c,toUInt8(" + o + ") AS o,toUInt8(" + p + ") AS p," + planSQLColumns + " FROM filtered"
		if condition != "" {
			sql += " WHERE " + condition
		}
		ctes = append(ctes, sql+")")
	}
	input("full_input", "filtered.g", empty, "0", "0", "")
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
		selected, err = normalizePlanGroups(membership[0], plan, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) >= 2 {
		selectedColumns, err = normalizePlanColumns(membership[1], plan, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) >= 3 {
		selectedChart, err = normalizePlanChartGroups(membership[2], plan, budget)
		if err != nil {
			return "", nil, err
		}
	}
	if len(membership) == 4 {
		selectedMatrixRows, err = normalizePlanMatrixRows(membership[3], plan, budget)
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
	outputs = append(outputs, "SELECT 'counts' AS kind,"+empty+" AS g,"+empty+" AS c,toUInt8(0) AS o,toUInt8(0) AS p,toInt64(-1) AS bi,'0' AS duration,["+strings.Join(zeroMetrics, ",")+"] AS metrics,toUInt64(uniqExact(filtered.g)) AS total_groups,if(count()=0,'',toString(min(event_time),'UTC')) AS oldest_input FROM filtered")
	input("other_input", empty, empty, "1", "0", "filtered.g NOT IN (SELECT g FROM ranked WHERE rk<={detail_limit:UInt64})")
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
		input("chart_other_input", empty, empty, "1", "0", "filtered.g NOT IN ("+chartTop+")")
		ctes = append(ctes, planStatsSQL("chart_other", "chart_other_input", plan)...)
		outputs = append(outputs, output("chart_other", "chart_other_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("chart_input", "if(filtered.g IN ("+chartTop+"),filtered.g,"+empty+")", empty, "filtered.g NOT IN ("+chartTop+")", "0", "")
		ctes = append(ctes, planBucketSQL("chart", "chart_input", plan))
		ctes = append(ctes, pointProjection("chart"))
		outputs = append(outputs, output("point", "chart_points", "", "bucket_index", "toString(duration_ns)", "toUInt64(0)"))
	}
	if plan.View == "matrix" {
		rowTop := "SELECT g FROM " + globalRank + " WHERE rk<={matrix_depth:UInt64}"
		if selectedMatrixRows != nil {
			encoded, err := json.Marshal(selectedMatrixRows)
			if err != nil {
				return "", nil, err
			}
			params["selected_matrix_rows"] = string(encoded)
			rowTop = "SELECT arrayJoin(JSONExtract({selected_matrix_rows:String},'Array(Array(String))'))"
		}
		outputs = append(outputs, output("matrix_row", "full_stats", "g IN ("+rowTop+")", "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("column_input", "filtered.c", empty, "0", "0", "filtered.g IN ("+rowTop+")")
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
		columnTop := "SELECT g FROM column_ranked WHERE rk<={matrix_depth:UInt64}"
		if selectedColumns != nil {
			// Preserve pinned membership even when a column occurs only in
			// this period's Other rows and has no conditioned statistics.
			columnTop = "SELECT arrayJoin(JSONExtract({selected_columns:String},'Array(Array(String))'))"
		}
		outputs = append(outputs, output("matrix_column", "column_ranked", "rk<={matrix_depth:UInt64}", "toInt64(-1)", "'0'", "toUInt64(0)"))
		input("matrix_input", "if(filtered.g IN ("+rowTop+"),filtered.g,"+empty+")", "if(filtered.c IN ("+columnTop+"),filtered.c,"+empty+")", "filtered.g NOT IN ("+rowTop+")", "filtered.c NOT IN ("+columnTop+")", "")
		ctes = append(ctes, planStatsSQL("matrix", "matrix_input", plan)...)
		outputs = append(outputs, output("matrix", "matrix_stats", "", "toInt64(-1)", "'0'", "toUInt64(0)"))
	}
	// Throw on every cost limit: no silently truncated or approximate response.
	sql := "WITH " + strings.Join(ctes, ",\n") + "\n" + strings.Join(outputs, "\nUNION ALL\n") + "\n" + settings
	return sql, params, nil
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
	ctes := []string{planBucketSQL(prefix, input, plan), prefix + "_totals AS (SELECT " + planSQLGroup + "," + strings.Join(totals, ",") + " FROM " + input + " GROUP BY " + planSQLGroup + ")"}
	calculations := []string{}
	bucketCount := "toUInt64(intDiv({window_ns:Int64}-1,{width_ns:Int64})+1)"
	for i, metric := range plan.Metrics {
		value := "v" + strconv.Itoa(indices[metric.Measure])
		total := "any(t" + strconv.Itoa(indices[metric.Measure]) + ")"
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
	ctes = append(ctes, prefix+"_stats AS (SELECT "+planSQLGroup+","+strings.Join(calculations, ",")+" FROM "+prefix+"_buckets INNER JOIN "+prefix+"_totals USING ("+planSQLGroup+") GROUP BY "+planSQLGroup+")")
	return ctes
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
