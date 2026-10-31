// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"slices"
	"strings"
)

// QueryMetric defines a measure/calculation and its chart/table role. Primary
// sorts the result; three secondary chart metrics are permitted. Additional
// table metrics are bounded by the registry rather than a smaller display cap.
type QueryMetric struct {
	Measure     string `json:"measure"`
	Calculation string `json:"calculation"`
	Role        string `json:"role"`
}

// QueryMetricDefinition is shared by schema, planner and all user transports.
type QueryMetricDefinition struct {
	Name             string            `json:"name"`
	Unit             string            `json:"unit"`
	DistinctField    string            `json:"distinct_field,omitempty"`
	Calculations     []string          `json:"calculations"`
	CalculationUnits map[string]string `json:"calculation_units"`
}

// QueryMetricDefinitions publishes all D102 metric families and statistics.
func QueryMetricDefinitions() []QueryMetricDefinition {
	definitions := []QueryMetricDefinition{
		{Name: "bps", Unit: "bit/s"}, {Name: "pps", Unit: "packet/s"}, {Name: "fps", Unit: "flow/s"},
		{Name: "bytes", Unit: "byte"}, {Name: "packets", Unit: "packet"}, {Name: "flows", Unit: "flow"},
	}
	for _, direction := range []string{"src", "dst"} {
		for _, dimension := range []struct{ suffix, field, unit string }{{"", "addr", "IP"}, {"_port", "port", "port"}, {"_asn", "asn", "ASN"}, {"_country", "country", "country"}} {
			definitions = append(definitions, QueryMetricDefinition{Name: "unique_" + direction + dimension.suffix, Unit: dimension.unit, DistinctField: direction + "_" + dimension.field})
		}
	}
	for i := range definitions {
		definitions[i].Calculations = []string{"avg", "p95", "p99", "max", "total"}
		definitions[i].CalculationUnits = map[string]string{}
		for _, calculation := range definitions[i].Calculations {
			definitions[i].CalculationUnits[calculation] = definitions[i].Unit
		}
		switch definitions[i].Name {
		case "bps":
			definitions[i].CalculationUnits["total"] = "byte"
		case "pps":
			definitions[i].CalculationUnits["total"] = "packet"
		case "fps":
			definitions[i].CalculationUnits["total"] = "flow"
		}
		if definitions[i].DistinctField != "" {
			definitions[i].Calculations = append(definitions[i].Calculations, "bucket_total")
			definitions[i].CalculationUnits["bucket_total"] = definitions[i].Unit + "-observations"
		}
	}
	return definitions
}

// NormalizeQueryMetrics ensures one primary, at most three secondary chart
// metrics and no repeated measure/calculation. It never accepts expressions.
func NormalizeQueryMetrics(input []QueryMetric) ([]QueryMetric, error) {
	definitions := QueryMetricDefinitions()
	if len(input) == 0 {
		return []QueryMetric{{Measure: "bps", Calculation: "avg", Role: "primary"}}, nil
	}
	combinations := 0
	for _, definition := range definitions {
		combinations += len(definition.Calculations)
	}
	if len(input) > combinations {
		return nil, errors.New("flow metric selections exceed the registered combinations")
	}
	out := make([]QueryMetric, 0, len(input))
	seen := map[string]bool{}
	primary, secondary := 0, 0
	for i, item := range input {
		item.Measure = strings.ToLower(strings.TrimSpace(item.Measure))
		item.Calculation = strings.ToLower(strings.TrimSpace(item.Calculation))
		item.Role = strings.ToLower(strings.TrimSpace(item.Role))
		if item.Calculation == "" {
			item.Calculation = "avg"
		}
		if item.Role == "" {
			if i == 0 {
				item.Role = "primary"
			} else {
				item.Role = "additional"
			}
		}
		definition, ok := QueryMetricDefinition{}, false
		for _, candidate := range definitions {
			if candidate.Name == item.Measure {
				definition = candidate
				ok = true
				break
			}
		}
		if !ok || !slices.Contains(definition.Calculations, item.Calculation) {
			return nil, errors.New("unsupported flow metric or calculation")
		}
		key := item.Measure + ":" + item.Calculation
		if seen[key] {
			return nil, errors.New("duplicate flow metric calculation")
		}
		seen[key] = true
		switch item.Role {
		case "primary":
			primary++
		case "secondary":
			secondary++
		case "additional":
		default:
			return nil, errors.New("flow metric role must be primary, secondary or additional")
		}
		out = append(out, item)
	}
	if primary != 1 || secondary > 3 {
		return nil, errors.New("flow charts require one primary metric and at most three secondary metrics")
	}
	return out, nil
}
