// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import "github.com/ctlplne/probectl/internal/flow"

func (p *questionPlanParser) displayStart() bool {
	for _, phrase := range []string{"table", "bar", "line", "timeline", "matrix", "stacked area", "stacked columns", "percent area", "percentage area", "horizon", "total overlay", "no total overlay", "synchronize axes", "independent axes", "one chart per series", "one chart with all series", "charts per row", "chart height", "horizon scale", "percent basis", "log scale", "logarithmic scale", "linear scale"} {
		if p.at(phrase) {
			return true
		}
	}
	return false
}

func (p *questionPlanParser) display() error {
	if p.proposal.Display == nil {
		p.proposal.Display = &flow.QueryViewDisplay{}
	}
	display, plan := p.proposal.Display, p.proposal.Plan
	switch {
	case p.accept("table"):
		plan.View = "table"
	case p.accept("bar chart") || p.accept("bar"):
		plan.View = "bar"
	case p.accept("line chart") || p.accept("line"):
		plan.View = "line"
		display.TimeStyle = "line"
	case p.accept("timeline"):
		plan.View = "timeline"
	case p.accept("matrix"):
		plan.View = "matrix"
		p.accept("view")
	case p.accept("stacked area"):
		plan.View = "line"
		display.TimeStyle = "stacked_area"
	case p.accept("stacked columns"):
		plan.View = "line"
		display.TimeStyle = "stacked_columns"
	case p.accept("percent area") || p.accept("percentage area"):
		plan.View = "line"
		display.TimeStyle = "percent_area"
	case p.accept("horizon scale"):
		if p.accept("per lane") {
			display.HorizonScale = "lane"
			return nil
		}
		value, err := p.literal()
		display.HorizonScale = value
		return err
	case p.accept("horizon"):
		plan.View = "line"
		display.TimeStyle = "horizon"
	case p.accept("total overlay"):
		display.TotalOverlay = true
		return nil
	case p.accept("no total overlay"):
		display.TotalOverlay = false
		return nil
	case p.accept("synchronize axes"):
		display.SyncAxes = true
		return nil
	case p.accept("independent axes"):
		display.SyncAxes = false
		return nil
	case p.accept("one chart per series"):
		display.OneChartPerSeries = true
		return nil
	case p.accept("one chart with all series"):
		display.OneChartPerSeries = false
		return nil
	case p.accept("linear scale"):
		display.LogMetrics = nil
		return nil
	case p.accept("log scale") || p.accept("logarithmic scale"):
		if !p.accept("for") {
			return errQuestionClause
		}
		var keys []string
		for {
			metric, err := p.metric()
			if err != nil {
				return err
			}
			keys = append(keys, metric.Measure+":"+metric.Calculation)
			before := p.position
			if !p.accept(",") && !p.accept("and") {
				break
			}
			if !p.metricStart() {
				p.position = before
				break
			}
		}
		display.LogMetrics = keys
		return nil
	case p.accept("charts per row"):
		value, err := p.positiveInteger()
		display.ChartsPerRow = value
		return err
	case p.accept("chart height"):
		value, err := p.literal()
		display.ChartHeight = value
		return err
	case p.accept("percent basis"):
		value, err := p.literal()
		display.PercentBasis = value
		return err
	default:
		return errQuestionClause
	}
	p.viewSet = true
	if plan.View != "matrix" {
		plan.MatrixWith = nil
	}
	return nil
}
