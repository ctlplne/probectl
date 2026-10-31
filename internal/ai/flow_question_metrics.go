// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
)

func (p *questionPlanParser) metricStart() bool {
	if p.at("primary") || p.at("secondary") || p.at("additional") {
		return true
	}
	_, count, _ := p.vocabulary.metrics.match(p.tokens, p.position)
	if count > 0 {
		return true
	}
	_, count, _ = p.vocabulary.calculations.match(p.tokens, p.position)
	return count > 0
}

func (p *questionPlanParser) metrics(add bool) error {
	if !p.metricsSet && !add {
		p.proposal.Plan.Metrics = nil
	}
	p.metricsSet = true
	for {
		metric, err := p.metric()
		if err != nil {
			return err
		}
		p.proposal.Plan.Metrics = append(p.proposal.Plan.Metrics, metric)
		before := p.position
		if !p.accept(",") && !p.accept("and") {
			return nil
		}
		if !p.metricStart() {
			p.position = before
			return nil
		}
	}
}

func (p *questionPlanParser) metric() (flow.QueryMetric, error) {
	role := ""
	for _, candidate := range []string{"primary", "secondary", "additional"} {
		if p.accept(candidate) {
			role = candidate
			break
		}
	}
	calculation, count, ambiguous := p.vocabulary.calculations.match(p.tokens, p.position)
	if ambiguous {
		return flow.QueryMetric{}, errQuestionClause
	}
	if count > 0 {
		p.position += count
		p.accept("of")
	}
	wrapped := p.accept("(")
	measure, count, ambiguous := p.vocabulary.metrics.match(p.tokens, p.position)
	if count == 0 || ambiguous {
		return flow.QueryMetric{}, errQuestionClause
	}
	p.position += count
	if wrapped && !p.accept(")") {
		return flow.QueryMetric{}, errQuestionClause
	}
	if calculation == "" {
		value, count, ambiguous := p.vocabulary.calculations.match(p.tokens, p.position)
		if ambiguous {
			return flow.QueryMetric{}, errQuestionClause
		}
		if count > 0 {
			calculation = value
			p.position += count
		}
	}
	if calculation == "" {
		calculation = "total"
		for _, definition := range flow.QueryMetricDefinitions() {
			if definition.Name == measure && strings.HasSuffix(definition.Unit, "/s") {
				calculation = "avg"
			}
		}
	}
	if p.accept("as") {
		matched := false
		for _, candidate := range []string{"primary", "secondary", "additional"} {
			if p.accept(candidate) {
				if role != "" && role != candidate {
					return flow.QueryMetric{}, errQuestionClause
				}
				role = candidate
				matched = true
				break
			}
		}
		if !matched {
			p.position--
		} // leave a view's as-clause to the outer parser
	}
	if role == "" {
		if len(p.proposal.Plan.Metrics) == 0 {
			role = "primary"
		} else {
			plotted := 0
			for _, existing := range p.proposal.Plan.Metrics {
				if existing.Role != "additional" {
					plotted++
				}
			}
			role = "additional"
			if plotted < 4 {
				role = "secondary"
			}
		}
	}
	return flow.QueryMetric{Measure: measure, Calculation: calculation, Role: role}, nil
}
