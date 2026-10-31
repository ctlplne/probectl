// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

var errQuestionAction = errors.New("question requests an unsupported action")

// BuiltinFlowQuestionPlanner is an offline, registry-derived compositional
// planner. It has no backend, principal, source credentials or network client.
type BuiltinFlowQuestionPlanner struct {
	budget     FlowQuestionBudget
	vocabulary flowQuestionVocabulary
}

var _ FlowQuestionPlanner = (*BuiltinFlowQuestionPlanner)(nil)

func NewBuiltinFlowQuestionPlanner(budget FlowQuestionBudget) (*BuiltinFlowQuestionPlanner, error) {
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	return &BuiltinFlowQuestionPlanner{budget: budget, vocabulary: newFlowQuestionVocabulary()}, nil
}

type questionPlanParser struct {
	questionCursor
	input                                 FlowQuestionInput
	proposal                              FlowQuestionProposal
	location                              *time.Location
	metricsSet, rowsSet, pageSet, viewSet bool
	clauses                               int
}

func (p *BuiltinFlowQuestionPlanner) Plan(ctx context.Context, input FlowQuestionInput) (FlowQuestionProposal, error) {
	if p == nil || p.budget.Validate() != nil {
		return FlowQuestionProposal{}, ErrFlowQuestionBudget
	}
	if input.Now.IsZero() {
		return FlowQuestionProposal{}, ErrFlowQuestionInput
	}
	tokens, err := lexFlowQuestion(ctx, input.Question, p.budget)
	if err != nil {
		return FlowQuestionProposal{}, err
	}
	location, err := questionLocation(input.TimeZone)
	if err != nil {
		return questionClarification(), nil
	}
	parser := questionPlanParser{questionCursor: questionCursor{ctx: ctx, tokens: tokens, vocabulary: p.vocabulary, budget: p.budget, questionTail: true}, input: input, location: location, proposal: FlowQuestionProposal{Status: FlowQuestionReady, Plan: &flow.QueryPlan{}}}
	if input.Parent != nil {
		parent, err := NormalizeFlowQuestionProposal(*input.Parent, input.Now)
		if err != nil || parent.Status != FlowQuestionReady {
			return FlowQuestionProposal{}, ErrFlowQuestionPlan
		}
		parser.proposal = parent
		parser.proposal.Assumptions = []string{"Unchanged query settings come from the explicitly selected parent message."}
	}
	parser.readPrefix()
	for parser.position < len(tokens) {
		if err := ctx.Err(); err != nil {
			return FlowQuestionProposal{}, err
		}
		before := parser.position
		if parser.accept(";") {
			continue
		}
		if parser.accept("and") || parser.accept("then") {
			if parser.position == len(tokens) || (parser.clauses == 0 && input.Parent == nil) {
				return questionClarification(), nil
			}
			continue
		}
		if parser.accept("?") {
			if parser.position != len(tokens) {
				return questionClarification(), nil
			}
			break
		}
		matched, err := parser.clause()
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrFlowQuestionBudget) {
				return FlowQuestionProposal{}, err
			}
			if errors.Is(err, errQuestionAction) {
				return FlowQuestionProposal{Status: FlowQuestionRefused, Guidance: "Only read-only flow questions can be planned here; administrative actions and SQL are not executed."}, nil
			}
			return questionClarification(), nil
		}
		if !matched || parser.position <= before {
			return questionClarification(), nil
		}
		parser.clauses++
	}
	if parser.clauses == 0 {
		return questionClarification(), nil
	}
	plan := parser.proposal.Plan
	if plan.From.IsZero() && plan.To.IsZero() {
		parser.proposal.Assumptions = append(parser.proposal.Assumptions, "Time defaults to the preceding hour.")
	}
	if len(plan.Metrics) == 0 {
		parser.proposal.Assumptions = append(parser.proposal.Assumptions, "Metric defaults to average bits per second.")
	}
	if plan.View == "" {
		plan.View = "table"
	}
	if parser.viewSet && plan.View != "table" && !parser.rowsSet && plan.RowLimit > flow.MaxPlanChartRows {
		plan.RowLimit = flow.MaxPlanChartRows
	}
	if !parser.pageSet && plan.RowLimit > 0 && plan.PageSize > plan.RowLimit {
		plan.PageSize = plan.RowLimit
	}
	parser.proposal.Guidance = "Inspect the validated native flow plan before interpreting its results."
	result, err := NormalizeFlowQuestionProposal(parser.proposal, input.Now)
	if err != nil {
		return questionClarification(), nil
	}
	if err := ctx.Err(); err != nil {
		return FlowQuestionProposal{}, err
	}
	return result, nil
}

func questionClarification() FlowQuestionProposal {
	return FlowQuestionProposal{Status: FlowQuestionClarify, Guidance: "Specify registered metrics, grouping fields, typed filters, a time window or a supported view; unknown or conflicting clauses are not executed."}
}

func (p *questionPlanParser) readPrefix() {
	for {
		matched := false
		for _, phrase := range []string{"please", "can you", "could you", "would you", "show me", "give me", "tell me", "what about", "what are", "what is", "how much", "how many", "show", "list", "find", "display", "plot", "graph", "now", "instead", "the"} {
			if p.accept(phrase) {
				matched = true
				break
			}
		}
		if !matched {
			return
		}
	}
}

func (p *questionPlanParser) clause() (bool, error) {
	for _, clause := range []func() (bool, error){p.filterClause, p.periodClause, p.queryOptionsClause, p.outputClause} {
		handled, err := clause()
		if handled || err != nil {
			return handled, err
		}
	}
	return false, nil
}

func (p *questionPlanParser) filterClause() (bool, error) {
	plan := p.proposal.Plan
	switch {
	case p.accept("traffic") || p.accept("network traffic"):
		return true, nil
	case p.accept("same as before") || p.accept("same query") || p.accept("again"):
		if p.input.Parent == nil {
			return true, errQuestionClause
		}
		return true, nil
	case p.accept("clear filters") || p.accept("without filters") || p.accept("remove filters"):
		plan.Filter = nil
		return true, nil
	case p.accept("replace filter with") || p.accept("only where"):
		filter, err := p.filter()
		if err == nil {
			plan.Filter = filter
		}
		return true, err
	case p.accept("where") || p.accept("filter by") || p.accept("filter"):
		filter, err := p.filter()
		if err != nil {
			return true, err
		}
		if plan.Filter == nil {
			plan.Filter = filter
		} else {
			merged := packQuestionGroup(combineQuestionGroups("all", *plan.Filter, *filter))
			plan.Filter = &merged
		}
		return true, nil
	case p.accept("add grouping") || p.accept("also group by"):
		fields, err := p.dimensions()
		plan.GroupBy = append(plan.GroupBy, fields...)
		return true, err
	case p.accept("group by") || p.accept("grouped by") || p.accept("split by") || p.accept("grouping by") || p.accept("by"):
		fields, err := p.dimensions()
		plan.GroupBy = fields
		return true, err
	case p.accept("matrix with") || p.accept("columns by") || p.accept("against"):
		fields, err := p.dimensions()
		plan.MatrixWith, plan.View = fields, "matrix"
		p.viewSet = true
		return true, err
	}
	return false, nil
}

func (p *questionPlanParser) periodClause() (bool, error) {
	plan := p.proposal.Plan
	switch {
	case p.accept("without comparison") || p.accept("clear comparison"):
		p.proposal.Comparison = nil
		return true, nil
	case p.accept("compare") || p.accept("compared with") || p.accept("versus"):
		p.accept("with")
		p.accept("to")
		p.accept("the")
		if p.accept("previous period") || p.accept("preceding period") || p.accept("previous window") {
			p.proposal.Comparison = &flow.QueryViewComparison{Mode: "preceding"}
			return true, nil
		}
		period, err := p.period(p.input.Now, p.location)
		if err == nil {
			p.proposal.Comparison = &flow.QueryViewComparison{Mode: "absolute", From: period.From, To: period.To}
		}
		return true, err
	case p.accept("for") || p.accept("over") || p.accept("during"):
		p.accept("the")
		period, err := p.period(p.input.Now, p.location)
		if err == nil {
			plan.From, plan.To = period.From, period.To
		}
		return true, err
	case p.at("from") || p.at("between") || p.at("last") || p.at("past") || p.at("previous") || p.at("today") || p.at("yesterday") || p.at("this"):
		period, err := p.period(p.input.Now, p.location)
		if err == nil {
			plan.From, plan.To = period.From, period.To
		}
		return true, err
	case p.accept("every") || p.accept("bucket") || p.accept("buckets of") || p.accept("per"):
		duration, err := p.duration()
		if err != nil || duration%time.Second != 0 {
			return true, errQuestionClause
		}
		plan.BucketSeconds = int(duration / time.Second)
		return true, nil
	}
	return false, nil
}

func (p *questionPlanParser) queryOptionsClause() (bool, error) {
	plan := p.proposal.Plan
	switch {
	case p.accept("using") || p.accept("source"):
		if p.accept("raw") {
			plan.DataSeries = "raw"
			return true, nil
		}
		if p.accept("rollups") || p.accept("rollup") {
			plan.DataSeries = "rollup"
			return true, nil
		}
		if p.accept("auto") {
			plan.DataSeries = "auto"
			return true, nil
		}
		if p.accept("saved filter") {
			id, err := p.literal()
			if err != nil {
				return true, err
			}
			filter := flow.QueryFilterGroup{Match: "all", Mode: "include", Saved: []flow.QuerySavedFilterRef{{ID: id, Mode: "include"}}}
			if plan.Filter == nil {
				plan.Filter = &filter
			} else {
				merged := combineQuestionGroups("all", *plan.Filter, filter)
				plan.Filter = &merged
			}
			return true, nil
		}
		return true, errQuestionClause
	case p.accept("all rows"):
		plan.RowLimit = flow.MaxPlanTableRows
		p.rowsSet = true
		return true, nil
	case p.accept("all series"):
		plan.SeriesDepth = flow.MaxPlanChartSeries
		return true, nil
	case p.accept("top"):
		value, err := p.positiveInteger()
		if p.accept("series") {
			plan.SeriesDepth = value
		} else {
			plan.RowLimit = value
			p.rowsSet = true
			p.accept("rows")
		}
		return true, err
	case p.accept("limit") || p.accept("rows"):
		value, err := p.positiveInteger()
		plan.RowLimit = value
		p.rowsSet = true
		p.accept("rows")
		return true, err
	case p.accept("page size"):
		value, err := p.positiveInteger()
		plan.PageSize = value
		p.pageSet = true
		return true, err
	case p.accept("series depth") || p.accept("series"):
		value, err := p.positiveInteger()
		plan.SeriesDepth = value
		return true, err
	case p.accept("matrix depth"):
		value, err := p.positiveInteger()
		plan.MatrixDepth = value
		return true, err
	case p.accept("ipv4 prefix"):
		value, err := p.prefixLength()
		plan.IPv4PrefixLength = &value
		return true, err
	case p.accept("ipv6 prefix"):
		value, err := p.prefixLength()
		plan.IPv6PrefixLength = &value
		return true, err
	}
	return false, nil
}

func (p *questionPlanParser) outputClause() (bool, error) {
	plan := p.proposal.Plan
	switch {
	case p.accept("add metrics") || p.accept("add metric") || p.accept("also") || p.accept("add"):
		return true, p.metrics(true)
	case p.accept("metrics") || p.accept("metric") || p.accept("with metrics") || p.accept("with metric"):
		return true, p.metrics(false)
	case p.accept("as") || p.accept("view") || p.accept("in"):
		p.accept("a")
		p.accept("an")
		return true, p.display()
	}
	if p.displayStart() {
		return true, p.display()
	}
	if p.metricStart() {
		return true, p.metrics(false)
	}
	if p.input.Parent != nil {
		if _, count, ambiguous := p.vocabulary.fields.match(p.tokens, p.position); count > 0 && !ambiguous {
			fields, err := p.dimensions()
			plan.GroupBy = fields
			return true, err
		}
	}
	if questionActionWords[p.peekWord()] {
		return true, errQuestionAction
	}
	return false, nil
}

func (p *questionPlanParser) dimensions() ([]string, error) {
	var fields []string
	for {
		field, count, ambiguous := p.vocabulary.fields.match(p.tokens, p.position)
		if count == 0 || ambiguous {
			return nil, errQuestionClause
		}
		p.position += count
		fields = append(fields, field)
		if len(fields) > flow.MaxPlanDimensions {
			return nil, errQuestionClause
		}
		before := p.position
		if !p.accept(",") && !p.accept("and") {
			break
		}
		if _, count, _ := p.vocabulary.fields.match(p.tokens, p.position); count == 0 {
			p.position = before
			break
		}
	}
	return fields, nil
}

var questionActionWords = map[string]bool{"select": true, "drop": true, "delete": true, "insert": true, "update": true, "alter": true, "truncate": true, "grant": true, "revoke": true, "shutdown": true, "restart": true, "disable": true, "enable": true, "block": true, "unblock": true, "execute": true, "exec": true, "apply": true, "approve": true, "remediate": true, "change": true}
