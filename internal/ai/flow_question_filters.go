// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
)

var errQuestionClause = errors.New("clarify the requested field, operator, values or clause structure")

type questionCursor struct {
	ctx          context.Context
	tokens       []questionToken
	position     int
	vocabulary   flowQuestionVocabulary
	budget       FlowQuestionBudget
	conditions   int
	questionTail bool // Only the outer question may resume after a complete filter.
}

func (c *questionCursor) at(phrase string) bool {
	words := strings.Fields(phrase)
	if c.position+len(words) > len(c.tokens) {
		return false
	}
	for i, word := range words {
		if c.tokens[c.position+i].quoted || c.tokens[c.position+i].lower != word {
			return false
		}
	}
	return true
}

func (c *questionCursor) accept(phrase string) bool {
	if !c.at(phrase) {
		return false
	}
	c.position += len(strings.Fields(phrase))
	return true
}

func (c *questionCursor) literal() (string, error) {
	if err := c.ctx.Err(); err != nil {
		return "", err
	}
	if c.position >= len(c.tokens) {
		return "", errQuestionClause
	}
	token := c.tokens[c.position]
	if !token.quoted && (strings.ContainsAny(token.text, "(),;?=<>!&|") || token.lower == "and" || token.lower == "or") {
		return "", errQuestionClause
	}
	c.position++
	return token.text, nil
}

func (c *questionCursor) filter() (*flow.QueryFilterGroup, error) {
	group, err := c.filterOr(0, "all")
	if err != nil {
		return nil, err
	}
	group = packQuestionGroup(group)
	result, err := flow.NormalizeQueryFilterGroup(&group)
	if err != nil {
		return nil, errQuestionClause
	}
	return result, nil
}

func (c *questionCursor) filterOr(depth int, commaMatch string) (flow.QueryFilterGroup, error) {
	left, err := c.filterAnd(depth, commaMatch)
	if err != nil {
		return flow.QueryFilterGroup{}, err
	}
	for c.accept("or") || c.accept("||") || (commaMatch == "any" && c.accept(",")) {
		right, err := c.filterAnd(depth, commaMatch)
		if err != nil {
			return flow.QueryFilterGroup{}, err
		}
		left = combineQuestionGroups("any", left, right)
	}
	return left, nil
}

func (c *questionCursor) filterAnd(depth int, commaMatch string) (flow.QueryFilterGroup, error) {
	left, err := c.filterAtom(depth)
	if err != nil {
		return flow.QueryFilterGroup{}, err
	}
	for {
		before := c.position
		if !c.accept("and") && !c.accept("&&") && (commaMatch != "all" || !c.accept(",")) {
			break
		}
		if depth == 0 && c.questionTail && c.tokens[before].lower == "and" && c.atQuestionTail() {
			c.position = before
			break
		}
		right, err := c.filterAtom(depth)
		if err != nil {
			return flow.QueryFilterGroup{}, err
		}
		left = combineQuestionGroups("all", left, right)
	}
	return left, nil
}

// A top-level conjunction can join a filter to another explicitly recognized
// query clause. Inside parentheses it always joins predicates; an unknown or
// incomplete suffix still fails the entire question rather than dropping it.
func (c *questionCursor) atQuestionTail() bool {
	if _, count, _ := c.vocabulary.fields.match(c.tokens, c.position); count > 0 {
		return false
	}
	for _, phrase := range []string{"group by", "grouped by", "split by", "grouping by", "by", "add grouping", "also group by", "matrix with", "columns by", "against", "compare", "compared with", "versus", "for", "over", "during", "from", "between", "last", "past", "previous", "today", "yesterday", "this", "every", "bucket", "buckets of", "per", "using", "source", "all rows", "all series", "top", "limit", "rows", "page size", "series", "matrix depth", "ipv4 prefix", "ipv6 prefix", "add", "also", "metrics", "metric", "with metrics", "with metric", "as", "view", "in", "clear filters", "without filters", "remove filters", "without comparison", "clear comparison"} {
		if c.at(phrase) {
			return true
		}
	}
	return false
}

func (c *questionCursor) filterAtom(depth int) (flow.QueryFilterGroup, error) {
	if err := c.ctx.Err(); err != nil {
		return flow.QueryFilterGroup{}, err
	}
	if depth >= c.budget.Nesting {
		return flow.QueryFilterGroup{}, ErrFlowQuestionBudget
	}
	if c.accept("not") || c.accept("exclude") {
		group, err := c.filterAtom(depth + 1)
		if err != nil {
			return flow.QueryFilterGroup{}, err
		}
		if group.Mode == "exclude" {
			group.Mode = "include"
		} else {
			group.Mode = "exclude"
		}
		return group, nil
	}
	if c.accept("include") {
		return c.filterAtom(depth + 1)
	}
	match := "all"
	explicit := false
	if c.accept("all of") {
		explicit = true
	} else if c.accept("any of") {
		match, explicit = "any", true
	}
	if c.accept("(") {
		group, err := c.filterOr(depth+1, match)
		if err != nil || !c.accept(")") {
			if err != nil {
				return flow.QueryFilterGroup{}, err
			}
			return flow.QueryFilterGroup{}, errQuestionClause
		}
		return group, nil
	}
	if explicit {
		return flow.QueryFilterGroup{}, errQuestionClause
	}
	if c.conditions >= flow.MaxQueryPredicates {
		return flow.QueryFilterGroup{}, errQuestionClause
	}
	if c.accept("saved filter") {
		id, err := c.literal()
		if err != nil {
			return flow.QueryFilterGroup{}, err
		}
		c.conditions++
		return flow.QueryFilterGroup{Match: "all", Mode: "include", Saved: []flow.QuerySavedFilterRef{{ID: id, Mode: "include"}}}, nil
	}
	fieldName, count, ambiguous := c.vocabulary.fields.match(c.tokens, c.position)
	if count == 0 || ambiguous {
		return flow.QueryFilterGroup{}, errQuestionClause
	}
	c.position += count
	operator, count, ambiguous := c.vocabulary.operators.match(c.tokens, c.position)
	if count == 0 || ambiguous {
		return flow.QueryFilterGroup{}, errQuestionClause
	}
	c.position += count
	values, err := c.filterValues(fieldName, flow.QueryOperator(operator))
	if err != nil {
		return flow.QueryFilterGroup{}, err
	}
	predicates, err := flow.NormalizeQueryPredicates([]flow.QueryPredicate{{Field: fieldName, Op: flow.QueryOperator(operator), Values: values}})
	if err != nil {
		return flow.QueryFilterGroup{}, errQuestionClause
	}
	c.conditions++
	return flow.QueryFilterGroup{Match: "all", Mode: "include", Conditions: predicates}, nil
}

func (c *questionCursor) filterValues(field string, operator flow.QueryOperator) ([]string, error) {
	if c.accept("(") {
		var values []string
		for {
			if len(values) >= flow.MaxQueryValues {
				return nil, errQuestionClause
			}
			value, err := c.literal()
			if err != nil {
				return nil, err
			}
			values = append(values, value)
			if c.accept(")") {
				return values, nil
			}
			if !c.accept(",") {
				return nil, errQuestionClause
			}
		}
	}
	if (operator == flow.QueryRegex || operator == flow.QueryNotRegex) && (c.position >= len(c.tokens) || !c.tokens[c.position].quoted) {
		return nil, errQuestionClause
	}
	first, err := c.literal()
	if err != nil {
		return nil, err
	}
	if operator != flow.QueryBetween && operator != flow.QueryNotBetween {
		return []string{first}, nil
	}
	definition, _ := flow.LookupQueryField(field)
	if definition.Type == flow.QueryUnsigned {
		if lower, upper, found := strings.Cut(first, "-"); found && lower != "" && upper != "" {
			return []string{lower, upper}, nil
		}
	}
	if !c.accept("and") && !c.accept("to") {
		return nil, errQuestionClause
	}
	second, err := c.literal()
	if err != nil {
		return nil, err
	}
	return []string{first, second}, nil
}

func combineQuestionGroups(match string, left, right flow.QueryFilterGroup) flow.QueryFilterGroup {
	result := flow.QueryFilterGroup{Match: match, Mode: "include"}
	appendOperand := func(group flow.QueryFilterGroup) {
		entries := len(group.Conditions) + len(group.Saved) + len(group.Groups)
		if group.Mode != "exclude" && (group.Match == match || entries == 1) {
			result.Conditions = append(result.Conditions, group.Conditions...)
			result.Saved = append(result.Saved, group.Saved...)
			result.Groups = append(result.Groups, group.Groups...)
		} else {
			result.Groups = append(result.Groups, group)
		}
	}
	appendOperand(left)
	appendOperand(right)
	return result
}

// Associative expressions are packed into valid groups, preserving boolean
// meaning and the native250-entry/1000-condition/depth guards. No literal or
// unsupported expression becomes a backend fragment.
func packQuestionGroup(group flow.QueryFilterGroup) flow.QueryFilterGroup {
	for i := range group.Groups {
		group.Groups[i] = packQuestionGroup(group.Groups[i])
	}
	if len(group.Conditions)+len(group.Saved)+len(group.Groups) <= flow.MaxQueryGroupEntries {
		return group
	}
	parent := flow.QueryFilterGroup{Match: group.Match, Mode: group.Mode}
	chunk := flow.QueryFilterGroup{Match: group.Match, Mode: "include"}
	flush := func() {
		if len(chunk.Conditions)+len(chunk.Saved)+len(chunk.Groups) == flow.MaxQueryGroupEntries {
			parent.Groups = append(parent.Groups, chunk)
			chunk = flow.QueryFilterGroup{Match: group.Match, Mode: "include"}
		}
	}
	for _, condition := range group.Conditions {
		chunk.Conditions = append(chunk.Conditions, condition)
		flush()
	}
	for _, reference := range group.Saved {
		chunk.Saved = append(chunk.Saved, reference)
		flush()
	}
	for _, child := range group.Groups {
		chunk.Groups = append(chunk.Groups, child)
		flush()
	}
	if len(chunk.Conditions)+len(chunk.Saved)+len(chunk.Groups) > 0 {
		parent.Groups = append(parent.Groups, chunk)
	}
	return parent
}
