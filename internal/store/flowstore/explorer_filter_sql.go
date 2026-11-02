// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
)

// explorerFilterSQL preserves the nested Boolean tree. Only validated registry
// selectors contribute structure; all literals remain separately bound values.
// It is composed inside, never in place of, the outer tenant predicate.
func explorerFilterSQL(input *flow.QueryFilterGroup, params chParams) (string, error) {
	return explorerFilterSQLWithVocabulary(input, params, flow.QueryVocabulary{})
}

func explorerFilterSQLWithVocabulary(input *flow.QueryFilterGroup, params chParams,
	vocabulary flow.QueryVocabulary) (string, error) {
	root, err := flow.NormalizeQueryFilterGroupWithVocabulary(input, vocabulary)
	if err != nil {
		return "", err
	}
	index := 0
	var compile func(*flow.QueryFilterGroup) (string, error)
	compile = func(group *flow.QueryFilterGroup) (string, error) {
		if group == nil {
			return "1", nil
		}
		if len(group.Saved) > 0 {
			return "", errors.New("saved flow filters must be tenant-resolved before compilation")
		}
		parts := []string{}
		for _, predicate := range group.Conditions {
			sql, err := explorerPredicateSQLWithVocabulary(predicate, index, params, vocabulary)
			if err != nil {
				return "", err
			}
			index++
			parts = append(parts, "("+sql+")")
		}
		for i := range group.Groups {
			sql, err := compile(&group.Groups[i])
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+sql+")")
		}
		connective := " AND "
		if group.Match == "any" {
			connective = " OR "
		}
		sql := "(" + strings.Join(parts, connective) + ")"
		if group.Mode == "exclude" {
			sql = "NOT " + sql
		}
		return sql, nil
	}
	return compile(root)
}
