// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PreparedQueryFilter is immutable after preparation. Regex compilation and
// typed operand parsing happen once, never once per flow row.
type PreparedQueryFilter struct {
	matches func(func(string) string) bool
}

// Matches evaluates only canonical registry values supplied by tenant-scoped
// storage. It cannot request a tenant selector or invoke arbitrary expressions.
func (f PreparedQueryFilter) Matches(value func(string) string) bool {
	return f.matches != nil && f.matches(value)
}

// PrepareQueryFilter rejects unresolved saved references before evaluation.
// The store must resolve them with tenant RLS, then repeat bounded validation.
func PrepareQueryFilter(input *QueryFilterGroup) (PreparedQueryFilter, error) {
	root, err := NormalizeQueryFilterGroup(input)
	if err != nil {
		return PreparedQueryFilter{}, err
	}
	type check func(func(string) string) bool
	var compile func(*QueryFilterGroup) (check, error)
	compile = func(group *QueryFilterGroup) (check, error) {
		if group == nil {
			return func(func(string) string) bool { return true }, nil
		}
		if len(group.Saved) > 0 {
			return nil, errors.New("saved flow filters must be resolved before evaluation")
		}
		checks := []check{}
		for _, predicate := range group.Conditions {
			match, err := prepareQueryPredicate(predicate)
			if err != nil {
				return nil, err
			}
			field := predicate.Field
			checks = append(checks, func(value func(string) string) bool { return match(value(field)) })
		}
		for i := range group.Groups {
			child, err := compile(&group.Groups[i])
			if err != nil {
				return nil, err
			}
			checks = append(checks, child)
		}
		matchAny := group.Match == "any"
		exclude := group.Mode == "exclude"
		return func(value func(string) string) bool {
			result := !matchAny
			for _, match := range checks {
				if matchAny && match(value) {
					result = true
					break
				}
				if !matchAny && !match(value) {
					result = false
					break
				}
			}
			if exclude {
				return !result
			}
			return result
		}, nil
	}
	match, err := compile(root)
	if err != nil {
		return PreparedQueryFilter{}, err
	}
	return PreparedQueryFilter{matches: match}, nil
}

func prepareQueryPredicate(predicate QueryPredicate) (func(string) bool, error) {
	field, ok := LookupQueryField(predicate.Field)
	if !ok {
		return nil, errors.New("unsupported flow field")
	}
	values := predicate.Values
	switch predicate.Op {
	case QueryEqual, QueryIn:
		return func(value string) bool { return slices.Contains(values, value) }, nil
	case QueryNotEqual, QueryNotIn:
		return func(value string) bool { return !slices.Contains(values, value) }, nil
	case QueryContains, QueryNotContains:
		needle := strings.ToLower(values[0])
		exclude := predicate.Op == QueryNotContains
		return func(value string) bool {
			match := strings.Contains(strings.ToLower(value), needle)
			return match != exclude
		}, nil
	case QueryRegex, QueryNotRegex:
		pattern, err := regexp.Compile(values[0])
		if err != nil {
			return nil, errors.New("invalid RE2 pattern")
		}
		exclude := predicate.Op == QueryNotRegex
		return func(value string) bool { return pattern.MatchString(value) != exclude }, nil
	case QueryCIDR, QueryNotCIDR:
		prefixes := make([]netip.Prefix, len(values))
		for i, value := range values {
			prefixes[i], _ = netip.ParsePrefix(value)
		}
		exclude := predicate.Op == QueryNotCIDR
		return func(value string) bool {
			address, err := netip.ParseAddr(value)
			match := false
			if err == nil {
				for _, prefix := range prefixes {
					if prefix.Contains(address.Unmap()) {
						match = true
						break
					}
				}
			}
			return match != exclude
		}, nil
	case QueryHasAnyFlag, QueryHasNoFlag:
		exclude := predicate.Op == QueryHasNoFlag
		return func(value string) bool {
			match := false
			for _, flag := range strings.Split(value, ",") {
				if slices.Contains(values, flag) {
					match = true
					break
				}
			}
			return match != exclude
		}, nil
	case QueryBitAnd:
		mask, err := strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return nil, errors.New("invalid flow bit mask")
		}
		return func(value string) bool {
			number, err := strconv.ParseUint(value, 10, 64)
			if field.Type == QueryFlags {
				number = 0
				err = nil
				for _, name := range strings.Split(value, ",") {
					bit := slices.Index([]string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}, name)
					if bit >= 0 {
						number |= 1 << bit
					} else if name != "NONE" {
						return false
					}
				}
			}
			return err == nil && number&mask != 0
		}, nil
	case QueryGreater, QueryLess, QueryBetween, QueryNotBetween:
		if field.Type == QueryTimestamp {
			first, _ := time.Parse(time.RFC3339Nano, values[0])
			last := first
			if len(values) > 1 {
				last, _ = time.Parse(time.RFC3339Nano, values[1])
			}
			return func(value string) bool {
				at, err := time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return false
				}
				return compareQueryRange(at.Compare(first), at.Compare(last), predicate.Op)
			}, nil
		}
		first, _ := strconv.ParseUint(values[0], 10, 64)
		last := first
		if len(values) > 1 {
			last, _ = strconv.ParseUint(values[1], 10, 64)
		}
		compare := func(a, b uint64) int {
			if a < b {
				return -1
			}
			if a > b {
				return 1
			}
			return 0
		}
		return func(value string) bool {
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return false
			}
			return compareQueryRange(compare(number, first), compare(number, last), predicate.Op)
		}, nil
	default:
		return nil, errors.New("unsupported flow operator")
	}
}

func compareQueryRange(first, last int, op QueryOperator) bool {
	switch op {
	case QueryGreater:
		return first > 0
	case QueryLess:
		return first < 0
	case QueryBetween:
		return first >= 0 && last <= 0
	case QueryNotBetween:
		return first < 0 || last > 0
	default:
		return false
	}
}
