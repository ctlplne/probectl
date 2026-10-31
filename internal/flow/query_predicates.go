// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// D103 raises the original D102100-condition guard above Kentik's
	// published250-per-group reach; expanded queries remain resource-bounded.
	MaxQueryPredicates   = 1000
	MaxQueryGroupEntries = 250
	MaxQueryFilterDepth  = 5
	MaxQueryRegexBytes   = 1024
	MaxQueryValues       = 1000
	MaxQueryValueBytes   = 64 * 1024
)

// QueryPredicate carries typed values. Field and operator resolve through the
// registry; even a value that looks like SQL remains ordinary bound data.
type QueryPredicate struct {
	Field  string        `json:"field"`
	Op     QueryOperator `json:"op"`
	Values []string      `json:"values"`
}

// NormalizeQueryPredicates validates a copy and canonicalizes addresses,
// integers, prefixes and timestamps before either backend sees a predicate.
func NormalizeQueryPredicates(input []QueryPredicate) ([]QueryPredicate, error) {
	if len(input) > MaxQueryPredicates {
		return nil, fmt.Errorf("flow queries allow at most %d predicates", MaxQueryPredicates)
	}
	out := make([]QueryPredicate, 0, len(input))
	for _, predicate := range input {
		field, ok := LookupQueryField(predicate.Field)
		if !ok {
			return nil, errors.New("unsupported flow field")
		}
		if !slices.Contains(field.Operators, predicate.Op) {
			return nil, fmt.Errorf("unsupported operator for %s", field.Name)
		}
		n := len(predicate.Values)
		if n == 0 || n > MaxQueryValues {
			return nil, fmt.Errorf("flow predicates require 1-%d values", MaxQueryValues)
		}
		switch predicate.Op {
		case QueryEqual, QueryNotEqual, QueryContains, QueryNotContains, QueryRegex, QueryNotRegex, QueryGreater, QueryLess, QueryBitAnd:
			if n != 1 {
				return nil, fmt.Errorf("%s requires one value", predicate.Op)
			}
		case QueryBetween, QueryNotBetween:
			if n != 2 {
				return nil, fmt.Errorf("%s requires a lower and upper bound", predicate.Op)
			}
		}
		values := make([]string, 0, n)
		for _, value := range predicate.Values {
			if predicate.Op != QueryRegex && predicate.Op != QueryNotRegex && predicate.Op != QueryContains && predicate.Op != QueryNotContains {
				value = strings.TrimSpace(value)
			}
			if len(value) > MaxQueryValueBytes {
				return nil, fmt.Errorf("flow predicate values allow at most %d bytes", MaxQueryValueBytes)
			}
			if value == "" {
				exact := predicate.Op == QueryEqual || predicate.Op == QueryNotEqual || predicate.Op == QueryIn || predicate.Op == QueryNotIn
				if exact && (field.Type == QueryText || field.Type == QueryAddress || field.Type == QueryPrefix) {
					values = append(values, "")
					continue
				}
				return nil, fmt.Errorf("%s requires a nonempty typed value", field.Name)
			}
			canonical, err := normalizeQueryValue(field, predicate.Op, value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s predicate: %w", field.Name, err)
			}
			values = append(values, canonical)
		}
		if predicate.Op == QueryBetween || predicate.Op == QueryNotBetween {
			if queryBoundsReversed(field.Type, values[0], values[1]) {
				return nil, fmt.Errorf("%s lower bound exceeds its upper bound", field.Name)
			}
		} else {
			slices.Sort(values)
			values = slices.Compact(values)
		}
		out = append(out, QueryPredicate{Field: field.Name, Op: predicate.Op, Values: values})
	}
	return out, nil
}

func normalizeQueryValue(field QueryField, op QueryOperator, value string) (string, error) {
	if op == QueryRegex || op == QueryNotRegex {
		if len(value) > MaxQueryRegexBytes {
			return "", errors.New("regex exceeds 1024-byte RE2 limit")
		}
		if _, err := regexp.Compile(value); err != nil {
			return "", errors.New("invalid RE2 pattern")
		}
		return value, nil
	}
	if op == QueryContains || op == QueryNotContains {
		return value, nil
	}
	if op == QueryBitAnd && field.Type == QueryFlags {
		number, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return "", errors.New("expected an eight-bit flag mask")
		}
		return strconv.FormatUint(number, 10), nil
	}
	if op == QueryCIDR || op == QueryNotCIDR || field.Type == QueryPrefix {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" {
			return "", fmt.Errorf("expected an address prefix")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return "", fmt.Errorf("mapped IPv4 prefixes need at least 96 bits")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked().String(), nil
	}
	switch field.Type {
	case QueryAddress:
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return "", fmt.Errorf("expected an IP address without a zone")
		}
		return address.Unmap().String(), nil
	case QueryUnsigned:
		number, err := strconv.ParseUint(value, 10, 64)
		if err != nil || number > field.MaxValue {
			return "", fmt.Errorf("expected an integer between 0 and %d", field.MaxValue)
		}
		return strconv.FormatUint(number, 10), nil
	case QueryTimestamp:
		ts, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return "", fmt.Errorf("expected an RFC3339 timestamp")
		}
		return ts.UTC().Format(time.RFC3339Nano), nil
	case QueryFlags:
		flags := strings.Split(strings.ToUpper(value), ",")
		if len(flags) == 1 && flags[0] == "NONE" && op != QueryHasAnyFlag && op != QueryHasNoFlag {
			return "NONE", nil
		}
		order := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
		for i := range flags {
			flags[i] = strings.TrimSpace(flags[i])
			if !slices.Contains(order, flags[i]) {
				return "", fmt.Errorf("unknown TCP flag")
			}
		}
		if (op == QueryHasAnyFlag || op == QueryHasNoFlag) && len(flags) != 1 {
			return "", fmt.Errorf("each flag-set member must name one flag")
		}
		slices.SortFunc(flags, func(a, b string) int { return slices.Index(order, a) - slices.Index(order, b) })
		return strings.Join(slices.Compact(flags), ","), nil
	default:
		return value, nil
	}
}

func queryBoundsReversed(kind QueryFieldType, lower, upper string) bool {
	if kind == QueryTimestamp {
		lo, _ := time.Parse(time.RFC3339Nano, lower)
		hi, _ := time.Parse(time.RFC3339Nano, upper)
		return lo.After(hi)
	}
	lo, _ := strconv.ParseUint(lower, 10, 64)
	hi, _ := strconv.ParseUint(upper, 10, 64)
	return lo > hi
}
