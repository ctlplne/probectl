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

// Aliases resolve only to canonical registry values. A collision is retained
// and reported as ambiguous, never settled by map/registration ordering.
type questionVocabulary struct {
	aliases  map[string]map[string]bool
	maxWords int
}

func (v *questionVocabulary) add(phrase, canonical string) {
	key := strings.ToLower(strings.Join(strings.Fields(phrase), " "))
	if key == "" {
		return
	}
	if v.aliases == nil {
		v.aliases = map[string]map[string]bool{}
	}
	if v.aliases[key] == nil {
		v.aliases[key] = map[string]bool{}
	}
	v.aliases[key][canonical] = true
	v.maxWords = max(v.maxWords, len(strings.Fields(key)))
}

func (v questionVocabulary) match(tokens []questionToken, position int) (name string, consumed int, ambiguous bool) {
	if position < 0 || position >= len(tokens) {
		return "", 0, false
	}
	resolve := func(candidates map[string]bool, count int) {
		if len(candidates) == 0 {
			return
		}
		name, consumed, ambiguous = "", count, len(candidates) > 1
		if !ambiguous {
			for value := range candidates {
				name = value
			}
		}
	}
	if tokens[position].quoted {
		resolve(v.aliases[strings.ToLower(strings.Join(strings.Fields(tokens[position].text), " "))], 1)
		return name, consumed, ambiguous
	}
	words := make([]string, 0, min(v.maxWords, len(tokens)-position))
	for offset := 0; offset < v.maxWords && position+offset < len(tokens); offset++ {
		if tokens[position+offset].quoted {
			break
		}
		words = append(words, tokens[position+offset].lower)
		resolve(v.aliases[strings.Join(words, " ")], offset+1)
	}
	return name, consumed, ambiguous
}

type flowQuestionVocabulary struct{ fields, metrics, calculations, operators questionVocabulary }

func newFlowQuestionVocabulary() flowQuestionVocabulary {
	var vocabulary flowQuestionVocabulary
	for _, field := range flow.QueryFields() {
		for _, alias := range questionFieldAliases(field.Name) {
			vocabulary.fields.add(alias, field.Name)
			vocabulary.fields.add(pluralQuestionPhrase(alias), field.Name)
		}
		for _, operator := range field.Operators {
			vocabulary.operators.add(string(operator), string(operator))
			for _, alias := range questionOperatorAliases[operator] {
				vocabulary.operators.add(alias, string(operator))
			}
		}
	}
	for _, metric := range flow.QueryMetricDefinitions() {
		vocabulary.metrics.add(metric.Name, metric.Name)
		vocabulary.metrics.add(strings.ReplaceAll(metric.Name, "_", " "), metric.Name)
		for _, alias := range questionMetricAliases[metric.Name] {
			vocabulary.metrics.add(alias, metric.Name)
		}
		if metric.DistinctField != "" {
			for _, fieldAlias := range questionFieldAliases(metric.DistinctField) {
				for _, alias := range []string{fieldAlias, pluralQuestionPhrase(fieldAlias)} {
					vocabulary.metrics.add("unique "+alias, metric.Name)
					vocabulary.metrics.add("distinct "+alias, metric.Name)
				}
			}
		}
		for _, calculation := range metric.Calculations {
			vocabulary.calculations.add(calculation, calculation)
			vocabulary.calculations.add(strings.ReplaceAll(calculation, "_", " "), calculation)
			for _, alias := range questionCalculationAliases[calculation] {
				vocabulary.calculations.add(alias, calculation)
			}
		}
	}
	return vocabulary
}

func questionFieldAliases(name string) []string {
	aliases := []string{name}
	phrases := []string{""}
	for _, word := range strings.Split(name, "_") {
		choices := questionFieldWords[word]
		if len(choices) == 0 {
			choices = []string{word}
		}
		var next []string
		for _, prefix := range phrases {
			for _, choice := range choices {
				next = append(next, strings.TrimSpace(prefix+" "+choice))
			}
		}
		phrases = next
	}
	aliases = append(aliases, phrases...)
	aliases = append(aliases, questionFieldPhrases[name]...)
	return aliases
}

func pluralQuestionPhrase(phrase string) string {
	words := strings.Fields(phrase)
	if len(words) == 0 {
		return phrase
	}
	last := words[len(words)-1]
	switch {
	case strings.EqualFold(last, "country"):
		last = last[:len(last)-1] + "ies"
	case strings.HasSuffix(last, "address"):
		last += "es"
	default:
		last += "s"
	}
	words[len(words)-1] = last
	return strings.Join(words, " ")
}

var questionFieldWords = map[string][]string{
	"src": {"source"}, "dst": {"destination"}, "addr": {"address", "IP", "IP address"},
	"asn": {"ASN", "AS number", "autonomous system number"}, "as": {"AS", "autonomous system"},
	"if": {"interface"}, "in": {"input", "ingress"}, "out": {"output", "egress"},
	"obs": {"observation"}, "id": {"id", "identifier"}, "ts": {"timestamp"},
	"tos": {"ToS", "type of service"}, "net": {"network"},
}

var questionFieldPhrases = map[string][]string{
	"protocol":  {"flow protocol", "flow wire protocol", "collector protocol"},
	"transport": {"transport protocol", "IP protocol", "network transport"},
	"ts":        {"observation time", "observed at"}, "start_ts": {"flow start time", "started at"},
	"net_type": {"network layer", "IP version"},
	"in_if":    {"input interface index", "ingress interface index"}, "out_if": {"output interface index", "egress interface index"},
	"tcp_flags": {"TCP flag mask"}, "tcp_flag_names": {"named TCP flags"},
	"raw_bytes": {"uncorrected bytes"}, "raw_packets": {"uncorrected packets"},
	"bytes_scaled":   {"scaled bytes", "corrected bytes", "sample adjusted bytes"},
	"packets_scaled": {"scaled packets", "corrected packets", "sample adjusted packets"},
}

var questionMetricAliases = map[string][]string{
	"bps":   {"bits per second", "bit per second", "bit/s"},
	"pps":   {"packets per second", "packet per second", "packet/s"},
	"fps":   {"flows per second", "flow per second", "flow/s"},
	"bytes": {"bytes", "byte"}, "packets": {"packets", "packet"}, "flows": {"flows", "flow"},
}

var questionCalculationAliases = map[string][]string{
	"avg": {"average", "mean"}, "p95": {"95th percentile", "95 percentile"},
	"p99": {"99th percentile", "99 percentile"}, "max": {"maximum", "peak"}, "total": {"sum", "total"},
	"bucket_total": {"sum of bucket counts", "sum of per bucket counts"},
}

var questionOperatorAliases = map[flow.QueryOperator][]string{
	flow.QueryEqual:    {"=", "==", "equals", "equal to", "is", "is equal to"},
	flow.QueryNotEqual: {"!=", "<>", "not equal to", "does not equal", "is not", "is not equal to"},
	flow.QueryIn:       {"in", "one of", "is one of"}, flow.QueryNotIn: {"not in", "none of", "is not one of"},
	flow.QueryCIDR: {"in subnet", "in CIDR", "within CIDR", "inside subnet"}, flow.QueryNotCIDR: {"not in subnet", "not in CIDR", "outside subnet"},
	flow.QueryBetween: {"between", "in range", "in port range"}, flow.QueryNotBetween: {"not between", "outside range", "outside port range"},
	flow.QueryHasAnyFlag: {"has any", "has any flag"}, flow.QueryHasNoFlag: {"has none", "has no flag"},
	flow.QueryContains: {"contains"}, flow.QueryNotContains: {"does not contain", "not contains"},
	flow.QueryRegex: {"matches", "regex match", "matches regex"}, flow.QueryNotRegex: {"does not match", "regex no match", "not matches regex"},
	flow.QueryGreater: {">", "greater than", "more than"}, flow.QueryLess: {"<", "less than", "below"},
	flow.QueryBitAnd: {"&", "bitwise AND", "bitwise and mask"},
}
