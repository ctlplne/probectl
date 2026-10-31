// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func matchQuestionVocabulary(t *testing.T, vocabulary questionVocabulary, phrase string) string {
	t.Helper()
	tokens, err := lexFlowQuestion(t.Context(), phrase, DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	name, consumed, ambiguous := vocabulary.match(tokens, 0)
	if consumed != len(tokens) || ambiguous {
		t.Fatalf("phrase did not resolve completely: %q", phrase)
	}
	return name
}

func TestFlowQuestionVocabularyCoversEveryCanonicalRegistryEntry(t *testing.T) {
	v := newFlowQuestionVocabulary()
	for _, field := range flow.QueryFields() {
		if got := matchQuestionVocabulary(t, v.fields, field.Name); got != field.Name {
			t.Fatal("registered field absent", field.Name)
		}
		for _, operator := range field.Operators {
			if got := matchQuestionVocabulary(t, v.operators, string(operator)); got != string(operator) {
				t.Fatal("registered operator absent", operator)
			}
		}
	}
	for _, metric := range flow.QueryMetricDefinitions() {
		if got := matchQuestionVocabulary(t, v.metrics, metric.Name); got != metric.Name {
			t.Fatal("registered metric absent", metric.Name)
		}
		for _, calculation := range metric.Calculations {
			if got := matchQuestionVocabulary(t, v.calculations, calculation); got != calculation {
				t.Fatal("registered calculation absent", calculation)
			}
		}
	}
}

func TestFlowQuestionVocabularyUsesLongestMeaningAndPreservesProtocolPlanes(t *testing.T) {
	v := newFlowQuestionVocabulary()
	for _, tc := range []struct {
		phrase, want string
		vocabulary   questionVocabulary
	}{
		{"source IP address", "src_addr", v.fields},
		{"source AS name", "src_as_name", v.fields},
		{"ingress interface name", "in_if_name", v.fields},
		{"flow protocol", "protocol", v.fields},
		{"IP protocol", "transport", v.fields},
		{"unique source IP addresses", "unique_src", v.metrics},
		{"distinct destination countries", "unique_dst_country", v.metrics},
		{"bits per second", "bps", v.metrics},
		{"95th percentile", "p95", v.calculations},
		{"is not equal to", "ne", v.operators},
		{"outside port range", "not_between", v.operators},
		{"<>", "ne", v.operators},
	} {
		if got := matchQuestionVocabulary(t, tc.vocabulary, tc.phrase); got != tc.want {
			t.Fatal("phrase changed meaning", tc.phrase, got)
		}
	}
	tokens, _ := lexFlowQuestion(t.Context(), "tenant_id", DefaultFlowQuestionBudget())
	if name, count, _ := v.fields.match(tokens, 0); name != "" || count != 0 {
		t.Fatal("question acquired a tenant selector")
	}
}

func TestFlowQuestionVocabularyNeverChoosesAnAmbiguousAlias(t *testing.T) {
	var vocabulary questionVocabulary
	vocabulary.add("address", "src_addr")
	vocabulary.add("address", "dst_addr")
	tokens, _ := lexFlowQuestion(t.Context(), "address", DefaultFlowQuestionBudget())
	if name, count, ambiguous := vocabulary.match(tokens, 0); name != "" || count != 1 || !ambiguous {
		t.Fatal("alias collision chose arbitrary source scope")
	}
}
