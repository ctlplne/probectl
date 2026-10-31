// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSubjectDocumentMentionsNestedProseAndExactNeighbors(t *testing.T) {
	cases := []struct {
		subject, text string
		want          bool
	}{
		{"bob@example.test", "Why is BOB@example.test failing?", true},
		{"bob@example.test", "Contact bob@example.test.", true},
		{"bob@example.test", "evilbob@example.test", false},
		{"bob@example.test", "bob@example.test.evil", false},
		{"bob@example.test", `^bob@example\.test$`, true},
		{"bob@example.test", "https://sso.example/users/bob%40example.test", true},
		{"10.0.0.1", "traffic to 10.0.0.1:443.", true},
		{"10.0.0.1", "traffic to 10.0.0.10", false},
		{"10.0.0.1", "traffic to 110.0.0.1", false},
		{"10.0.0.1", `^10\.0\.0\.1$`, true},
		{"10.0.0.1", `^10\.0\.0\.10$`, false},
		{"10.0.0.1", "::ffff:10.0.0.1", true},
		{"10.0.0.1", "2001:db8::10.0.0.1", false},
		{"2001:db8::1", "https://[2001:0DB8:0000:0:0:0:0:1]:443/x", true},
		{"2001:db8::1", "[2001:db8::10]", false},
		{"2001:db8::1", "2001%3Adb8%3A%3A1", true},
		{"fe80::1", "[fe80::1%en0]:443", true},
		{"fe80::1%en0", "fe80::1%en1", false},
		{"00000000-0000-0000-0000-000000000abc", "owner=00000000-0000-0000-0000-000000000ABC", true},
		{"00000000-0000-0000-0000-000000000abc", "00000000-0000-0000-0000-000000000abc-extra", false},
		{"https://example.test/a", "visit https://example.test/a.", true},
		{"https://example.test/a", "visit https://example.test/alice", false},
		{"https://example.test/a", "visit https://example.test/a/extra", false},
		{"Σ", "Look at ς.", true},
		{"a.*b", "literal a.*b", true},
		{"a.*b", "axxxb", false},
		{"42", "142", false},
	}
	for _, test := range cases {
		matcher, err := NewSubjectDocumentMatcher([]string{test.subject}, DefaultSubjectDocumentBudget())
		if err != nil {
			t.Fatal(err)
		}
		for _, document := range []any{map[string]any{"question": test.text}, map[string]any{"nested": []any{map[string]any{test.text: "key"}}}} {
			body, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			got, err := matcher.MatchJSON(t.Context(), body)
			if err != nil || got != test.want {
				t.Errorf("subject=%q text=%q: match=%v want=%v err=%v", test.subject, test.text, got, test.want, err)
			}
		}
	}
	matcher, _ := NewSubjectDocumentMatcher([]string{"42"}, DefaultSubjectDocumentBudget())
	if got, err := matcher.MatchJSON(t.Context(), []byte(`{"number":42,"float":42.0}`)); got || err != nil {
		t.Fatal("JSON numbers were coerced to subject identity", err)
	}
}

func TestSubjectDocumentCompleteScanRefusesInvalidTailAndUnicode(t *testing.T) {
	matcher, _ := NewSubjectDocumentMatcher([]string{"bob@example.test"}, DefaultSubjectDocumentBudget())
	for _, body := range [][]byte{
		[]byte(`{"question":"bob@example.test","tail":`),
		[]byte(`{"question":"bob@example.test"} {"other":1}`),
		[]byte(`{"question":"bob@example.test","tail":"\ud800"}`),
		[]byte(`{"question":"bob@example.test","tail":"\udc00"}`),
		[]byte("{\"question\":\"bob@example.test\",\"tail\":\"" + string([]byte{255}) + "\"}"),
		nil,
	} {
		if got, err := matcher.MatchJSON(t.Context(), body); got || !errors.Is(err, ErrSubjectDocument) {
			t.Fatal("positive prefix certified an incomplete or malformed document", err)
		}
	}
	for _, body := range []string{`{"q":"b\u006fb@example.test","valid":"\ud83d\ude00"}`, `{"q":"bob@example.test","literal":"\\ud800"}`} {
		if got, err := matcher.MatchJSON(t.Context(), []byte(body)); !got || err != nil {
			t.Fatal("valid exact JSON Unicode lost subject", err)
		}
	}
}

func TestSubjectDocumentBudgetsRefuseRatherThanReturnPartialProof(t *testing.T) {
	defaults := DefaultSubjectDocumentBudget()
	body := []byte(`{"q":"bob@example.test","more":[1,2,3]}`)
	exact := defaults
	exact.Bytes = len(body)
	exact.Tokens = 10
	exact.Depth = 2
	matcher, err := NewSubjectDocumentMatcher([]string{"bob@example.test"}, exact)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := matcher.MatchJSON(t.Context(), body); !got || err != nil {
		t.Fatal("exact positive resource limit refused", err)
	}
	for _, budget := range []SubjectDocumentBudget{
		{Bytes: len(body) - 1, AliasBytes: 100, Tokens: 100, Depth: 10, Work: 1000},
		{Bytes: 1000, AliasBytes: 100, Tokens: 4, Depth: 10, Work: 1000},
		{Bytes: 1000, AliasBytes: 100, Tokens: 100, Depth: 1, Work: 1000},
		{Bytes: 1000, AliasBytes: 100, Tokens: 100, Depth: 10, Work: 1},
	} {
		matcher, err := NewSubjectDocumentMatcher([]string{"bob@example.test"}, budget)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := matcher.MatchJSON(t.Context(), body); got || !errors.Is(err, ErrSubjectDocumentBudget) {
			t.Fatal("resource bound returned partial or false proof", err)
		}
	}
	budget := defaults
	budget.AliasBytes = len("bob@example.test") - 1
	if _, err := NewSubjectDocumentMatcher([]string{"bob@example.test"}, budget); !errors.Is(err, ErrSubjectDocumentBudget) {
		t.Fatal("alias resource bound ignored", err)
	}
	for _, aliases := range [][]string{nil, {""}, {" "}, {string([]byte{255})}} {
		if _, err := NewSubjectDocumentMatcher(aliases, defaults); !errors.Is(err, ErrSubjectDocument) {
			t.Fatal("invalid subject alias accepted", err)
		}
	}
	budget = defaults
	budget.Work = 0
	if _, err := NewSubjectDocumentMatcher([]string{"bob@example.test"}, budget); !errors.Is(err, ErrSubjectDocument) {
		t.Fatal("zero resource policy accepted", err)
	}
}

func TestSubjectDocumentCancellationAndAliasesAreImmutable(t *testing.T) {
	aliases := []string{"bob@example.test", "10.0.0.1"}
	matcher, err := NewSubjectDocumentMatcher(aliases, DefaultSubjectDocumentBudget())
	if err != nil {
		t.Fatal(err)
	}
	aliases[0] = "alice@example.test"
	if got, err := matcher.MatchJSON(t.Context(), []byte(`{"q":"bob@example.test"}`)); !got || err != nil {
		t.Fatal("matcher retained mutable alias slice", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := matcher.MatchJSON(ctx, []byte(`{"q":"bob@example.test"}`)); got || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled scan returned subject proof", err)
	}
	// No full-document allocation/tree or number coercion is needed for a long
	// history-shaped source value; matching still validates its entire tail.
	body := []byte(`{"q":"bob@example.test","history":"` + strings.Repeat("x", 2<<20) + `"}`)
	if got, err := matcher.MatchJSON(t.Context(), body); !got || err != nil {
		t.Fatal("large valid history fragment refused", err)
	}
}
