// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
)

func TestFlowQuerySubjectDecodedDocumentsAndNearMatches(t *testing.T) {
	for _, table := range []string{"flow_query_filters", "flow_query_views"} {
		for _, test := range []struct {
			subject, document string
			want              bool
		}{
			{"192.0.2.1", `[{"regex":"^192\\.0\\.2\\.1$"}]`, true},
			{"192.0.2.1", `[{"regex":"^192\\.0\\.2\\.10$"}]`, false},
			{"2001:db8::1", `[{"nested":["https://[2001:0DB8:0000:0:0:0:0:1]:443/x"]}]`, true},
			{"2001:db8::1", `["2001:db8::10"]`, false},
			{"bob@example.test", `[{"b\u006fb@example.test":"nested key"}]`, true},
			{"bob@example.test", `["evilbob@example.test"]`, false},
		} {
			scan, err := newFlowQuerySubjectScan(table, newSubjectAliasSet(test.subject))
			if err != nil {
				t.Fatal(err)
			}
			got, err := scan.matches(t.Context(), false, []byte(test.document))
			if err != nil || got != test.want {
				t.Fatalf("%s subject=%q: match=%v want=%v err=%v", table, test.subject, got, test.want, err)
			}
			for _, column := range []string{"tenant_id", "id", "version", "created_at"} {
				if strings.Contains(scan.documentSQL, `subject_row."`+column+`"`) {
					t.Fatal("unclassified metadata became a decoded subject selector", column)
				}
			}
		}
	}
}

func TestFlowQuerySubjectExactOwnerCannotHideIncompleteDocument(t *testing.T) {
	scan, err := newFlowQuerySubjectScan("flow_query_views", newSubjectAliasSet("bob@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`["bob@example.test",`, `["bob@example.test","\ud800"]`, `["bob@example.test"] []`} {
		if got, err := scan.matches(t.Context(), true, []byte(body)); got || !errors.Is(err, govern.ErrSubjectDocument) {
			t.Fatal("matching owner certified an incomplete document", err)
		}
	}
	if got, err := scan.matches(t.Context(), true, []byte(`["unrelated"]`)); !got || err != nil {
		t.Fatal("exact owner was lost", err)
	}
	budget := govern.DefaultSubjectDocumentBudget()
	budget.Bytes = 1
	scan.document, err = govern.NewSubjectDocumentMatcher([]string{"bob@example.test"}, budget)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := scan.matches(t.Context(), true, []byte(`[]`)); got || !errors.Is(err, govern.ErrSubjectDocumentBudget) {
		t.Fatal("matching owner certified a resource-refused scan", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := scan.matches(ctx, true, []byte(`[]`)); got || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled scan returned a subject match", err)
	}
	for _, table := range []string{"users", `flow_query_views;DROP TABLE users`, "public.flow_query_views"} {
		if _, err := newFlowQuerySubjectScan(table, newSubjectAliasSet("bob@example.test")); err == nil {
			t.Fatal("non-configuration table entered the decoder", table)
		}
	}
}
