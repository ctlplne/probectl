// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
)

func TestFlowQuerySubjectDecodedDocumentsAndNearMatches(t *testing.T) {
	for _, table := range []string{"flow_query_filters", "flow_query_views", "bgp_flow_capture_objects", "alert_rules"} {
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
			{"alice\"@example.test", `[{"nested":"alice\"@example.test"}]`, true},
			{"11111111-1111-4111-8111-111111111111", `[{"owner_user_id":"11111111-1111-4111-8111-111111111111"}]`, true},
		} {
			scan, err := newFlowQuerySubjectScan(table, newSubjectAliasSet(test.subject))
			if err != nil {
				t.Fatal(err)
			}
			document := []byte(test.document)
			if table == "flow_query_filters" || table == "flow_query_views" {
				// Match the SQL projection: name/description precede the
				// complete expression or definition document.
				var part []json.RawMessage
				if err := json.Unmarshal(document, &part); err != nil {
					t.Fatal(err)
				}
				fields := make([]json.RawMessage, len(subjectPostgresTablePolicies[table].contains))
				fields[len(fields)-1] = part[0]
				document, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := scan.matches(t.Context(), false, document)
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
	if got, err := scan.matches(t.Context(), true, []byte(`[null,"unrelated"]`)); !got || err != nil {
		t.Fatal("exact owner was lost", err)
	}
	if got, err := scan.matches(t.Context(), true, []byte(`["unrelated"]`)); got || !errors.Is(err, govern.ErrSubjectDocument) {
		t.Fatal("matching owner certified an incomplete classified column set", err)
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

func TestFlowQuerySubjectStructuralProjectionKeepsUnknownKeysAndExactNumbers(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	raw := []byte(`["Owned",{"tag_ids":{"tag.role":"` + id + `"},"plan":{"filter":{"groups":[{"saved":[{"id":"` + id + `"}]}]}},"future":{"id":"` + id + `"},"exact":9007199254740993123456789}]`)
	before := string(raw)
	projected, changed, err := projectSavedQuerySubject(t.Context(), "flow_query_views", raw)
	if err != nil || !changed || string(raw) != before || !strings.Contains(string(projected), `9007199254740993123456789`) || !strings.Contains(string(projected), `"future":{"id":"`+id+`"}`) {
		t.Fatal("structural projection altered original/exact/unknown data", err)
	}
	scan, err := newFlowQuerySubjectScan("flow_query_views", newSubjectAliasSet(id))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := scan.matches(t.Context(), false, raw); err != nil || !got {
		t.Fatal("an unknown identity field was hidden by reference projection", err)
	}
	scan, err = newFlowQuerySubjectScan("flow_query_views", newSubjectAliasSet("bob@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	personalKey := []byte(`["Owned",{"tag_ids":{"tag.bob@example.test":"` + id + `"}}]`)
	if got, err := scan.matches(t.Context(), false, personalKey); err != nil || got {
		t.Fatal("a distinct prefixed email key was treated as the same subject", err)
	}
	// The complete key is a different person's email. Removing its structural
	// UUID value must preserve that key for the actual subject's own request.
	scan, err = newFlowQuerySubjectScan("flow_query_views", newSubjectAliasSet("tag.bob@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := scan.matches(t.Context(), false, personalKey); err != nil || !got {
		t.Fatal("a personal tag key was hidden with its structural value", err)
	}
}
