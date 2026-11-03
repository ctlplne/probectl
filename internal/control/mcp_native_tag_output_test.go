// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestNativeTagOutputAndCSVKeepOriginalIdentityAndExactCounters(t *testing.T) {
	const tenant = "00000000-0000-4000-8000-000000000101"
	const other = "00000000-0000-4000-8000-000000000102"
	const definition = "00000000-0000-4000-8000-000000000301"
	at := time.Now().UTC().Truncate(time.Minute)
	plan := flow.QueryPlan{From: at.Add(-time.Hour), To: at, View: "table", GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	source := flowstore.PlanResult{Query: plan, Source: "raw", ResolutionSeconds: 60, TotalGroups: 1,
		TagTenantID: tenant, TagRevision: 9007199254740993, TagIDs: map[string]string{"tag.customer": definition},
		Coverage: &flowstore.PlanSourceCoverage{Fields: []string{"tag.customer"}, ResolutionSeconds: 60, CompleteInputs: true},
		Rows:     []flowstore.PlanRow{{Group: map[string]string{"tag.customer": "=owned annotation"}, Metrics: map[string]string{"bytes:total": "9007199254740993"}}},
		Totals:   map[string]string{"bytes:total": "9007199254740993"}}
	wire, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var frozen flowstore.PlanResult
	if err := json.Unmarshal(wire, &frozen); err != nil {
		t.Fatal(err)
	}
	projected, err := projectNativeFlowQuery(explorerResult{Flow: &frozen}, tenant)
	if err != nil {
		t.Fatalf("original tagged output was rejected by static-only normalization: %v", err)
	}
	if projected.Flow.TagTenantID != tenant || projected.Flow.TagRevision != "9007199254740993" || len(projected.Flow.TagIDs) != 1 || projected.Flow.TagIDs[0].ID != definition || projected.Flow.TagIDs[0].Field != "tag.customer" || projected.Flow.Rows[0].Metrics[0].Value != "9007199254740993" || projected.Flow.Rows[0].Group[0].Value != "=owned annotation" {
		t.Fatal("native frozen output changed original scope, identity, revision or values")
	}
	if _, err := projectNativeFlowQuery(explorerResult{Flow: &frozen}, other); err == nil {
		t.Fatal("foreign native actor accepted frozen tag identities")
	}
	vocabulary, err := frozen.OutputVocabulary(tenant)
	if err != nil {
		t.Fatal(err)
	}
	format, columns, err := newFlowCSVFormat(frozen.Query, vocabulary)
	if err != nil || strings.Join(columns, ",") != "record_type,tag.customer,bytes:total" {
		t.Fatalf("tag CSV lost original header: %v", err)
	}
	row, err := format.row(frozen.Rows[0], "detail")
	if err != nil || strings.Join(row, ",") != "detail,'=owned annotation,9007199254740993" {
		t.Fatalf("tag CSV changed safe text or exact counter: %v", err)
	}
	if _, _, err := newFlowComparisonCSVFormat(frozen.Query, vocabulary); err != nil {
		t.Fatalf("tag comparison CSV rejected original field: %v", err)
	}
}
