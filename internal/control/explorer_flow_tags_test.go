// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestFlowTagServiceBindsOneTenantRevisionBeforeAggregation(t *testing.T) {
	a, b := gouuid.NewString(), gouuid.NewString()
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	flows := flowstore.NewMemory()
	if err := flows.Insert(t.Context(), []flowstore.Row{
		{TenantID: a, TS: at, Exporter: "192.0.2.1", AgentID: "untrusted-b", BytesScaled: 100},
		{TenantID: a, TS: at, Exporter: "192.0.2.2", BytesScaled: 200},
		{TenantID: b, TS: at, Exporter: "192.0.2.1", BytesScaled: 900},
	}); err != nil {
		t.Fatal(err)
	}
	definition := tags.Definition{TenantID: a, ID: gouuid.NewString(), Key: "customer"}
	lookup, err := flowstore.NewTagQueryData(a, 8, []tags.Definition{definition},
		[]tags.ExporterProjection{{Exporter: "192.0.2.1", Values: map[string]string{"customer": "blue"}}}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vocabulary, err := lookup.Vocabulary(a)
	if err != nil {
		t.Fatal(err)
	}
	raw := ai.ExplorerQuery{Source: ai.ExplorerFlow, Question: "Group flows by customer",
		Flow: &flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute),
			GroupBy: []string{"tag.customer"}, Metrics: []flow.QueryMetric{{
				Measure: "bytes", Calculation: "total", Role: "primary"}}}}
	query, err := ai.NormalizeExplorerQueryWithVocabulary(raw, at, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(fakePinger{}).WithFlowStore(flows)
	principal := &auth.Principal{TenantID: a, UserID: "reader", Permissions: map[string]bool{
		permAIQuery: true, permFlowRead: true, permTagsRead: true}}
	ctx := flowTagQueryContext(t.Context(), lookup)
	result, err := server.recordFlowQuery(ctx, principal, query)
	if err != nil || result.Flow == nil || result.Flow.TagRevision != 8 || result.Flow.Totals["bytes:total"] != "300" {
		t.Fatalf("tenant tag query lost scope or revision: %+v, %v", result, err)
	}
	groups := map[string]string{}
	for _, row := range result.Flow.Rows {
		groups[row.Group["tag.customer"]] = row.Metrics["bytes:total"]
	}
	if groups["blue"] != "100" || groups[""] != "200" {
		t.Fatalf("tag query changed exact totals or ignored unmatched flow: %+v", groups)
	}
	withheld := *principal
	withheld.Permissions = map[string]bool{permAIQuery: true, permFlowRead: true}
	if _, err := server.recordFlowQuery(ctx, &withheld, query); err == nil {
		t.Fatal("tag query bypassed tags.read")
	}
	foreign := *principal
	foreign.TenantID = b
	if _, err := server.recordFlowQuery(ctx, &foreign, query); err == nil {
		t.Fatal("foreign principal reused another tenant's tag snapshot")
	}
}
