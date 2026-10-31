// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestFlowSnapshotTypedServicesRequirePrivateStorage(t *testing.T) {
	server := &Server{}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: "opaque"}}
	for _, principal := range []*auth.Principal{nil, {TenantID: "tenant-a"}, {TenantID: "tenant-a", UserID: "owner-a"}} {
		ctx := context.Background()
		if got, err := server.createFlowSnapshot(ctx, principal, query, flow.QueryPlan{}, nil); err == nil || got.Flow != nil {
			t.Fatal("query creation returned data without private source/storage prerequisites")
		}
		if got, err := server.resumeFlowSnapshot(ctx, principal, query); err == nil || got.Flow != nil {
			t.Fatal("query continuation returned data without private storage")
		}
		if got, err := server.createFlowComparisonSnapshot(ctx, principal, query, query, nil); err == nil || got.Flow != nil {
			t.Fatal("comparison creation returned data without private source/storage prerequisites")
		}
		if got, err := server.resumeFlowComparisonSnapshot(ctx, principal, query); err == nil || got.Flow != nil {
			t.Fatal("comparison continuation returned data without private storage")
		}
	}
}

func TestFlowSnapshotTypedProjectionPreservesExactSource(t *testing.T) {
	encode := func(value any) json.RawMessage {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	when := time.Date(2026, 10, 28, 1, 2, 3, 123456789, time.UTC)
	const value = "18446744073709551615.123456789012345678"
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Groupings: []string{"src_addr"}}
	row := flowstore.PlanRow{Group: map[string]string{"src_addr": "192.0.2.1"}, Metrics: map[string]string{"bytes:total": value}}
	common := explorerResult{Flow: &flowstore.PlanResult{
		OldestInput: when, Totals: map[string]string{"bytes:total": value},
		TotalSeries: []flowstore.PlanPoint{{TS: when, Metrics: map[string]string{"bytes:total": value}}},
	}}
	page := flowsnapshot.Page{Header: flowsnapshot.Header{
		SnapshotID: "private-scoped-result", ExpiresAt: when.Add(time.Minute),
		Query: encode(query), Data: encode(common), SelectedRows: 50000, PageSize: 5000,
	}, Rows: []json.RawMessage{encode(row)}, Offset: 10000, NextCursor: "opaque-next"}
	got, err := decodeFlowSnapshotPage(page)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flow.Rows[0].Metrics["bytes:total"] != value || got.Rows[0]["bytes:total_str"] != value || got.Flow.TotalSeries[0].TS != when || got.Flow.TotalSeries[0].Metrics["bytes:total"] != value {
		t.Fatalf("source precision changed: %+v", got)
	}
	if !got.Flow.OldestInput.IsZero() || got.FlowPaging.Offset != 10000 || got.FlowPaging.SelectedRows != 50000 || got.FlowPaging.NextCursor != "opaque-next" || !got.FlowPaging.More {
		t.Fatalf("private metadata leaked or global paging changed: %+v", got)
	}

	for _, tc := range []struct {
		name string
		edit func(*flowsnapshot.Page)
	}{
		{"bad metadata", func(p *flowsnapshot.Page) { p.Data = json.RawMessage(`{`) }},
		{"missing flow", func(p *flowsnapshot.Page) { p.Data = json.RawMessage(`{}`) }},
		{"comparison cursor", func(p *flowsnapshot.Page) {
			p.Data = json.RawMessage(`{"contract_version":"flow-explorer-comparison/v2"}`)
		}},
		{"bad query", func(p *flowsnapshot.Page) { p.Query = json.RawMessage(`{`) }},
		{"different source", func(p *flowsnapshot.Page) { p.Query = json.RawMessage(`{"source":"bgp"}`) }},
		{"bad row", func(p *flowsnapshot.Page) { p.Rows = []json.RawMessage{json.RawMessage(`{`)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := page
			tc.edit(&broken)
			if _, err := decodeFlowSnapshotPage(broken); err == nil {
				t.Fatal("corrupt or cross-endpoint snapshot accepted")
			}
		})
	}
}

func TestFlowComparisonTypedProjectionKeepsMissingPeriod(t *testing.T) {
	plan := &flow.QueryPlan{RowLimit: 50000, GroupBy: []string{"src_addr"}}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: plan, Groupings: plan.GroupBy, Measures: []string{"bytes:total"}}
	common := explorerComparisonResult{
		ContractVersion: "flow-explorer-comparison/v2", Current: query, Previous: query, Groupings: plan.GroupBy,
		Flow: &flowExplorerComparisonData{},
	}
	data, err := json.Marshal(common)
	if err != nil {
		t.Fatal(err)
	}
	page := flowsnapshot.Page{Header: flowsnapshot.Header{Data: data, SnapshotID: "private-comparison", SelectedRows: 50000, PageSize: 5000}, Offset: 5000, Rows: []json.RawMessage{
		json.RawMessage(`{"current":{"group":{"src_addr":"192.0.2.1"},"metrics":{"bytes:total":"18446744073709551615"}},"previous":{"group":{"src_addr":"192.0.2.1"},"metrics":{"bytes:total":"18446744073709551614"}}}`),
		json.RawMessage(`{"current":null,"previous":{"group":{"src_addr":"192.0.2.2"},"metrics":{"bytes:total":"7"}}}`),
	}}
	got, err := decodeFlowComparisonSnapshotPage(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 2 || got.FlowPaging.Offset != 5000 || got.FlowPaging.SelectedRows != 50000 {
		t.Fatalf("comparison population changed: %+v", got)
	}
	for _, row := range got.Rows {
		if row.Group["src_addr"] == "192.0.2.1" {
			if row.CurrentExact == nil || *row.CurrentExact != "18446744073709551615" || row.DeltaExact == nil || *row.DeltaExact != "1" {
				t.Fatalf("comparison rounded an exact delta: %+v", row)
			}
		} else if row.CurrentExact != nil || row.CurrentValue != nil || row.PreviousExact == nil || *row.PreviousExact != "7" {
			t.Fatalf("missing period became a measured value: %+v", row)
		}
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{`), json.RawMessage(`{}`), json.RawMessage(`{"current":{"other":true}}`)} {
		broken := page
		broken.Rows = []json.RawMessage{raw}
		if _, err := decodeFlowComparisonSnapshotPage(broken); err == nil {
			t.Fatalf("invalid comparison row accepted: %s", raw)
		}
	}
	page.Data = json.RawMessage(`{"flow":{}}`)
	if _, err := decodeFlowComparisonSnapshotPage(page); err == nil {
		t.Fatal("single-query cursor accepted as a comparison")
	}
}
