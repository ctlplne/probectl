// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestSubscriberUsageCountsEachRecordOnceAndSelectsRemoteService(t *testing.T) {
	input := flow.SubscriberUsageRequest{ViewID: "owned", Version: "1", TagID: "subscriber-tag", TagKey: "subscriber", Subscriber: "alpha"}
	source, destination := input.TagFields()
	from := time.Date(2026, 11, 20, 5, 0, 0, 0, time.UTC)
	plan := input.Plan(flow.QueryPlan{From: from, To: from.Add(time.Minute)})
	captured := capturedReportFlow{TenantID: "tenant", ID: input.ViewID, Version: input.Version, Period: "current", TagAsOf: plan.To, Result: flowstore.PlanResult{
		Query: plan, Source: "raw", TagTenantID: "tenant", TagRevision: 4, TagIDs: map[string]string{source: input.TagID, destination: input.TagID},
		Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, TotalGroups: 3, ResolutionSeconds: 1,
		Totals: map[string]string{"bytes:total": "9007199254741023", "packets:total": "9"},
		Rows: []flowstore.PlanRow{
			{Group: map[string]string{source: "alpha", destination: "beta", "dst_service_status": "known", "dst_service_provider": "Provider", "dst_service": "Object storage"}, Metrics: map[string]string{"bytes:total": "9007199254740993", "packets:total": "3"}},
			{Group: map[string]string{source: "beta", destination: "alpha", "src_service_status": "ambiguous", "src_service_provider": "unsupported alternative"}, Metrics: map[string]string{"bytes:total": "10", "packets:total": "2"}},
			{Group: map[string]string{source: "alpha", destination: "alpha"}, Metrics: map[string]string{"bytes:total": "20", "packets:total": "4"}},
		},
	}}
	out, err := projectSubscriberUsage(t.Context(), input, captured)
	if err != nil || out.Total.Bytes != "9007199254741023" || out.Download.Bytes != "10" || out.Upload.Bytes != "9007199254740993" || out.Internal.Bytes != "20" ||
		len(out.TopServices) != 2 || out.TopServices[0].Service != "Object storage" || out.TopServices[1].Status != "ambiguous" || out.TopServices[1].Provider != "" {
		t.Fatalf("wrong exact subscriber projection %+v, %v", out, err)
	}
	captured.Result.DetailLimited = true
	if _, err := projectSubscriberUsage(t.Context(), input, captured); err == nil {
		t.Fatal("an incomplete subscriber group population must not publish")
	}
}
