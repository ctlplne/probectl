// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestFlowCSVSeparatesExactMetricsFromUntrustedLabelsAndSummaries(t *testing.T) {
	plan := flow.QueryPlan{From: time.Now().Add(-time.Hour), To: time.Now(), GroupBy: []string{"agent_id"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	format, header, err := newFlowCSVFormat(plan, flow.QueryVocabulary{})
	if err != nil || !reflect.DeepEqual(header, []string{"record_type", "agent_id", "bytes:total"}) {
		t.Fatalf("CSV schema: %v %v", header, err)
	}
	for _, value := range []string{"=1+1", "+1", "-1", "@SUM(1)", " \t=1+1", "\ufeff=1+1", "\tlabel"} {
		row, err := format.row(flowstore.PlanRow{Group: map[string]string{"agent_id": value}, Metrics: map[string]string{"bytes:total": "18446744073709551616001"}}, "detail")
		if err != nil || row[1] != "'"+value || row[2] != "18446744073709551616001" {
			t.Fatalf("label/metric encoding: %q %v", row, err)
		}
	}
	row, err := format.row(flowstore.PlanRow{Group: map[string]string{"agent_id": "Other"}, Metrics: map[string]string{"bytes:total": "1"}}, "detail")
	if err != nil || row[0] != "detail" || row[1] != "Other" {
		t.Fatal("literal Other was conflated with summary")
	}
	other, err := format.row(flowstore.PlanRow{Other: true, Metrics: map[string]string{"bytes:total": "2"}}, "other")
	if err != nil || other[0] != "other" || other[1] != "" {
		t.Fatal("structural Other was not explicit")
	}
	for _, metric := range []string{"=1+1", "NaN", "1e20", "-1", ""} {
		if _, err := format.row(flowstore.PlanRow{Group: map[string]string{"agent_id": "ok"}, Metrics: map[string]string{"bytes:total": metric}}, "detail"); !errors.Is(err, flowsnapshot.ErrIntegrity) {
			t.Fatalf("invalid metric accepted: %q %v", metric, err)
		}
	}
}

func TestFlowCSVOutputBudgetAndCancellationNeverWritePartialRecord(t *testing.T) {
	var body bytes.Buffer
	writer := &flowCSVWriter{ctx: t.Context(), target: &body, remaining: 3}
	if n, err := writer.Write([]byte("four")); n != 0 || !errors.Is(err, flowsnapshot.ErrBudget) || body.Len() != 0 {
		t.Fatalf("over-budget bytes written: %d %v", n, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	writer.ctx = ctx
	if _, err := writer.Write([]byte("x")); !errors.Is(err, context.Canceled) || body.Len() != 0 {
		t.Fatal("canceled export wrote data")
	}
}

func TestFlowComparisonCSVExactSignedDeltasAndMissingPeriod(t *testing.T) {
	format, columns, err := newFlowComparisonCSVFormat(flow.QueryPlan{GroupBy: []string{"agent_id"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}, flow.QueryVocabulary{})
	if err != nil || len(columns) != 9 {
		t.Fatal("comparison CSV schema", columns, err)
	}
	now := &flowstore.PlanRow{Group: map[string]string{"agent_id": "=unsafe"}, Metrics: map[string]string{"bytes:total": "9007199254740993"}}
	before := &flowstore.PlanRow{Group: now.Group, Metrics: map[string]string{"bytes:total": "9007199254740994"}}
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	if err := format.write(writer, now, before, "detail"); err != nil {
		t.Fatal(err)
	}
	if err := format.write(writer, now, nil, "detail"); err != nil {
		t.Fatal(err)
	}
	writer.Flush()
	records, err := csv.NewReader(&body).ReadAll()
	if err != nil || records[0][1] != "'=unsafe" || records[0][4] != "9007199254740993" || records[0][6] != "-1" || records[1][5] != "" || records[1][8] != "missing_previous" {
		t.Fatalf("CSV changed exact values/state: %v %v", records, err)
	}
}
