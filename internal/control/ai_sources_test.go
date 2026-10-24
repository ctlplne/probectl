// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// DPR-297: a question about a target must find the probe series of that
// target. The series are made by the result pipeline exactly as the shipped
// consumer writes them, so the test holds the label set the TSDB really has
// (server_address, not "target"). Two tenants probe the same host; only the
// asking tenant's series answer.
func TestMetricsEvidenceFindsTheProbeSeriesOfATarget(t *testing.T) {
	mem := tsdb.NewMemory()
	now := time.Now()
	for _, r := range []*resultv1.Result{
		{TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "tcp", ServerAddress: "127.0.0.1", Success: false},
		{TenantId: "tenant-b", AgentId: "agent-b", CanaryType: "tcp", ServerAddress: "127.0.0.1", Success: true},
		{TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "tcp", ServerAddress: "198.51.100.7", Success: true},
	} {
		if err := mem.Write(context.Background(), pipeline.ResultToSeries(r)); err != nil {
			t.Fatal(err)
		}
	}
	src := metricsEvidenceSource{writer: mem}
	rows, err := src.QueryMetrics(context.Background(), "tenant-a", map[string]string{"target": "127.0.0.1"},
		ai.TimeRange{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("a question about 127.0.0.1 found none of the tenant's probe series of 127.0.0.1")
	}
	sawSuccess := false
	for _, row := range rows {
		if row["agent_id"] != "agent-a" || row["target"] != "127.0.0.1" {
			t.Errorf("row %v is not tenant-a's probe of 127.0.0.1", row)
		}
		if row["metric"] == "probectl_probe_success" {
			sawSuccess = true
			if row["value"] != float64(0) {
				t.Errorf("tenant-a's probe success reads %v, want its own failed probe (0)", row["value"])
			}
		}
	}
	if !sawSuccess {
		t.Errorf("rows %v hold no probectl_probe_success", rows)
	}
}

func TestMetricsSelectorMatchesTheTargetLabelTheSeriesCarry(t *testing.T) {
	got := metricsSelector(map[string]string{"target": "edge.example.com", "agent_id": "a1"}, "t1").String()
	for _, want := range []string{`server_address="edge.example.com"`, `agent_id="a1"`, `tenant_id="t1"`} {
		if !strings.Contains(got, want) {
			t.Errorf("selector %s lacks %s", got, want)
		}
	}
	if strings.Contains(got, `target=`) {
		t.Errorf("selector %s matches a target label no series carries", got)
	}
}

// DPR-308: two tests against one host are two series under one agent and
// server_address. Each metric evidence row must carry its series' test_id, and
// the answer's allow-list must keep it, or a cited value cannot be followed
// back to the series it came from (G4(a) found the RCA citing a 0 and a 1 for
// "probectl_probe_success on 127.0.0.1" with nothing to tell them apart).
func TestMetricsEvidenceNamesTheTestOfEachSeries(t *testing.T) {
	mem := tsdb.NewMemory()
	now := time.Now()
	for _, r := range []*resultv1.Result{
		{TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "http", ServerAddress: "127.0.0.1", Success: true,
			Attributes: map[string]string{"probectl.test.id": "test-readyz"}},
		{TenantId: "tenant-a", AgentId: "agent-a", CanaryType: "http", ServerAddress: "127.0.0.1", Success: false,
			Attributes: map[string]string{"probectl.test.id": "test-service"}},
	} {
		if err := mem.Write(context.Background(), pipeline.ResultToSeries(r)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := metricsEvidenceSource{writer: mem}.QueryMetrics(context.Background(), "tenant-a",
		map[string]string{"target": "127.0.0.1"}, ai.TimeRange{Start: now.Add(-time.Hour), End: now.Add(time.Minute)}, 50)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{}
	for _, row := range rows {
		if row["metric"] != "probectl_probe_success" {
			continue
		}
		clean := ai.SanitizeRow(ai.DomainMetrics, row)
		id, _ := clean["test_id"].(string)
		if id == "" {
			t.Fatalf("serialized metric evidence %v names no test_id", clean)
		}
		values[id] = clean["value"]
	}
	if values["test-readyz"] != float64(1) || values["test-service"] != float64(0) {
		t.Errorf("probe success by test = %v, want test-readyz=1 and test-service=0", values)
	}
}
