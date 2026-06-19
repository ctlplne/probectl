// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestWriteStageConfigDefaultsAndOverrides(t *testing.T) {
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "test", testLogger())
	if got := c.WriteStageConfig(); got.Workers != 4 || got.QueueDepth != 64 {
		t.Fatalf("default write stage = %+v, want workers=4 queue=64", got)
	}

	c.WithWriteWorkers(9)
	if got := c.WriteStageConfig(); got.Workers != 9 || got.QueueDepth != 144 {
		t.Fatalf("worker-derived queue = %+v, want workers=9 queue=144", got)
	}

	c.WithWriteQueueDepth(321)
	if got := c.WriteStageConfig(); got.Workers != 9 || got.QueueDepth != 321 {
		t.Fatalf("explicit queue = %+v, want workers=9 queue=321", got)
	}
}

func TestWriteStageMetricsExposeQueuePressure(t *testing.T) {
	reg := metrics.New("test", "test")
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "test", testLogger()).
		WithWriteWorkers(2).
		WithWriteQueueDepth(3).
		WithMetrics(reg)

	if c.WriteChCapacity() != 3 {
		t.Fatalf("WriteChCapacity = %d, want 3", c.WriteChCapacity())
	}
	c.recordWriteQueueSaturation()
	if got := c.Stats().WriteQueueSaturated; got != 1 {
		t.Fatalf("WriteQueueSaturated = %d, want 1", got)
	}

	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{
		"probectl_pipeline_results_write_queue_capacity 3",
		"probectl_pipeline_results_write_queue_saturated_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, body)
		}
	}
}
