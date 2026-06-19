// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestBuildResultPipelineConsumerWiresWriteStageConfig(t *testing.T) {
	cfg := &config.Config{
		IngestWriteWorkers: 13,
		IngestWriteQueue:   4096,
	}
	consumer := buildResultPipelineConsumer(
		cfg,
		bus.NewMemory(),
		tsdb.NewMemory(),
		quietLogger(),
		nil,
		nil,
		nil,
		nil,
		metrics.New("test", "test"),
	)

	if got := consumer.WriteStageConfig(); got.Workers != 13 || got.QueueDepth != 4096 {
		t.Fatalf("served result pipeline write stage = %+v, want workers=13 queue=4096", got)
	}
}
