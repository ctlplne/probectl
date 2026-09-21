// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/store/tsdb"
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
