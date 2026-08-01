// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
