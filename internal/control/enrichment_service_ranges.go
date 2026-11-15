// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/opendata"
)

func registerServiceRangeEnrichment(en *opendata.Enricher, cfg *config.Config, log *slog.Logger) {
	if cfg.FlowEnrichServiceFile == "" {
		return
	}
	source, err := opendata.LoadServiceRanges(context.Background(), cfg.FlowEnrichServiceFile, cfg.FlowEnrichServiceMaxAge, int64(cfg.FlowEnrichServiceMemoryBytes), time.Now())
	if err != nil {
		log.Error("complete published service ranges unavailable", "error", err)
		en.RegisterUnavailable(&opendata.ServiceRanges{}, err)
		return
	}
	en.Register(source)
	log.Info("complete local published service ranges enabled", "source", source.Descriptor().Name, "memory_admission_bytes", cfg.FlowEnrichServiceMemoryBytes)
}
