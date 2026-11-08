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

func registerRPKIEnrichment(en *opendata.Enricher, cfg *config.Config, log *slog.Logger) {
	if cfg.FlowEnrichRPKIFile == "" {
		return
	}
	source, err := opendata.LoadRPKIVRPs(context.Background(), cfg.FlowEnrichRPKIFile, cfg.FlowEnrichRPKIMaxAge, int64(cfg.FlowEnrichRPKIMemoryBytes), int64(cfg.FlowEnrichRPKIWorkUnits), time.Now())
	if err != nil {
		log.Error("RPKI validator export configured but unavailable", "error", err)
		en.RegisterUnavailable(&opendata.RPKIVRPs{}, err)
		return
	}
	en.Register(source)
	log.Info("complete local RPKI validator source enabled", "source", source.Descriptor().Name)
}
