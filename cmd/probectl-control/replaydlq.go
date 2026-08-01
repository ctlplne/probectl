// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/pipeline"
)

// runReplayDeadLetter is the `probectl-control replay-deadletter` subcommand
// (ARCH-001): drain a probectl.deadletter.* topic and re-ingest each parked
// record onto its source topic, so a store outage that outlived the retry
// budget is recoverable by the product itself — no ad-hoc operator tooling.
//
//	probectl-control replay-deadletter --topic probectl.deadletter.results [--max-rate N] [--max N] [--idle 5s]
//
// It uses the SAME bus the control plane uses (so it publishes to the live
// source topics). The original tenant key + payload are preserved verbatim; a
// replayed record re-enters the normal ingest path and is deduped downstream.
func runReplayDeadLetter(cfg *config.Config, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("replay-deadletter", flag.ContinueOnError)
	topic := fs.String("topic", "", "dead-letter topic to drain (e.g. probectl.deadletter.results)")
	maxRate := fs.Float64("max-rate", 0, "max records/sec to re-publish (0 = unthrottled)")
	maxRecords := fs.Int("max", 0, "stop after N records (0 = drain until idle)")
	idle := fs.Duration("idle", 5*time.Second, "stop after this long with no new record")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *topic == "" {
		return fmt.Errorf("replay-deadletter: --topic is required (one of %v)", pipeline.ReplayableTopics())
	}
	if _, ok := pipeline.SourceTopicFor(*topic); !ok {
		return fmt.Errorf("replay-deadletter: %q is not a known dead-letter topic (want one of %v)", *topic, pipeline.ReplayableTopics())
	}

	b, err := bus.New(cfg.BusMode, cfg.BusBrokers, cfg.BusSecurity())
	if err != nil {
		return fmt.Errorf("replay-deadletter: bus: %w", err)
	}
	defer b.Close()

	res, err := pipeline.NewDeadLetterReplayer(b, log).Replay(context.Background(), pipeline.ReplayConfig{
		DLQTopic:    *topic,
		MaxRecords:  *maxRecords,
		MaxPerSec:   *maxRate,
		IdleTimeout: *idle,
	})
	if err != nil {
		return err
	}
	fmt.Printf("replayed %d record(s) from %s to %s\n", res.Replayed, res.DLQTopic, res.SourceTopic)
	return nil
}
