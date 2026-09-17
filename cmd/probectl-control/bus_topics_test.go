// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
)

// TestEnsureBusTopicsCreatesLanesOrFailsClosed (DPR-047): on a fresh broker
// the plane creates its shared lanes (idempotently), the verify-only mode
// names what is missing instead of letting the first batch time out, and the
// memory bus is untouched.
func TestEnsureBusTopicsCreatesLanesOrFailsClosed(t *testing.T) {
	cluster, err := kfake.NewCluster()
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	b, err := bus.NewKafka(cluster.ListenAddrs(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	verifyOnly := &config.Config{BusCreateTopics: false, BusTopicPartitions: 1, BusTopicReplication: -1}
	err = ensureBusTopics(ctx, b, verifyOnly, log, busSharedTopics())
	if err == nil || !strings.Contains(err.Error(), "PROBECTL_BUS_CREATE_TOPICS=false") || !strings.Contains(err.Error(), bus.NetworkResultsTopic) {
		t.Fatalf("verify-only mode must fail closed naming the missing lanes, got %v", err)
	}

	create := &config.Config{BusCreateTopics: true, BusTopicPartitions: 2, BusTopicReplication: -1}
	if err := ensureBusTopics(ctx, b, create, log, busSharedTopics()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ensureBusTopics(ctx, b, verifyOnly, log, busSharedTopics()); err != nil {
		t.Fatalf("after creation the verify-only mode must pass: %v", err)
	}
	if missing, err := b.TopicsMissing(ctx, busSharedTopics()); err != nil || len(missing) != 0 {
		t.Fatalf("shared lanes still missing: %v %v", missing, err)
	}

	// Tenant lanes follow the namespace set; invalid namespaces are skipped.
	lanes := busLaneTopics([]string{"t-globex-eu", "", "not valid!"})
	if len(lanes) != 7 || lanes[0] != "probectl.t-globex-eu.bgp.events" {
		t.Fatalf("lane topics = %v", lanes)
	}
	installLaneTopicEnsurer(b, create, log)
	ensureLaneTopics(ctx, log, []string{"t-globex-eu"})
	if missing, err := b.TopicsMissing(ctx, lanes); err != nil || len(missing) != 0 {
		t.Fatalf("tenant lanes still missing: %v %v", missing, err)
	}

	if err := ensureBusTopics(ctx, bus.NewMemory(), verifyOnly, log, busSharedTopics()); err != nil {
		t.Fatalf("memory bus has nothing to create: %v", err)
	}
}
