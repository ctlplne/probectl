// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
)

// busTopicEnsurer is what a broker-backed bus offers for DPR-047; the memory
// bus has no topics to create and is skipped.
type busTopicEnsurer interface {
	EnsureTopics(ctx context.Context, topics []string, partitions int32, replication int16) ([]string, error)
	TopicsMissing(ctx context.Context, topics []string) ([]string, error)
}

// busSharedTopics are the lanes every deployment publishes or consumes.
func busSharedTopics() []string {
	return []string{
		bus.NetworkResultsTopic, bus.EndpointResultsTopic, bus.RUMEventsTopic,
		bus.FlowEventsTopic, bus.DeviceMetricsTopic, bus.BGPEventsTopic,
		bus.OTLPMetricsTopic, bus.DeadLetterResultsTopic,
	}
}

// busLaneTopics are the namespaced copies of the tenant-facing lanes for the
// given siloed/hybrid tenant namespaces (probectl.<namespace>.<lane>).
func busLaneTopics(namespaces []string) []string {
	bases := []string{
		bus.NetworkResultsTopic, bus.EndpointResultsTopic, bus.RUMEventsTopic,
		bus.FlowEventsTopic, bus.DeviceMetricsTopic, bus.BGPEventsTopic, bus.OTLPMetricsTopic,
	}
	var out []string
	for _, ns := range namespaces {
		if !bus.ValidNamespace(ns) || ns == "" {
			continue
		}
		for _, base := range bases {
			if t, err := bus.TopicFor(ns, base); err == nil {
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ensureBusTopics (DPR-047) makes the plane's lanes exist before anything
// publishes to them. With PROBECTL_BUS_CREATE_TOPICS=true it creates what is
// missing and says so; with false it only verifies and fails closed naming
// the missing topics. Before this the client neither created nor asked the
// broker to auto-create a lane, so on a fresh Kafka every result batch was
// refused with "publish not durable" and nothing said why.
func ensureBusTopics(ctx context.Context, b bus.Bus, cfg *config.Config, log *slog.Logger, topics []string) error {
	ensurer, ok := b.(busTopicEnsurer)
	if !ok || len(topics) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !cfg.BusCreateTopics {
		missing, err := ensurer.TopicsMissing(ctx, topics)
		if err != nil {
			return fmt.Errorf("bus topics: %w", err)
		}
		if len(missing) > 0 {
			return fmt.Errorf("bus topics: PROBECTL_BUS_CREATE_TOPICS=false and these topics do not exist on the brokers: %s (create them, or let the control plane do it with PROBECTL_BUS_CREATE_TOPICS=true; docs/deploying-agents.md#bus-topics)", strings.Join(missing, ", "))
		}
		return nil
	}
	created, err := ensurer.EnsureTopics(ctx, topics, int32(cfg.BusTopicPartitions), int16(cfg.BusTopicReplication))
	if err != nil {
		return fmt.Errorf("bus topics: %w — grant the bus user CREATE on probectl.*, or pre-create the lanes and set PROBECTL_BUS_CREATE_TOPICS=false (docs/deploying-agents.md#bus-topics)", err)
	}
	if len(created) > 0 {
		log.Info("bus topics created", "topics", created, "partitions", cfg.BusTopicPartitions, "replication", cfg.BusTopicReplication)
	}
	return nil
}

// laneTopicEnsurer is installed once the bus exists and is called by the bus
// lane supervisors whenever the set of siloed namespaces is (re)loaded, so a
// tenant provisioned at runtime gets its lanes without a restart. Failures
// are logged, never fatal: shared lanes keep flowing.
var laneTopicEnsurer struct {
	mu   sync.Mutex
	fn   func(ctx context.Context, namespaces []string) error
	last string
}

func installLaneTopicEnsurer(b bus.Bus, cfg *config.Config, log *slog.Logger) {
	laneTopicEnsurer.mu.Lock()
	defer laneTopicEnsurer.mu.Unlock()
	laneTopicEnsurer.last = ""
	laneTopicEnsurer.fn = func(ctx context.Context, namespaces []string) error {
		return ensureBusTopics(ctx, b, cfg, log, busLaneTopics(namespaces))
	}
}

func ensureLaneTopics(ctx context.Context, log *slog.Logger, namespaces []string) {
	laneTopicEnsurer.mu.Lock()
	fn := laneTopicEnsurer.fn
	key := strings.Join(namespaces, "\n")
	if fn == nil || key == laneTopicEnsurer.last {
		laneTopicEnsurer.mu.Unlock()
		return
	}
	laneTopicEnsurer.last = key
	laneTopicEnsurer.mu.Unlock()
	if err := fn(ctx, namespaces); err != nil {
		log.Error("isolation: could not ensure tenant bus lanes; siloed producers may be refused until the topics exist", "namespaces", namespaces, "error", err.Error())
		laneTopicEnsurer.mu.Lock()
		laneTopicEnsurer.last = "" // retry on the next refresh
		laneTopicEnsurer.mu.Unlock()
	}
}
