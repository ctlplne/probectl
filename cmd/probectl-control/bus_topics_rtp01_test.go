// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
)

// TestBusSharedTopicsCoverEveryProducerTopic is the RTP-01 regression: the
// control plane ensured only a subset of topics at boot, so on a broker with
// auto.create.topics.enable=false the eBPF service map, flow ingest-quality,
// LLDP/CDP neighbors, device collection outcomes, OTLP traces/logs and the
// flow/device/OTLP dead-letters silently lost all data. busSharedTopics() must
// now ensure every topic a shipped producer publishes to, and the per-tenant
// lanes must be namespaced for siloed tenants.
func TestBusSharedTopicsCoverEveryProducerTopic(t *testing.T) {
	// Every topic a producer publishes to (the constants in internal/bus).
	producer := []string{
		bus.NetworkResultsTopic, bus.EndpointResultsTopic, bus.RUMEventsTopic,
		bus.FlowEventsTopic, bus.FlowIngestQualityTopic,
		bus.DeviceMetricsTopic, bus.DeviceNeighborsTopic, bus.DeviceCollectionOutcomesTopic,
		bus.EBPFFlowsTopic, bus.BGPEventsTopic,
		bus.OTLPMetricsTopic, bus.OTLPTracesTopic, bus.OTLPLogsTopic,
		bus.DeadLetterResultsTopic, bus.DeadLetterDeviceTopic, bus.DeadLetterFlowTopic,
		bus.DeadLetterOTLPMetricsTopic, bus.DeadLetterOTLPTracesTopic, bus.DeadLetterOTLPLogsTopic,
	}
	ensured := map[string]bool{}
	for _, tpc := range busSharedTopics() {
		ensured[tpc] = true
	}
	for _, tpc := range producer {
		if !ensured[tpc] {
			t.Errorf("producer topic %q is never ensured at boot (busSharedTopics); on a broker without auto-create this plane silently loses all data (RTP-01)", tpc)
		}
	}

	// The per-tenant data lanes must also exist namespaced for a siloed tenant.
	const ns = "t-abc123"
	lanes := map[string]bool{}
	for _, l := range busLaneTopics([]string{ns}) {
		lanes[l] = true
	}
	for _, base := range []string{
		bus.EBPFFlowsTopic, bus.FlowIngestQualityTopic,
		bus.DeviceNeighborsTopic, bus.DeviceCollectionOutcomesTopic,
		bus.OTLPTracesTopic, bus.OTLPLogsTopic,
	} {
		want, err := bus.TopicFor(ns, base)
		if err != nil {
			t.Fatalf("TopicFor(%s,%s): %v", ns, base, err)
		}
		if !lanes[want] {
			t.Errorf("per-tenant lane %q is not provisioned for a siloed tenant (RTP-01)", want)
		}
	}
}
