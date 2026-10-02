// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/pipeline"
)

// TestBusSharedTopicsCoverEveryProducerTopic is the RTP-01 regression. The
// control plane ensured only a subset of topics, so on a broker with
// auto.create.topics.enable=false the eBPF/flow-quality/neighbors/outcomes/
// OTLP-traces-logs planes and the dead-letter queues silently lost data.
//
// The expected set is DERIVED, not hand-listed — every per-tenant lane, each
// lane's dead-letter topic via bus.DeadLetterTopicFor (which computes the
// endpoint/RUM sub-DLQs and the per-tenant namespaced DLQs at runtime), and the
// replay DLQ set — so a producer topic whose name is computed cannot drift out
// of coverage undetected.
func TestBusSharedTopicsCoverEveryProducerTopic(t *testing.T) {
	ensuredShared := map[string]bool{}
	for _, tpc := range busSharedTopics() {
		ensuredShared[tpc] = true
	}

	expected := map[string]bool{}
	for _, lane := range bus.TenantLaneTopics() {
		expected[lane] = true
		if dlq, err := bus.DeadLetterTopicFor(lane); err == nil {
			expected[dlq] = true
		}
	}
	for _, tpc := range pipeline.ReplayableTopics() {
		expected[tpc] = true
	}
	for tpc := range expected {
		if !ensuredShared[tpc] {
			t.Errorf("producer topic %q is never ensured at boot (busSharedTopics); on a broker without auto-create this plane silently loses data (RTP-01)", tpc)
		}
	}

	// Per-tenant lanes AND their namespaced dead-letters are provisioned for a
	// siloed tenant.
	const ns = "t-abc123"
	laneSet := map[string]bool{}
	for _, l := range busLaneTopics([]string{ns}) {
		laneSet[l] = true
	}
	for _, base := range bus.TenantLaneTopics() {
		lt, err := bus.TopicFor(ns, base)
		if err != nil {
			t.Fatalf("TopicFor(%s,%s): %v", ns, base, err)
		}
		if !laneSet[lt] {
			t.Errorf("per-tenant lane %q is not provisioned for a siloed tenant (RTP-01)", lt)
		}
		if dlq, err := bus.DeadLetterTopicFor(lt); err == nil && !laneSet[dlq] {
			t.Errorf("per-tenant dead-letter %q is not provisioned for a siloed tenant (RTP-01)", dlq)
		}
	}
}
