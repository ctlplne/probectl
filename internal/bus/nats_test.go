// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"strings"
	"testing"
)

// TestDurableLightweightModeIsRefusedInTheClear (DPR-119): the durable
// lightweight transport exists so a small deployment does not need Kafka. It
// does NOT exist so a small deployment can skip TLS: "smaller" and "plaintext"
// are different words, and the product had already conflated "lightweight" with
// "volatile" once.
func TestDurableLightweightModeIsRefusedInTheClear(t *testing.T) {
	if _, err := New("nats", []string{"nats://b1:4222"}, Security{}); err == nil ||
		!strings.Contains(err.Error(), "without TLS is refused") {
		t.Fatalf("plaintext nats must be refused, got %v", err)
	}
	if _, err := New("nats", nil, Security{TLSEnabled: true}); err == nil ||
		!strings.Contains(err.Error(), "PROBECTL_BUS_BROKERS") {
		t.Fatalf("nats without servers must be refused, got %v", err)
	}
	// A Kafka SASL mechanism NATS cannot use is refused rather than ignored: a
	// credential the server never sees is the same as no credential.
	sec := Security{TLSEnabled: true, SASLMechanism: "scram-sha-512", SASLUser: "u", SASLPassword: "p"}
	if _, err := sec.natsOpts(); err == nil || !strings.Contains(err.Error(), "NATS cannot use") {
		t.Fatalf("a SCRAM mechanism must be refused for nats, got %v", err)
	}
	// Plain credentials and TLS render without complaint.
	ok := Security{TLSEnabled: true, SASLMechanism: "plain", SASLUser: "u", SASLPassword: "p"}
	opts, err := ok.natsOpts()
	if err != nil {
		t.Fatalf("plain credentials must render: %v", err)
	}
	if len(opts) != 2 {
		t.Errorf("expected TLS and credentials options, got %d", len(opts))
	}
}

// TestUnknownBusModeNamesTheThreeThatExist (DPR-119).
func TestUnknownBusModeNamesTheThreeThatExist(t *testing.T) {
	_, err := New("redis", []string{"x"}, Security{})
	if err == nil || !strings.Contains(err.Error(), "memory|nats|kafka") {
		t.Fatalf("an unknown mode must name the modes that exist, got %v", err)
	}
}

// TestSubjectAndDurableNamesSurviveTheTopicVocabulary (DPR-119): JetStream
// stream and consumer names cannot contain the dots that every probectl topic
// has, and a per-tenant lane must stay a lane of its own after the mapping —
// two tenants whose topics collapsed to one stream would share a lane.
func TestSubjectAndDurableNamesSurviveTheTopicVocabulary(t *testing.T) {
	seen := map[string]string{}
	for _, topic := range []string{
		NetworkResultsTopic, BGPEventsTopic, EBPFFlowsTopic, FlowEventsTopic,
		DeviceMetricsTopic, OTLPMetricsTopic, OTLPTracesTopic, OTLPLogsTopic,
		RUMEventsTopic,
		"probectl.t-acme-industries.ebpf.flows",
		"probectl.t-globex-eu.ebpf.flows",
	} {
		name := streamName(topic)
		if strings.ContainsAny(name, ".*> ") {
			t.Errorf("%q maps to %q, which JetStream cannot name", topic, name)
		}
		if prev, ok := seen[name]; ok {
			t.Errorf("%q and %q both map to %q: two lanes would share one stream", prev, topic, name)
		}
		seen[name] = topic
	}
	// Consumer groups carry the same restriction, including the per-replica
	// view groups whose names contain a pod name (DPR-109).
	for _, group := range []string{
		"topology-ebpf-probectl-6c7fcf9b4b-zxw8c-t-acme-industries",
		"compliance-flow",
		"ndr-flow-t-globex-eu",
	} {
		if d := durableName(group); strings.ContainsAny(d, ".*> ") {
			t.Errorf("group %q maps to %q, which JetStream cannot name", group, d)
		}
	}
}

// TestDedupeKeepsOneOfEach guards the sweep's listing helper.
func TestDedupeKeepsOneOfEach(t *testing.T) {
	got := dedupe([]string{"a", "a", "b", "b", "b", "c"})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("dedupe = %v", got)
	}
	if got := dedupe(nil); got != nil {
		t.Errorf("dedupe(nil) = %v", got)
	}
}
