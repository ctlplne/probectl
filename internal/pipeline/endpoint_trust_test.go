// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// The endpoint/DEM agent's declared trust tier (Foundation-Loop S-3ae8162b,
// threat model B9).
//
// probectl has two agent trust models. The canary agent's tenant comes from its
// mTLS/SPIFFE certificate and the control plane re-stamps it before publishing.
// The endpoint agent asserts its tenant from local YAML, with no certificate,
// and publishes straight to the bus. That tier is accepted deliberately — DEM's
// value is coverage of the real end-user fleet — and the WHOLE containment is
// one rule: the endpoint payload's tenant is never authoritative, because every
// endpoint lane verifies the claim against the agent registry.
//
// So that rule needs a permanent test, and it needs to be stated as a PROPERTY.
// A test listing today's lanes would pass the moment a namespace, a lane or a
// topic is added without `verify` — which is exactly how a declared tier decays
// into an undeclared one.

// TestEndpointLanesAlwaysVerify is the property: every subscription the consumer
// creates on an endpoint topic — base or namespaced, now or later — must be a
// verifying lane.
func TestEndpointLanesAlwaysVerify(t *testing.T) {
	c := &Consumer{
		group:      "trust-tier",
		namespaces: []string{"acme", "globex"},
		nsTenants:  map[string]string{"acme": "tenant-acme", "globex": "tenant-globex"},
	}

	lanes := c.resultTopics()
	seen := 0
	for _, lane := range lanes {
		if !isEndpointTopic(lane.topic) {
			continue
		}
		seen++
		if !lane.verify {
			t.Errorf("lane %q (group %q) carries endpoint traffic without verify: the payload tenant "+
				"would be authoritative, and an endpoint agent asserts its tenant from a local YAML file "+
				"with no certificate", lane.topic, lane.group)
		}
	}
	// Guard against the test passing because it found nothing to check.
	if want := 1 + len(c.namespaces); seen != want {
		t.Fatalf("found %d endpoint lanes, want %d (the base lane plus one per namespace): "+
			"the property was asserted over the wrong set", seen, want)
	}
}

// A namespaced (siloed) endpoint lane must additionally be bound to its lane
// tenant, so a payload claiming another tenant is overwritten rather than
// merely checked.
func TestNamespacedEndpointLanesAreTenantBound(t *testing.T) {
	c := &Consumer{
		group:      "trust-tier",
		namespaces: []string{"acme"},
		nsTenants:  map[string]string{"acme": "tenant-acme"},
	}
	for _, lane := range c.resultTopics() {
		if !isEndpointTopic(lane.topic) || lane.topic == bus.EndpointResultsTopic {
			continue
		}
		if lane.laneTenant == "" {
			t.Errorf("namespaced endpoint lane %q has no authoritative lane tenant: a siloed tenant's "+
				"lane must overwrite the payload's claim, not trust it", lane.topic)
		}
	}
}

// Replay is the path a verifying lane is most easily lost on: a dead-lettered
// record could re-enter through a generic topic and skip the check. The DLQ
// mapping must send endpoint dead letters back into the ENDPOINT lane.
func TestEndpointDeadLettersReplayIntoAVerifyingLane(t *testing.T) {
	c := &Consumer{group: "trust-tier"}
	verifying := map[string]bool{}
	for _, lane := range c.resultTopics() {
		verifying[lane.topic] = lane.verify
	}

	const endpointDLQ = bus.DeadLetterResultsTopic + ".endpoint"
	source, ok := bus.SourceTopicForDeadLetter(endpointDLQ)
	if !ok {
		t.Fatalf("%q has no source-topic mapping: replay would fail closed, but the mapping is the "+
			"mechanism that keeps replay inside the verifying lane", endpointDLQ)
	}
	if !isEndpointTopic(source) {
		t.Fatalf("endpoint dead letters replay into %q: a record that left the endpoint lane must "+
			"re-enter it, or replay becomes the bypass", source)
	}
	if !verifying[source] {
		t.Fatalf("endpoint dead letters replay into %q, which is not a verifying lane: an attacker "+
			"who can get a record dead-lettered would launder an unverified tenant claim through replay", source)
	}
}

// A verifying lane with no binding verifies NOTHING: the payload's tenant claim
// becomes authoritative again, silently. Refusing to start is what makes the
// endpoint trust tier a property of the code rather than a note in a doc — the
// consumer used to subscribe happily and store whatever the payload claimed.
func TestConsumerRefusesToOpenAVerifyingLaneWithoutABinding(t *testing.T) {
	c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "trust-tier", testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.Run(ctx)
	if err == nil {
		t.Fatal("Run started with no tenant binding: the endpoint lane would treat the payload's " +
			"tenant claim as authoritative, and an endpoint agent asserts its tenant from local YAML")
	}
	if !strings.Contains(err.Error(), bus.EndpointResultsTopic) {
		t.Errorf("refusal must name the offending lane, got: %v", err)
	}
}

// The refusal must not fire for a consumer with no verifying lanes: a gate that
// blocks legitimate configurations gets disabled, and then it protects nothing.
func TestConsumerStartsWithABindingInstalled(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	c := NewConsumer(b, tsdb.NewMemory(), "trust-tier", testLogger()).
		WithTenantBinding(allowAllBinding{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	if !b.WaitForSubscribers(ctx, bus.EndpointResultsTopic, 1) {
		cancel()
		t.Fatal("consumer with a binding did not subscribe to the endpoint lane")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("clean shutdown returned %v", err)
	}
}

// isEndpointTopic reports whether a topic carries endpoint/DEM traffic, base or
// namespaced (probectl.<ns>.endpoint.results).
func isEndpointTopic(topic string) bool {
	if topic == bus.EndpointResultsTopic {
		return true
	}
	// Namespaced form shares the trailing segments of the base topic.
	suffix := strings.TrimPrefix(bus.EndpointResultsTopic, "probectl.")
	return strings.HasSuffix(topic, "."+suffix)
}
