// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDeadLetterTopicForPooledAndNamespacedLanes (DPR-230): the dead-letter
// mapping is a §7.1 boundary, not a lookup convenience. A siloed lane's dead
// letters must rest on a NAMESPACED DLQ under the same tenant-bound ACLs as the
// lane itself — routing them to the pooled DLQ would put one tenant's rejected
// payloads on a topic every other tenant's consumers can read. An unknown lane
// must fail closed rather than default anywhere.
//
// It had no unit test: the whole function, its inverse, and splitNamespaced were
// at 0% in the service-free lane.
func TestDeadLetterTopicForPooledAndNamespacedLanes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   string
	}{
		{"pooled results", NetworkResultsTopic, DeadLetterResultsTopic},
		{"pooled endpoint", EndpointResultsTopic, DeadLetterResultsTopic + ".endpoint"},
		{"pooled rum", RUMEventsTopic, DeadLetterResultsTopic + ".rum"},
		{"pooled flow", FlowEventsTopic, DeadLetterFlowTopic},
		{"pooled device", DeviceMetricsTopic, DeadLetterDeviceTopic},
		{"pooled otlp metrics", OTLPMetricsTopic, DeadLetterOTLPMetricsTopic},
		{"pooled otlp traces", OTLPTracesTopic, DeadLetterOTLPTracesTopic},
		{"pooled otlp logs", OTLPLogsTopic, DeadLetterOTLPLogsTopic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeadLetterTopicFor(tc.source)
			if err != nil || got != tc.want {
				t.Fatalf("DeadLetterTopicFor(%q) = %q, %v; want %q", tc.source, got, err, tc.want)
			}
			back, ok := SourceTopicForDeadLetter(got)
			if !ok || back != tc.source {
				t.Fatalf("SourceTopicForDeadLetter(%q) = %q, %v; want %q", got, back, ok, tc.source)
			}
		})
	}

	// A siloed lane keeps its namespace on the way to the DLQ, and back.
	const ns = "tenant-a"
	lane, err := TopicFor(ns, FlowEventsTopic)
	if err != nil {
		t.Fatalf("TopicFor: %v", err)
	}
	wantDLQ, err := TopicFor(ns, DeadLetterFlowTopic)
	if err != nil {
		t.Fatalf("TopicFor(dlq): %v", err)
	}
	gotDLQ, err := DeadLetterTopicFor(lane)
	if err != nil || gotDLQ != wantDLQ {
		t.Fatalf("namespaced DLQ = %q, %v; want %q", gotDLQ, err, wantDLQ)
	}
	if gotDLQ == DeadLetterFlowTopic {
		t.Fatalf("CROSS-TENANT: siloed lane %q was routed to the pooled DLQ", lane)
	}
	if back, ok := SourceTopicForDeadLetter(gotDLQ); !ok || back != lane {
		t.Fatalf("SourceTopicForDeadLetter(%q) = %q, %v; want %q", gotDLQ, back, ok, lane)
	}

	// Fail closed on anything not mapped.
	for _, bad := range []string{
		"",
		"probectl.unknown.lane",
		"kafka.internal.topic",
		"probectl.NOT-A-NS.flow.events",
	} {
		if got, err := DeadLetterTopicFor(bad); err == nil {
			t.Errorf("DeadLetterTopicFor(%q) = %q, want an error (fail closed)", bad, got)
		}
	}
	if got, ok := SourceTopicForDeadLetter("probectl.deadletter.nosuch"); ok {
		t.Errorf("SourceTopicForDeadLetter of an unknown DLQ = %q, want not-ok", got)
	}
	if got, ok := SourceTopicForDeadLetter("not.a.probectl.topic"); ok {
		t.Errorf("SourceTopicForDeadLetter of a foreign topic = %q, want not-ok", got)
	}
}

// TestOptionalEnvTuningFallsBackToPackageDefaults (DPR-230): every bus tuning
// knob is optional, and "unset, unparseable, or negative" must all mean "use the
// package default" (zero) rather than a surprising literal. Only the happy path
// was covered.
func TestOptionalEnvTuningFallsBackToPackageDefaults(t *testing.T) {
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset", "", 0},
		{"blank", "   ", 0},
		{"unparseable", "soon", 0},
		{"negative", "-5s", 0},
		{"valid", "1500ms", 1500 * time.Millisecond},
		{"valid with spaces", "  2s  ", 2 * time.Second},
	} {
		if got := durationFromEnv(env(map[string]string{"K": tc.raw}), "K"); got != tc.want {
			t.Errorf("durationFromEnv(%s=%q) = %v, want %v", tc.name, tc.raw, got, tc.want)
		}
	}
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{"unset", "", 0},
		{"blank", "\t", 0},
		{"unparseable", "many", 0},
		{"negative", "-3", 0},
		{"valid", "8", 8},
		{"valid with spaces", " 12 ", 12},
	} {
		if got := intFromEnv(env(map[string]string{"K": tc.raw}), "K"); got != tc.want {
			t.Errorf("intFromEnv(%s=%q) = %d, want %d", tc.name, tc.raw, got, tc.want)
		}
	}
}

// TestNATSCountersAndLagWithoutAServer (DPR-230): the NATS bus's reporting
// surface — PublishFailures, Stats, ConsumerLag and the error wrapping that
// attributes a flush failure to the topic that caused it — is pure struct state
// and needs no broker, so it belongs in the service-free lane. The lag gauge's
// documented decay (the newest sample always wins downward) had no test at all.
func TestNATSCountersAndLagWithoutAServer(t *testing.T) {
	n := &NATS{}

	// Nothing recorded yet: no lag signal, and no last-failure wrapping.
	if _, _, ok := n.ConsumerLag(); ok {
		t.Error("ConsumerLag must report not-ok before any message is delivered")
	}
	if failed, shed, last := n.PublishFailures(); failed != 0 || shed != 0 || last != nil {
		t.Errorf("PublishFailures on a fresh bus = %d, %d, %v; want zeroes and nil", failed, shed, last)
	}
	if err := n.flushError(nil); err != nil {
		t.Errorf("flushError(nil) = %v, want nil", err)
	}
	base := errors.New("flush timed out")
	if err := n.flushError(base); !errors.Is(err, base) {
		t.Errorf("flushError with no recorded failure must return the error unchanged, got %v", err)
	}

	// A recorded failure is attributed to its topic, and stays wrapped.
	cause := errors.New("no responders")
	n.recordFailure(NetworkResultsTopic, cause)
	_, _, last := n.PublishFailures()
	if !errors.Is(last, cause) {
		t.Fatalf("PublishFailures last = %v, want it to wrap the cause", last)
	}
	// The flush error stays in the chain so callers can still match on it, and
	// the last publish failure is attached as text naming its topic — that
	// attribution is the whole point of recordFailure.
	wrapped := n.flushError(base)
	if !errors.Is(wrapped, base) {
		t.Fatalf("flushError = %v, want the flush error still matchable with errors.Is", wrapped)
	}
	for _, want := range []string{NetworkResultsTopic, cause.Error(), base.Error()} {
		if !strings.Contains(wrapped.Error(), want) {
			t.Errorf("flushError text %q must mention %q", wrapped.Error(), want)
		}
	}

	// Counters are reported as they stand.
	n.produced.Store(9)
	n.failed.Store(2)
	n.shed.Store(3)
	n.handlerErr.Store(4)
	n.inflight.Store(5)
	if got := n.Stats(); got != (PublishStats{Produced: 9, Failed: 2, Shed: 3, Buffered: 5, HandlerErrors: 4}) {
		t.Errorf("Stats = %+v", got)
	}

	// Lag rises to the highest pending seen, then follows the newest sample down.
	n.recordLag(7)
	if peak, assignments, ok := n.ConsumerLag(); !ok || peak != 7 || assignments != 1 {
		t.Fatalf("ConsumerLag after 7 = %d, %d, %v; want 7, 1, true", peak, assignments, ok)
	}
	n.recordLag(11)
	if peak, _, _ := n.ConsumerLag(); peak != 11 {
		t.Fatalf("ConsumerLag after a higher sample = %d, want 11", peak)
	}
	n.recordLag(2)
	if peak, _, _ := n.ConsumerLag(); peak != 2 {
		t.Fatalf("ConsumerLag must decay to the newest sample, got %d, want 2", peak)
	}

	// The worker option is bounded: a non-positive value keeps the default.
	n.workers = 3
	if got := n.WithSubscribeWorkers(0); got != n || n.workers != 3 {
		t.Errorf("WithSubscribeWorkers(0) changed workers to %d, want the 3 it had", n.workers)
	}
	if got := n.WithSubscribeWorkers(-1); got != n || n.workers != 3 {
		t.Errorf("WithSubscribeWorkers(-1) changed workers to %d, want the 3 it had", n.workers)
	}
	if got := n.WithSubscribeWorkers(6); got != n || n.workers != 6 {
		t.Errorf("WithSubscribeWorkers(6) set workers to %d, want 6", n.workers)
	}
}

// TestKafkaSubscribeWorkersOption (DPR-230): the Kafka twin of the option above,
// which was also uncovered without a broker.
func TestKafkaSubscribeWorkersOption(t *testing.T) {
	k := &Kafka{}
	if got := k.WithSubscribeWorkers(4); got != k || k.workers != 4 {
		t.Fatalf("WithSubscribeWorkers(4) set workers to %d, want 4", k.workers)
	}
	if got := k.WithSubscribeFromEnd(); got != k || !k.consumeFromEnd {
		t.Fatalf("WithSubscribeFromEnd did not set consumeFromEnd")
	}
}

// TestNATSWithNoReachableBrokerFailsClosed (DPR-230) is the unit-level statement
// of the defect DPR-220 fixed in CI: NewNATS uses RetryOnFailedConnect, so
// CONSTRUCTION SUCCEEDS against a server that is not there. That is by design —
// a restarting broker must not take the control plane down — but it means
// "the bus object exists" is not evidence that a broker does, and every caller
// has to learn that from the publish path instead.
//
// So this pins the degraded contract without needing a server: the defaults a
// zero policy inherits, that an empty server list is refused outright, and that
// publishing with nothing listening FAILS and is ACCOUNTED — never silently
// accepted.
func TestNATSWithNoReachableBrokerFailsClosed(t *testing.T) {
	if _, err := NewNATS(nil, StreamPolicy{}, 0); err == nil {
		t.Fatal("NewNATS with no servers must be refused")
	}
	if _, err := NewNATS([]string{}, StreamPolicy{}, 0); err == nil {
		t.Fatal("NewNATS with an empty server list must be refused")
	}

	// RFC 6761 reserves .invalid, so this can never resolve to a real broker.
	b, err := NewNATS([]string{"nats://no-such-broker.invalid:4222"}, StreamPolicy{}, 0)
	if err != nil {
		t.Fatalf("NewNATS is documented to tolerate an unreachable server, got %v", err)
	}
	defer func() { _ = b.Close() }()

	// A zero policy inherits the package defaults, and maxPending is clamped.
	if b.stream.MaxAge != defaultNATSMaxAge || b.stream.Replicas != 1 ||
		b.stream.InactiveThreshold != defaultNATSInactiveThreshold {
		t.Errorf("zero StreamPolicy did not inherit defaults: %+v", b.stream)
	}
	if b.maxPending != defaultNATSMaxPending {
		t.Errorf("maxPending = %d, want the %d default", b.maxPending, defaultNATSMaxPending)
	}
	if b.workers != 1 {
		t.Errorf("workers = %d, want 1", b.workers)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Publishing with no broker must return an error AND be counted, so an
	// operator sees it in Stats/PublishFailures rather than assuming delivery.
	if err := b.Publish(ctx, NetworkResultsTopic, []byte("k"), []byte("v")); err == nil {
		t.Fatal("Publish with no reachable broker must not report success")
	}
	if got := b.Stats(); got.Failed == 0 && got.Shed == 0 {
		t.Errorf("a failed publish must be accounted, Stats = %+v", got)
	}
	failed, _, last := b.PublishFailures()
	if failed == 0 || last == nil {
		t.Errorf("PublishFailures = %d, %v; want the failure and its cause", failed, last)
	}
	if !strings.Contains(last.Error(), NetworkResultsTopic) {
		t.Errorf("the recorded failure %q must name the topic it was for", last.Error())
	}

	// Topic administration fails closed too, rather than reporting an empty
	// cluster as "nothing missing".
	if _, err := b.TopicsMissing(ctx, []string{NetworkResultsTopic}); err == nil {
		t.Error("TopicsMissing with no reachable broker must return an error, not an empty answer")
	}
	if _, err := b.EnsureTopics(ctx, []string{NetworkResultsTopic}, 1, 1); err == nil {
		t.Error("EnsureTopics with no reachable broker must return an error")
	}
	if missing, err := b.TopicsMissing(ctx, nil); err != nil || missing != nil {
		t.Errorf("TopicsMissing(nil) = %v, %v; want no work and no error", missing, err)
	}

	// Consumer-group housekeeping fails closed as well. DPR-109's janitor DELETES
	// what ListEmptyGroups reports, so an unreachable broker answering "no groups"
	// would be harmless — but an unreachable broker answering "these are empty"
	// would not, and neither may be inferred from silence.
	if groups, err := b.ListEmptyGroups(ctx); err == nil {
		t.Errorf("ListEmptyGroups with no reachable broker = %v, want an error", groups)
	}
	if deleted, err := b.DeleteGroups(ctx, []string{"itest-group"}); err == nil {
		t.Errorf("DeleteGroups with no reachable broker = %v, want an error", deleted)
	}
	if deleted, err := b.DeleteGroups(ctx, nil); err != nil || deleted != nil {
		t.Errorf("DeleteGroups(nil) = %v, %v; want no work and no error", deleted, err)
	}

	// A canceled context is refused before any network work.
	dead, stop := context.WithCancel(context.Background())
	stop()
	if err := b.Publish(dead, NetworkResultsTopic, nil, []byte("v")); !errors.Is(err, context.Canceled) {
		t.Errorf("Publish with a canceled context = %v, want context.Canceled", err)
	}
}

// TestKafkaGroupJanitorFailsClosedWithoutBrokers (DPR-230) is the Kafka twin of
// the housekeeping half above. Same reason: the janitor deletes committed
// offsets, so "the brokers did not answer" must never read as an answer.
func TestKafkaGroupJanitorFailsClosedWithoutBrokers(t *testing.T) {
	k, err := NewKafka([]string{"no-such-broker.invalid:9092"}, 0)
	if err != nil {
		t.Skipf("NewKafka refused an unreachable broker up front, which is also fail-closed: %v", err)
	}
	defer k.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if groups, err := k.ListEmptyGroups(ctx); err == nil {
		t.Errorf("ListEmptyGroups with no reachable broker = %v, want an error", groups)
	}
	if deleted, err := k.DeleteGroups(ctx, []string{"itest-group"}); err == nil {
		t.Errorf("DeleteGroups with no reachable broker = %v, want an error", deleted)
	}
	if deleted, err := k.DeleteGroups(ctx, nil); err != nil || deleted != nil {
		t.Errorf("DeleteGroups(nil) = %v, %v; want no work and no error", deleted, err)
	}
}
