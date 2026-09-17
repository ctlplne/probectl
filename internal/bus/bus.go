// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// NetworkResultsTopic is the topic for network-plane probe results (S6). The
// convention is probectl.<type>.results / probectl.<type>.events.
const NetworkResultsTopic = "probectl.network.results"

// BGPEventsTopic carries routing-security signals from the BGP analyzer bridge
// (S14), tenant-tagged via the message key. BGP intentionally has no dead-letter
// topic: a correlation failure is returned to the bus so the source offset stays
// uncommitted and Kafka redelivers the event. Declare a BGP DLQ only alongside a
// real bounded-retry producer and replay consumer.
const BGPEventsTopic = "probectl.bgp.events"

// EBPFFlowsTopic carries L3/L4 flow + service-edge batches from the eBPF host
// agent (S20), tenant-tagged via the message key. Payload: ebpfv1.FlowBatch.
const EBPFFlowsTopic = "probectl.ebpf.flows"

// OTLPMetricsTopic carries OTLP metrics ingested by the OTLP receiver (S22),
// tenant-tagged via the message key. Payload: a marshaled OTLP
// ExportMetricsServiceRequest.
const OTLPMetricsTopic = "probectl.otlp.metrics"

// OTLPTracesTopic / OTLPLogsTopic carry the other two OTLP signals
// (ARCH-001, Sprint 22) — same tenant-keyed contract as metrics.
const (
	OTLPTracesTopic = "probectl.otlp.traces"
	OTLPLogsTopic   = "probectl.otlp.logs"
)

// FlowEventsTopic carries normalized device-flow batches (NetFlow v5/v9, IPFIX,
// sFlow v5) from the flow collector (S38), tenant-tagged via the message key.
// Payload: flowv1.FlowBatch. The control plane consumes it, enriches ASN/geo
// (S15), and persists to ClickHouse (internal/store/flowstore).
const FlowEventsTopic = "probectl.flow.events"

// FlowIngestQualityTopic carries bounded, secret-free current quality
// receipts for ACL-accepted flow exporters. Payload:
// flowv1.FlowIngestQualityBatch.
const FlowIngestQualityTopic = "probectl.flow.ingest-quality"

// DeviceMetricsTopic carries normalized device-telemetry batches (SNMP polls +
// gNMI/OpenConfig subscriptions, S39) from the device collector, tenant-tagged
// via the message key. Payload: devicev1.DeviceMetricBatch. The control plane
// consumes it and lands the samples in the TSDB.
const DeviceMetricsTopic = "probectl.device.metrics"

// DeviceNeighborsTopic carries bounded, read-only LLDP/CDP snapshots from the
// device collector. Payload: devicev1.DeviceNeighborSnapshot.
const DeviceNeighborsTopic = "probectl.device.neighbors"

// DeviceCollectionOutcomesTopic carries bounded per-configured-target
// readiness receipts. Payload: devicev1.DeviceCollectionOutcomeBatch.
const DeviceCollectionOutcomesTopic = "probectl.device.collection-outcomes"

// EndpointResultsTopic carries DEM results from the endpoint agent (S37) — WiFi /
// gateway / last-mile / session signals and the slowdown attribution — tenant-
// tagged via the message key. Payload: resultv1.Result (the canonical canary
// result schema), so it flows through the same pipeline → TSDB path.
const EndpointResultsTopic = "probectl.endpoint.results"

// DeadLetterDeviceTopic receives device-metric messages whose TSDB write
// exhausted retries (Sprint 14, SCALE-008 residual) — tenant-keyed,
// replayable, same contract as the results DLQ.
const DeadLetterDeviceTopic = "probectl.deadletter.device"

// DeadLetterFlowTopic receives flow-event batches whose store insert exhausted
// retries (CORRECT-010 / SCALE-005) — the ORIGINAL flowv1.FlowBatch bytes,
// tenant-keyed, replayable. Same contract as the device + results DLQs: the
// flow plane is now at real parity with the result pipeline, not merely
// claiming to be.
const DeadLetterFlowTopic = "probectl.deadletter.flow"

// DeadLetterResultsTopic receives result messages whose store write failed
// after bounded retries (U-019): the ORIGINAL serialized record, tenant-keyed,
// replayable. Telemetry loss is never silent — dead-lettering is counted and
// logged; operators alert on this topic's depth.
const DeadLetterResultsTopic = "probectl.deadletter.results"

// DeadLetterOTLP{Metrics,Traces,Logs}Topic receive externally-ingested OTLP
// messages whose store write exhausted retries (SCALE-003 / ARCH-002) — the
// ORIGINAL marshaled Export*ServiceRequest, tenant-keyed, replayable. Same
// contract as the results DLQ; one topic PER signal because each replays into
// its own consumer + store (a metrics payload can't be decoded by the trace
// consumer).
const (
	DeadLetterOTLPMetricsTopic = "probectl.deadletter.otlp.metrics"
	DeadLetterOTLPTracesTopic  = "probectl.deadletter.otlp.traces"
	DeadLetterOTLPLogsTopic    = "probectl.deadletter.otlp.logs"
)

// RUMEventsTopic carries real-user page views from the RUM beacon ingest
// (S47b) — validated, consent-gated, PII-redacted at the edge — tenant-tagged
// via the message key. Payload: resultv1.Result (canary_type "rum"; the
// canonical schema), so RUM flows through the same pipeline → TSDB path.
const RUMEventsTopic = "probectl.rum.events"

// Message is one bus record. Key partitions the record (the tenant id, so a
// tenant's results stay ordered and co-located — pooled tenant-tagging).
type Message struct {
	Topic string
	Key   []byte
	Value []byte
}

// Handler processes a consumed message.
type Handler func(ctx context.Context, msg Message) error

// Bus is the result/event transport. Payloads are Protobuf.
type Bus interface {
	// Publish sends value to topic, partitioned by key.
	Publish(ctx context.Context, topic string, key, value []byte) error
	// Subscribe consumes topic in the given consumer group, invoking handler for
	// each message until ctx is canceled. It blocks.
	Subscribe(ctx context.Context, topic, group string, handler Handler) error
	// Close releases resources.
	Close() error
}

// Flusher is an optional Bus capability: block until everything published so
// far is durable/processed (or ctx expires). The async Kafka bus waits for
// broker acknowledgements; the in-memory bus waits until subscriber handlers
// have finished records already accepted by Publish. Callers that need a
// durability barrier before acking upstream (CORRECT-004 / RESIL-002)
// type-assert for it and treat a missing implementation as "already durable".
type Flusher interface {
	Flush(ctx context.Context) error
}

// GroupJanitor is an optional Bus capability: list the consumer groups nobody
// is consuming and delete them (DPR-109). The per-replica view groups are named
// after the process that owns them, so every restart and every rolling upgrade
// abandons a full set of them; without a sweep they accumulate on the broker
// and every lag dashboard reads them as enormous, permanent backlogs. A bus
// that cannot introspect groups simply does not implement this.
type GroupJanitor interface {
	// ListEmptyGroups returns groups the broker reports with no members.
	ListEmptyGroups(ctx context.Context) ([]string, error)
	// DeleteGroups removes groups and their committed offsets, returning the
	// ones actually deleted.
	DeleteGroups(ctx context.Context, groups []string) ([]string, error)
}

// SubscriberWaiter is an optional Bus capability: block until at least n
// subscribers are registered on a topic (or ctx is done). The in-memory bus is
// a LIVE pub/sub — it only delivers to subscribers present at publish time — so
// a producer that starts a consumer goroutine and then publishes must
// SYNCHRONIZE on the consumer's registration rather than sleep a guessed
// duration (TEST-002 / SCALE-003: a fixed sleep is non-deterministic under
// load and silently drops the messages published in the race window). Callers
// type-assert for it; on a bus without it (Kafka, where the broker persists
// and a group joins independently) the wait is unnecessary, so a missing
// implementation is treated as "ready".
type SubscriberWaiter interface {
	WaitForSubscribers(ctx context.Context, topic string, n int) bool
}

// PublishFailureReporter is an optional Bus capability: the cumulative count of
// records that Publish ACCEPTED but that never reached the broker (failed after
// the client's retries, or shed at a full buffer), plus the last such error.
// An asynchronous bus returns nil from Publish long before the broker answers,
// so a producer that wants to know its records were delivered flushes and then
// reads these counters (DPR-071: the eBPF agent published oversized batches for
// hours while logging "emitted" — the rejections were only ever counted here).
type PublishFailureReporter interface {
	PublishFailures() (failed, shed uint64, last error)
}

// namespaceRe is the shape a per-tenant topic namespace must have (S-T2,
// siloed bus isolation): lowercase alphanumerics and hyphens, no dots — it
// becomes one topic segment.
var namespaceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidNamespace reports whether ns can namespace topics ("" = shared).
func ValidNamespace(ns string) bool { return ns == "" || namespaceRe.MatchString(ns) }

// TopicFor namespaces a base topic for a siloed tenant (S-T2):
// TopicFor("t-acme", "probectl.network.results") = "probectl.t-acme.network.results".
// An empty namespace returns the shared topic (pooled). A NON-empty invalid
// namespace is an ERROR (RED-006 — fail closed): a siloed tenant's traffic
// must never silently degrade onto the shared lane because its namespace was
// malformed.
func TopicFor(namespace, base string) (string, error) {
	if namespace == "" {
		return base, nil
	}
	if !namespaceRe.MatchString(namespace) {
		return "", fmt.Errorf("bus: invalid topic namespace %q (must match %s) — refusing shared-lane fallback (RED-006)", namespace, namespaceRe.String())
	}
	rest, ok := strings.CutPrefix(base, "probectl.")
	if !ok {
		return "", fmt.Errorf("bus: topic %q is not namespaceable (no probectl. prefix)", base)
	}
	return "probectl." + namespace + "." + rest, nil
}

// New builds a Bus for the given mode. "memory" (or empty) is the lightweight
// in-process bus; "kafka" requires brokers and enforces the transport policy
// (U-010): TLS (+ optional SASL) unless the explicit dev-only AllowPlaintext
// flag is set.
func New(mode string, brokers []string, sec Security, memOpts ...MemoryOption) (Bus, error) {
	switch mode {
	case "", "memory":
		return NewMemory(memOpts...), nil
	case "kafka":
		if len(brokers) == 0 {
			return nil, errors.New("bus: kafka mode requires PROBECTL_BUS_BROKERS")
		}
		if err := sec.Validate(); err != nil {
			return nil, err
		}
		opts, err := sec.kgoOpts()
		if err != nil {
			return nil, err
		}
		return NewKafka(brokers, sec.MaxBufferedRecords, opts...)
	default:
		return nil, fmt.Errorf("bus: unknown mode %q (want memory|kafka)", mode)
	}
}

// TenantBuckets is the sub-partition fan per tenant (Sprint 15, SCALE-007).
const TenantBuckets = 16

// TenantKey builds the partition key for tenant-owned records. With entropy
// (normally the AGENT id) it appends a stable hash bucket — tenant|bN — so a
// single large tenant spreads across up to TenantBuckets partitions instead
// of hot-spotting one (SCALE-007).
//
// Ordering trade-off, stated: per-tenant TOTAL order narrows to per-bucket
// order. Because the entropy is the agent id, each AGENT's stream keeps its
// FIFO (the order consumers actually rely on — per-key shard dispatch and
// Kafka partition order both follow the key); cross-agent interleaving within
// a tenant was never guaranteed under concurrent agents anyway. Empty entropy
// = the plain tenant key (single-writer planes keep total order).
func TenantKey(tenantID, entropy string) []byte {
	if entropy == "" {
		return []byte(tenantID)
	}
	var h uint32 = 2166136261 // FNV-1a, matching the consumer shard hash
	for i := 0; i < len(entropy); i++ {
		h ^= uint32(entropy[i])
		h *= 16777619
	}
	b := h % TenantBuckets
	return []byte(tenantID + "|b" + string(rune('a'+b)))
}

// TenantFromKey returns the authenticated tenant portion of a bus key produced
// by TenantKey. Plain tenant keys remain valid for single-writer topics. Only
// the exact |b[a-p] suffix is stripped; a malformed suffix stays part of the
// key so downstream tenant/payload comparison rejects it instead of guessing.
func TenantFromKey(key []byte) string {
	s := string(key)
	if len(s) < 3 || s[len(s)-3:len(s)-1] != "|b" {
		return s
	}
	bucket := s[len(s)-1]
	if bucket < 'a' || bucket >= 'a'+TenantBuckets {
		return s
	}
	return s[:len(s)-3]
}

// deadLetterBySource is the bijective lane→dead-letter mapping (Foundation-Loop
// S-f02d4e59). Each ingest lane parks its exhausted records on its OWN
// dead-letter topic, so a dead letter carries its originally-bound lane
// authority and replay re-enters the exact lane it left — the endpoint lane
// re-verifies agent bindings, tenant-bound lanes re-bind, and a record can
// never be laundered into the trusted network lane by a round trip through
// the DLQ. The network lane keeps the legacy shared name so pre-existing
// parked records remain replayable (the replayer re-verifies that residue).
var deadLetterBySource = map[string]string{
	NetworkResultsTopic:  DeadLetterResultsTopic,
	EndpointResultsTopic: DeadLetterResultsTopic + ".endpoint",
	RUMEventsTopic:       DeadLetterResultsTopic + ".rum",
	FlowEventsTopic:      DeadLetterFlowTopic,
	DeviceMetricsTopic:   DeadLetterDeviceTopic,
	OTLPMetricsTopic:     DeadLetterOTLPMetricsTopic,
	OTLPTracesTopic:      DeadLetterOTLPTracesTopic,
	OTLPLogsTopic:        DeadLetterOTLPLogsTopic,
}

// DeadLetterTopicFor returns the dead-letter topic for an ingest lane topic,
// including namespaced (siloed) lanes: a siloed lane's dead letters rest on a
// namespaced DLQ topic under the SAME tenant-bound ACLs as the lane itself,
// never on a pooled topic. Unknown topics are an error (fail closed).
func DeadLetterTopicFor(sourceTopic string) (string, error) {
	if dlq, ok := deadLetterBySource[sourceTopic]; ok {
		return dlq, nil
	}
	ns, base, ok := splitNamespaced(sourceTopic)
	if ok {
		if dlq, mapped := deadLetterBySource[base]; mapped {
			return TopicFor(ns, dlq)
		}
	}
	return "", fmt.Errorf("bus: no dead-letter topic for lane %q (fail closed)", sourceTopic)
}

// SourceTopicForDeadLetter inverts DeadLetterTopicFor, again including
// namespaced dead-letter topics.
func SourceTopicForDeadLetter(dlqTopic string) (string, bool) {
	for src, dlq := range deadLetterBySource {
		if dlq == dlqTopic {
			return src, true
		}
	}
	ns, base, ok := splitNamespaced(dlqTopic)
	if !ok {
		return "", false
	}
	for src, dlq := range deadLetterBySource {
		if dlq == base {
			namespaced, err := TopicFor(ns, src)
			if err != nil {
				return "", false
			}
			return namespaced, true
		}
	}
	return "", false
}

// splitNamespaced decomposes "probectl.<ns>.<rest>" into (ns, "probectl.<rest>")
// when <ns> is a valid namespace and the base is a known probectl topic shape.
func splitNamespaced(topic string) (ns, base string, ok bool) {
	rest, hasPrefix := strings.CutPrefix(topic, "probectl.")
	if !hasPrefix {
		return "", "", false
	}
	seg, tail, found := strings.Cut(rest, ".")
	if !found || !namespaceRe.MatchString(seg) {
		return "", "", false
	}
	return seg, "probectl." + tail, true
}
