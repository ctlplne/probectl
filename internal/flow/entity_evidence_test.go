// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

type recordedFlowFaults struct {
	batches [][]entity.FaultObservation
	fail    bool
}

func (*recordedFlowFaults) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, nil
}

func (r *recordedFlowFaults) SubmitFaults(_ context.Context, faults []entity.FaultObservation) (int, error) {
	r.batches = append(r.batches, append([]entity.FaultObservation(nil), faults...))
	if r.fail {
		return 0, errors.New("lost response")
	}
	return len(faults), nil
}

func TestFlowStaleFaultUsesConfiguredExporterAndRetriesOneUUID(t *testing.T) {
	base := time.Now().UTC()
	current := base
	recorded := &recordedFlowFaults{fail: true}
	c := &Collector{cfg: &Config{TenantID: "tenant-a", AgentID: "flow-agent-a"},
		evidence: recorded, evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock: func() time.Time { return current }}
	receipts := []QualityReceipt{
		{ExporterAddress: "192.0.2.7", State: QualityStateStale,
			Reason: QualityReasonNoRecentPackets},
		{ExporterAddress: "192.0.2.7", State: QualityStateStale,
			Reason: QualityReasonNoRecentPackets},
		{ExporterAddress: "192.0.2.8", State: QualityStateStale,
			Reason: QualityReasonNoRecentPackets},
		{ExporterAddress: "192.0.2.9", State: QualityStateHealthy},
	}
	last := map[string]time.Time{}
	pending := map[string]entity.FaultObservation{}
	c.sendFlowFaults(context.Background(), receipts, last, pending)
	if len(recorded.batches) != 1 || len(recorded.batches[0]) != 1 ||
		recorded.batches[0][0].Source != (entity.SourceKey{AgentID: "flow-agent-a",
			Kind: entity.FlowExporter, SourceRef: "192.0.2.7"}) {
		t.Fatalf("unconfigured or duplicate exporter authored a fault: %+v", recorded.batches)
	}
	first := recorded.batches[0][0]
	current = base.Add(time.Minute)
	recorded.fail = false
	c.sendFlowFaults(context.Background(), receipts, last, pending)
	if len(recorded.batches) != 2 || recorded.batches[1][0].ID != first.ID ||
		!recorded.batches[1][0].ObservedAt.Equal(first.ObservedAt) || len(pending) != 0 {
		t.Fatalf("lost response did not retry same durable fault receipt: %+v", recorded.batches)
	}
	current = base.Add(2 * time.Minute)
	c.sendFlowFaults(context.Background(), receipts, last, pending)
	if len(recorded.batches) != 2 {
		t.Fatal("stale exporter generated a new fault every quality tick")
	}
	current = base.Add(3 * time.Minute)
	mixed := append(append([]QualityReceipt(nil), receipts...), QualityReceipt{
		ExporterAddress: "192.0.2.7", State: QualityStateHealthy})
	c.sendFlowFaults(context.Background(), mixed, last, pending)
	if len(recorded.batches) != 2 || len(last) != 0 {
		t.Fatal("a live flow protocol was reported as exporter silence")
	}
	current = base.Add(4 * time.Minute)
	c.sendFlowFaults(context.Background(), receipts, last, pending)
	if len(recorded.batches) != 3 || recorded.batches[2][0].ID == first.ID {
		t.Fatal("a new outage after recovery retained the previous outage throttle")
	}
	current = base.Add(4*time.Minute + flowFaultRefresh)
	c.sendFlowFaults(context.Background(), receipts, last, pending)
	if len(recorded.batches) != 4 || recorded.batches[3][0].ID == recorded.batches[2][0].ID {
		t.Fatal("persistent exporter outage was not refreshed within correlation window")
	}
}

func TestFlowQualityQueuesOnlyConfiguredExportersWithoutWaitingOnEvidenceRPC(t *testing.T) {
	at := time.Now().UTC()
	raw := &qualityCaptureEmitter{}
	seenAt := at.Add(-QualityStaleAfter - time.Second)
	window := func() *qualityWindow {
		return &qualityWindow{windowStartedAt: seenAt.Add(-time.Minute),
			lastPacketAt: seenAt, lastValidRecordAt: seenAt,
			packetsReceived: 1, recordsDecoded: 1,
			templateState: QualityTemplateReady, samplingState: QualitySamplingUnsampled}
	}
	c := &Collector{cfg: &Config{TenantID: "tenant-a", AgentID: "flow-agent-a"},
		emit: raw, evidence: &recordedFlowFaults{},
		evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		faultQueue:      make(chan []QualityReceipt, 1),
		quality: map[qualityKey]*qualityWindow{
			{exporter: "192.0.2.7", protocol: ProtoIPFIX}: window(),
			{exporter: "192.0.2.8", protocol: ProtoIPFIX}: window(),
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.emitQualityReceipts(context.Background(), at)
	if len(raw.receipts) != 2 {
		t.Fatalf("raw quality receipt path was blocked by optional fault: %d", len(raw.receipts))
	}
	select {
	case queued := <-c.faultQueue:
		if len(queued) != 1 || queued[0].ExporterAddress != "192.0.2.7" ||
			queued[0].State != QualityStateStale {
			t.Fatalf("unconfigured exporter entered fault worker: %+v", queued)
		}
	default:
		t.Fatal("real stale quality window was not queued for sender-bound fault")
	}
}

func TestFlowQualityInvalidLiveProtocolSuppressesSilenceFault(t *testing.T) {
	at := time.Now().UTC()
	raw := &qualityCaptureEmitter{}
	staleAt := at.Add(-QualityStaleAfter - time.Second)
	c := &Collector{cfg: &Config{TenantID: "tenant-a", AgentID: "flow-agent-a"},
		emit: raw, evidence: &recordedFlowFaults{},
		evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		faultQueue:      make(chan []QualityReceipt, 1),
		quality: map[qualityKey]*qualityWindow{
			{exporter: "192.0.2.7", protocol: ProtoIPFIX}: {
				windowStartedAt: staleAt.Add(-time.Minute), lastPacketAt: staleAt,
				lastValidRecordAt: staleAt, packetsReceived: 1, recordsDecoded: 1,
				templateState: QualityTemplateReady, samplingState: QualitySamplingUnsampled,
			},
			{exporter: "192.0.2.7", protocol: ProtoNetFlow5}: {
				windowStartedAt: at.Add(-time.Minute), lastPacketAt: at,
				lastValidRecordAt: at, packetsReceived: 1, recordsDecoded: 1,
				templateState: QualityTemplateReady, samplingState: QualitySamplingUnsampled,
			},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.emitQualityReceipts(context.Background(), at)
	if len(raw.receipts) != 1 || raw.receipts[0].Protocol != ProtoIPFIX {
		t.Fatalf("valid raw quality receipt was lost: %+v", raw.receipts)
	}
	select {
	case queued := <-c.faultQueue:
		t.Fatalf("invalid live protocol became exporter silence: %+v", queued)
	default:
	}
}

func TestFlowRecoveryAfterQueuedStaleWindowSuppressesFault(t *testing.T) {
	now := time.Now().UTC()
	staleWindowEnd := now.Add(-time.Minute)
	recorded := &recordedFlowFaults{}
	c := &Collector{cfg: &Config{AgentID: "flow-agent-a"}, evidence: recorded,
		evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		quality: map[qualityKey]*qualityWindow{
			{exporter: "192.0.2.7", protocol: ProtoIPFIX}: {
				lastPacketAt: now.Add(-time.Second),
			},
		},
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock: func() time.Time { return now }}
	last := map[string]time.Time{"192.0.2.7": now.Add(-flowFaultRefresh)}
	pending := map[string]entity.FaultObservation{"192.0.2.7": {ID: "pending"}}
	c.sendFlowFaults(context.Background(), []QualityReceipt{{
		ExporterAddress: "192.0.2.7", WindowEndedAt: staleWindowEnd,
		State: QualityStateStale, Reason: QualityReasonNoRecentPackets,
	}}, last, pending)
	if len(recorded.batches) != 0 || len(last) != 0 || len(pending) != 0 {
		t.Fatalf("late stale batch authored an outage after packet recovery: %+v", recorded.batches)
	}
}

func TestFlowQualityEvictionAfterQueuedWindowSuppressesSilenceFault(t *testing.T) {
	base := time.Now().UTC()
	now := base
	recorded := &recordedFlowFaults{}
	c := &Collector{cfg: &Config{AgentID: "flow-agent-a"}, evidence: recorded,
		evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		quality:         make(map[qualityKey]*qualityWindow),
		log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:           func() time.Time { return now }}
	for i := 0; i < MaxQualityReceiptsPerAgent-1; i++ {
		c.quality[qualityKey{exporter: fmt.Sprintf("198.%d.%d.%d", i/65536, (i/256)%256, i%256),
			protocol: ProtoIPFIX}] = &qualityWindow{lastPacketAt: base.Add(-time.Hour)}
	}
	// The recovery packet is present, then capacity churn evicts it before
	// the worker consumes its prior stale snapshot.
	c.observeQualityPacket("192.0.2.7", ProtoIPFIX, base, nil, 0, false)
	for i := 0; i < MaxQualityReceiptsPerAgent; i++ {
		c.observeQualityPacket(fmt.Sprintf("203.%d.%d.%d", i/65536, (i/256)%256, i%256), ProtoIPFIX,
			base.Add(time.Second+time.Duration(i)*time.Nanosecond), nil, 0, false)
	}
	if _, retained := c.quality[qualityKey{exporter: "192.0.2.7", protocol: ProtoIPFIX}]; retained {
		t.Fatal("fixture did not evict the recovery packet")
	}
	if !c.qualityEvictedAt.After(base) {
		t.Fatal("quality eviction was not recorded for the optional fault worker")
	}
	now = base.Add(2 * time.Second)
	stale := QualityReceipt{ExporterAddress: "192.0.2.7",
		WindowStartedAt: base.Add(-time.Minute), WindowEndedAt: base.Add(-time.Second),
		State: QualityStateStale, Reason: QualityReasonNoRecentPackets}
	last := map[string]time.Time{}
	pending := map[string]entity.FaultObservation{}
	c.sendFlowFaults(context.Background(), []QualityReceipt{stale}, last, pending)
	if len(recorded.batches) != 0 || len(pending) != 0 {
		t.Fatalf("evicted recovery packet became exporter silence: %+v", recorded.batches)
	}
	now = base.Add(2 * time.Minute)
	stale.WindowStartedAt = now.Add(-time.Minute)
	stale.WindowEndedAt = now
	c.sendFlowFaults(context.Background(), []QualityReceipt{stale}, last, pending)
	if len(recorded.batches) != 1 || len(recorded.batches[0]) != 1 {
		t.Fatalf("complete later stale window did not authorize a fault: %+v", recorded.batches)
	}
}

type unresolvedFlowEvidence struct{ calls chan int }

func (e unresolvedFlowEvidence) Submit(_ context.Context, claims []entity.Observation) (int, int, error) {
	e.calls <- len(claims)
	return 0, len(claims), nil
}

func TestWhollyUnresolvedFlowEvidenceRetriesAfterOneMinute(t *testing.T) {
	const agent = "22222222-2222-4222-8222-222222222222"
	base := time.Now().UTC()
	var clockNanos atomic.Int64
	clockNanos.Store(base.UnixNano())
	calls := make(chan int, 2)
	c := &Collector{cfg: &Config{AgentID: agent}, evidence: unresolvedFlowEvidence{calls: calls},
		evidenceQueue: make(chan []Record, 1), evidenceReset: make(chan struct{}, 1),
		evidenceSources: map[string]struct{}{"192.0.2.7": {}},
		log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:           func() time.Time { return time.Unix(0, clockNanos.Load()) }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.evidenceLoop(ctx) }()
	defer func() { cancel(); <-done }()
	send := func(at time.Time) {
		t.Helper()
		c.evidenceQueue <- []Record{{Exporter: "192.0.2.7", Protocol: ProtoIPFIX,
			ObservationDomain: 7, ObservedAt: at}}
		select {
		case count := <-calls:
			if count != 2 {
				t.Fatalf("unresolved flow claims = %d, want address and exporter", count)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("wholly unresolved flow evidence did not retry")
		}
	}
	send(base)
	clockNanos.Store(base.Add(flowEvidenceRetry).UnixNano())
	send(base.Add(flowEvidenceRetry))
}

func TestFlowEvidenceRequiresExactConfiguredExporter(t *testing.T) {
	base := EvidenceConfig{ControlAddr: "control:443", RotateURL: "https://control:8443", CertFile: "cert", KeyFile: "key",
		CAFile: "ca", Exporters: []string{"192.0.2.7"}}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, exporters := range [][]string{
		{"192.0.2.0/24"}, {"0.0.0.0"}, {"ff02::1"},
		{"192.0.2.7", "::ffff:192.0.2.7"},
	} {
		cfg := base
		cfg.Exporters = exporters
		if err := cfg.validate(); err == nil {
			t.Fatalf("accepted non-exact/duplicate exporter %v", exporters)
		}
	}
	base.KeyFile = ""
	if err := base.validate(); err == nil {
		t.Fatal("accepted partial evidence credential config")
	}
	base.KeyFile = "key"
	base.RotateURL = ""
	if err := base.validate(); err == nil {
		t.Fatal("accepted evidence channel without certificate renewal")
	}
	cfg := Default()
	cfg.TenantID = "11111111-1111-4111-8111-111111111111"
	cfg.CloudImport = CloudImportConfig{Provider: ProtoAWSVPCFlowLogs, Path: "-"}
	cfg.Evidence = EvidenceConfig{ControlAddr: "control:443", RotateURL: "https://control:8443", CertFile: "cert",
		KeyFile: "key", CAFile: "ca", Exporters: []string{"192.0.2.7"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("cloud import silently ignored configured exporter evidence")
	}
}

func TestFlowEvidenceClaimsAreBoundedAndDoNotUseUnlistedExporter(t *testing.T) {
	const agent = "22222222-2222-4222-8222-222222222222"
	c := &Collector{cfg: &Config{AgentID: agent},
		evidenceSources: map[string]struct{}{"192.0.2.7": {}}}
	now := time.Now().UTC()
	batch := []Record{{Exporter: "192.0.2.8", Protocol: ProtoIPFIX,
		ObservationDomain: 99, ObservedAt: now},
		{Exporter: "192.0.2.7", Protocol: "unknown", ObservationDomain: 98, ObservedAt: now}}
	for i := uint32(0); i < 40; i++ {
		batch = append(batch, Record{Exporter: "192.0.2.7", Protocol: ProtoIPFIX,
			ObservationDomain: i, ObservedAt: now})
	}
	claims, keys := c.flowEvidenceClaims(batch, nil, nil, nil, now)
	if len(claims) != 64 || len(keys) != 32 {
		t.Fatalf("claims/keys = %d/%d, want 64/32", len(claims), len(keys))
	}
	for i, claim := range claims {
		if claim.Source != (entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter,
			SourceRef: "192.0.2.7"}) || claim.ID == "" ||
			claim.SourceRef != "flow:ipfix:domain:"+strconv.Itoa(i/2) {
			t.Fatalf("flow packet selected unlisted or wrong source: %+v", claim)
		}
		if i%2 == 0 && (claim.Alias.Kind != entity.AddressAlias || claim.Alias.Value != "192.0.2.7") {
			t.Fatalf("exporter address claim = %+v", claim)
		}
	}
	key0 := evidenceSource{exporter: "192.0.2.7", protocol: ProtoIPFIX, domain: 0}
	claims, keys = c.flowEvidenceClaims(batch,
		map[evidenceSource]time.Time{key0: now}, nil, nil, now.Add(time.Minute))
	if len(claims) != 64 || len(keys) != 32 || keys[0].domain != 1 {
		t.Fatalf("accepted identity refreshed before 12 hours: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	claims, keys = c.flowEvidenceClaims(batch, nil,
		map[evidenceSource]time.Time{key0: now}, nil, now.Add(time.Second))
	if len(claims) != 64 || len(keys) != 32 || keys[0].domain != 1 {
		t.Fatalf("failed identity retried before one minute: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	claims, keys = c.flowEvidenceClaims(batch, nil,
		map[evidenceSource]time.Time{key0: now}, nil, now.Add(flowEvidenceRetry))
	if len(claims) != 64 || len(keys) != 32 || keys[0].domain != 0 {
		t.Fatalf("failed identity did not retry after one minute: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	claims, keys = c.flowEvidenceClaims(batch, nil, nil,
		map[evidenceSource]time.Time{key0: now}, now.Add(time.Minute))
	if len(claims) != 64 || len(keys) != 32 || keys[0].domain != 1 {
		t.Fatalf("partly accepted identity rewrote durable evidence within one hour: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	claims, keys = c.flowEvidenceClaims(batch, nil, nil,
		map[evidenceSource]time.Time{key0: now}, now.Add(flowEvidenceUnresolvedRetry))
	if len(claims) != 64 || len(keys) != 32 || keys[0].domain != 0 {
		t.Fatalf("partly accepted identity did not retry after one hour: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	fresh := []Record{{Exporter: "192.0.2.7", Protocol: ProtoIPFIX,
		ObservationDomain: 0, ObservedAt: now.Add(flowEvidenceRefresh)}}
	claims, keys = c.flowEvidenceClaims(fresh,
		map[evidenceSource]time.Time{key0: now}, nil, nil, now.Add(flowEvidenceRefresh))
	if len(claims) != 2 || len(keys) != 1 || keys[0].domain != 0 {
		t.Fatalf("accepted identity did not refresh before expiry: %d/%d first=%+v", len(claims), len(keys), keys[0])
	}
	stale := []Record{{Exporter: "192.0.2.7", Protocol: ProtoIPFIX,
		ObservationDomain: 123, ObservedAt: now.Add(-flowEvidenceMaxLag)}}
	claims, keys = c.flowEvidenceClaims(stale, nil, nil, nil, now)
	if len(claims) != 0 || len(keys) != 0 {
		t.Fatalf("delayed raw flow created near-expired canonical identity: %d/%d", len(claims), len(keys))
	}
	stale[0].ObservedAt = now.Add(-flowEvidenceMaxLag + time.Second)
	claims, keys = c.flowEvidenceClaims(stale, nil, nil, nil, now)
	if len(claims) != 2 || len(keys) != 1 {
		t.Fatalf("fresh exporter identity was discarded: %d/%d", len(claims), len(keys))
	}
	// A delayed record must not consume the per-batch dedupe key before a
	// fresh record for that same configured exporter and domain arrives.
	freshAfterStale := []Record{stale[0], stale[0]}
	freshAfterStale[0].ObservedAt = now.Add(-flowEvidenceMaxLag)
	freshAfterStale[1].ObservedAt = now
	claims, keys = c.flowEvidenceClaims(freshAfterStale, nil, nil, nil, now)
	if len(claims) != 2 || len(keys) != 1 || !claims[0].ObservedAt.Equal(now) {
		t.Fatalf("stale duplicate hid fresh exporter identity: %d/%d %+v", len(claims), len(keys), claims)
	}
}
