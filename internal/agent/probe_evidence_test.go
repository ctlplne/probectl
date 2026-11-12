// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/testspec"
)

type blockedProbeEvidence struct {
	calls   chan []entity.Observation
	release chan struct{}
}

func (s *blockedProbeEvidence) Submit(ctx context.Context, observations []entity.Observation) (int, int, error) {
	select {
	case s.calls <- observations:
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
	select {
	case <-s.release:
		return len(observations), 0, nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

func probeQueueFixture(t *testing.T, tenant, agentID string) (*Host, scheduled, canary.Result, *blockedProbeEvidence) {
	t.Helper()
	buffer, err := openBuffer(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{buffer: buffer, tenantID: tenant, agentID: agentID, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	definition := testspec.ExecutableDefinition{ID: "c52355d4-aa77-414b-956a-506ac061d88c", Type: "icmp", Target: "127.0.0.1", IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{"allow_private_targets": "true", "count": "3"}}
	probe, err := canary.NewICMP(canary.Config{Type: definition.Type, Target: definition.Target, Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := testspec.DefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	schedule := scheduled{canary: probe, interval: 30 * time.Second, testID: definition.ID, definitionHash: digest}
	end := time.Now().UTC()
	result := canary.Result{Type: "icmp", ICMP: &canary.ICMPMeasurement{TargetIP: "127.0.0.1", StartedAt: end.Add(-time.Millisecond), CompletedAt: end, Expected: 3, Attempted: 3, Transmitted: 3, Replies: 3, ReadComplete: true, Responders: []string{"127.0.0.1"}}, Attributes: map[string]string{"probectl.test.id": "forged-test", "definition_hash": "forged-definition"}}
	emitter := &blockedProbeEvidence{calls: make(chan []entity.Observation, 2), release: make(chan struct{})}
	(&Agent{host: host, buffer: buffer}).WithProbeEvidence(emitter)
	return host, schedule, result, emitter
}

func TestProbeEvidenceQueueKeepsLatestUnknownAndInflightAdmission(t *testing.T) {
	host, schedule, result, emitter := probeQueueFixture(t, "blue", "blue-agent")
	first, err := host.probeObservation(schedule, result)
	if err != nil {
		t.Fatal(err)
	}
	if first.Source.SourceRef != schedule.testID || first.ICMP.DefinitionHash != schedule.definitionHash {
		t.Fatal("result attributes chose source or definition authority")
	}
	if err := host.probeEvidence.enqueue(first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { host.runProbeEvidence(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case sent := <-emitter.calls:
		if len(sent) != 1 || sent[0].ID != first.ID {
			t.Fatal("wrong first batch")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not enter owned blocked transport")
	}
	unknown := first
	unknown.ID = "bde6ca60-78fe-4cba-9909-e22a74d33105"
	unknown.ICMP = new(entity.ICMPMeasurement)
	*unknown.ICMP = *first.ICMP
	unknown.ObservedAt = first.ObservedAt.Add(time.Millisecond)
	unknown.ICMP.CompletedAt = unknown.ObservedAt
	unknown.ICMP.Transmitted = 2
	unknown.ICMP.Replies = 0
	unknown.ICMP.Responders = nil
	unknown.ICMP.SendErrors = 1
	unknown.ICMP.IOFailed = true
	if err := host.probeEvidence.enqueue(unknown); err != nil {
		t.Fatal("in-flight transport blocked newer unknown evidence", err)
	}
	if err := host.probeEvidence.enqueue(first); err != nil {
		t.Fatal(err)
	}
	if records, _ := host.probeEvidence.usage(); records != 2 {
		t.Fatal("in-flight or coalesced memory was not charged", records)
	}
	if err := host.probeEvidence.enqueue(entity.Observation{Source: entity.SourceKey{SourceRef: "262c861d-43a5-4ce9-aa0b-bc39edc48422"}, ICMP: first.ICMP}); !errors.Is(err, errProbeEvidenceFull) {
		t.Fatal("a third record bypassed current memory admission", err)
	}
	close(emitter.release)
	select {
	case sent := <-emitter.calls:
		if len(sent) != 1 || sent[0].ID != unknown.ID || !sent[0].ICMP.IOFailed || sent[0].ICMP.Replies != 0 {
			t.Fatal("an older failure/healthy result replaced newer unknown health")
		}
	case <-time.After(time.Second):
		t.Fatal("newer source observation was not delivered")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if records, bytes := host.probeEvidence.usage(); records == 0 && bytes == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("completed RPC retained its admission charge")
}

func TestProbeEvidenceMemoryAndAgentQueuesDoNotBorrowAuthority(t *testing.T) {
	blue, schedule, result, _ := probeQueueFixture(t, "blue", "blue-agent")
	red, _, _, _ := probeQueueFixture(t, "red", "red-agent")
	observation, err := blue.probeObservation(schedule, result)
	if err != nil {
		t.Fatal(err)
	}
	bytes := probeEvidenceMemory(observation)
	blue.probeEvidence.maxBytes = bytes - 1
	if err := blue.probeEvidence.enqueue(observation); !errors.Is(err, errProbeEvidenceFull) {
		t.Fatal("whole measurement bypassed byte admission", err)
	}
	if records, used := blue.probeEvidence.usage(); records != 0 || used != 0 {
		t.Fatal("refused measurement retained a partial prefix")
	}
	blue.probeEvidence.maxBytes = bytes
	if err := blue.probeEvidence.enqueue(observation); err != nil {
		t.Fatal("raising resource admission did not retain the complete measurement", err)
	}
	other, err := red.probeObservation(schedule, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := red.probeEvidence.enqueue(other); err != nil {
		t.Fatal("other agent inherited exhausted admission", err)
	}
	for _, host := range []*Host{blue, red} {
		batch := host.probeEvidence.take()
		if len(batch) != 1 || batch[0].observation.Source.AgentID != host.agentID || batch[0].observation.Source.SourceRef != schedule.testID {
			t.Fatal("source authority moved across agent queues")
		}
		host.probeEvidence.release(batch)
	}
}
