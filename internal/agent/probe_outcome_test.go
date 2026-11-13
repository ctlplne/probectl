// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
)

type outcomeCanary struct {
	success  bool
	response *canary.HTTPMeasurement
}

func (p *outcomeCanary) Describe() canary.Spec { return canary.Spec{Type: "http"} }
func (p *outcomeCanary) Run(context.Context) (canary.Result, error) {
	return canary.Result{Type: "http", Success: p.success, HTTP: p.response, StartedAt: time.Unix(1, 0), Duration: 99 * time.Hour, Error: "password=untrusted-response", Attributes: map[string]string{"probectl.test.id": "other-test", "definition_hash": "other-definition", "agent_id": "other-agent"}}, nil
}

func TestConfiguredProbeEvidenceKeepsEveryOutcomeRuntimeIdentityAndClock(t *testing.T) {
	buffer, err := openBuffer(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{buffer: buffer, tenantID: "own-tenant", agentID: "own-agent", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	(&Agent{host: host, buffer: buffer}).WithProbeEvidence(&blockedProbeEvidence{})
	probe := &outcomeCanary{}
	schedule := scheduled{canary: probe, interval: time.Minute, testID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", definitionHash: strings.Repeat("a", 64)}
	before := time.Now().UTC().Truncate(time.Microsecond)
	host.probe(t.Context(), schedule)
	probe.success = true
	host.probe(t.Context(), schedule)
	batch := host.probeEvidence.take()
	if len(batch) != 2 || batch[0].observation.ID == batch[1].observation.ID || batch[0].observation.Outcome == nil || batch[0].observation.Outcome.Success || !batch[1].observation.Outcome.Success {
		t.Fatal("a later success erased an earlier configured failure", len(batch))
	}
	for _, item := range batch {
		claim := item.observation
		if claim.Source.AgentID != host.agentID || claim.Source.SourceRef != schedule.testID || claim.Alias.Value != schedule.testID || claim.Outcome.DefinitionHash != schedule.definitionHash || claim.Outcome.StartedAt.Before(before) || claim.Outcome.CompletedAt.Before(claim.Outcome.StartedAt) || claim.Outcome.CompletedAt.After(time.Now().UTC()) {
			t.Fatal("plugin fields selected identity, definition or clocks", claim)
		}
		body, err := json.Marshal(claim)
		if err != nil || strings.Contains(string(body), "untrusted-response") || strings.Contains(string(body), "other-agent") || strings.Contains(string(body), "other-test") {
			t.Fatal("untrusted response fields entered retained evidence", err)
		}
	}
	host.probeEvidence.release(batch)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	host.probe(ctx, schedule)
	canceled := host.probeEvidence.take()
	if len(canceled) != 1 || canceled[0].observation.Outcome == nil || !canceled[0].observation.Outcome.Canceled {
		t.Fatal("runtime cancellation was reported as an ordinary successful outcome")
	}
	host.probeEvidence.release(canceled)
	local := schedule
	local.testID = ""
	host.probe(t.Context(), local)
	if batch := host.probeEvidence.take(); len(batch) != 0 {
		t.Fatal("local-only result invented a canonical test binding")
	}
}

func TestHTTPOutcomeEvidenceKeepsRuntimeSourceAndPrimaryResponse(t *testing.T) {
	buffer, err := openBuffer(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{buffer: buffer, tenantID: "owned-tenant", agentID: "owned-agent", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	(&Agent{host: host, buffer: buffer}).WithProbeEvidence(&blockedProbeEvidence{})
	probe := &outcomeCanary{response: &canary.HTTPMeasurement{StatusCode: 503, TLSVerified: true, SameOrigin: true}}
	schedule := scheduled{canary: probe, interval: time.Minute, testID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", definitionHash: strings.Repeat("a", 64)}
	host.probe(t.Context(), schedule)
	probe.response.StatusCode = 777
	batch := host.probeEvidence.take()
	if len(batch) != 1 {
		t.Fatal("primary response was not retained once", len(batch))
	}
	defer host.probeEvidence.release(batch)
	original := batch[0].observation
	if original.Source.AgentID != host.agentID || original.Source.SourceRef != schedule.testID || original.Outcome.Version != 2 || original.Outcome.HTTPResponse == nil || original.Outcome.HTTPResponse.StatusCode != 503 || !original.Outcome.HTTPResponse.TLSVerified || !original.Outcome.HTTPResponse.SameOrigin {
		t.Fatal("HTTP facts lost their original collector or runtime source", original)
	}
	wire := encodeProbeOutcome(original.Outcome)
	if wire.GetHttpResponse() == nil || wire.GetHttpResponse().GetStatusCode() != 503 || !wire.GetHttpResponse().GetTlsVerified() || !wire.GetHttpResponse().GetSameOrigin() {
		t.Fatal("wire lost the typed primary response")
	}
}
