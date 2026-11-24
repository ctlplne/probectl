// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/configschema"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/testsync"
)

const (
	instantTestCapability = "agent.fetch_instant_tests.v1"
	instantTestInterval   = 2 * time.Second
)

// One worker owns this result across transport sessions. Keep the original
// result and ID through reconnects until the lease ends or the server replies.
type pendingInstantResult struct {
	agentID string
	request *agentv1.ReportInstantTestResultRequest
	expires time.Time
}

// runInstantTests owns one serial polling worker for this transport session.
// Scheduled bundle sync and buffered telemetry delivery can block independently.
func (s *testSyncer) runInstantTests(ctx context.Context, client *Client, agentID string) {
	ticker := time.NewTicker(instantTestInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		s.pullInstantTest(ctx, client, agentID)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *testSyncer) pullInstantTest(ctx context.Context, client *Client, agentID string) {
	if configschema.ProspectCollectionEnded(ctx) {
		s.pendingInstant = nil
		return
	}
	if pending := s.pendingInstant; pending != nil {
		if pending.agentID != agentID || !time.Now().Before(pending.expires) || s.reportInstantTest(ctx, client, pending) {
			s.pendingInstant = nil
		}
		// Prioritize this exact result before requesting another lease.
		return
	}
	pull, cancel := context.WithTimeout(ctx, 2*time.Second)
	wire, err := client.fetchInstantTest(pull)
	cancel()
	if err != nil || len(wire) == 0 {
		return
	}
	started := time.Now()
	job, err := testsync.VerifyInstantAssignment(wire, s.pub, s.tenantID, agentID, started)
	if err != nil {
		s.log.Warn("refused signed instant test assignment")
		return
	}
	if err := s.consumeInstantLease(job.LeaseID, started); err != nil {
		return
	}
	result, outcome := s.runInstantTest(ctx, job, started)
	id, err := crypto.UUIDv4()
	if err != nil {
		return
	}
	wireResult, err := proto.Marshal(envToResult(&resultEnvelope{TenantID: s.tenantID, AgentID: agentID, ResultID: id, Result: result}))
	if err != nil {
		return
	}
	request := &agentv1.ReportInstantTestResultRequest{
		RunId: job.RunID, LeaseId: job.LeaseID, TestId: job.Test.ID,
		ResultPayload: wireResult, Outcome: outcome,
	}
	pending := &pendingInstantResult{agentID: agentID, request: request, expires: job.ExpiresAt}
	s.pendingInstant = pending
	if s.reportInstantTest(ctx, client, pending) {
		s.pendingInstant = nil
	}
}

func (s *testSyncer) runInstantTest(ctx context.Context, job testsync.InstantAssignment, started time.Time) (canary.Result, string) {
	fallback := canary.Result{Type: job.Test.Type, StartedAt: started}
	reason, definition := s.admitOne(job.Test, nil)
	if reason != "" || configschema.ProspectCollectionEnded(ctx) {
		return fallback, "policy_refused"
	}
	deadline := minTime(started.Add(time.Duration(job.Test.TimeoutSeconds)*time.Second), job.ExpiresAt)
	probe, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if probe.Err() != nil {
		return fallback, "timed_out"
	}
	result, err := definition.sched.canary.Run(probe)
	fallback.Duration = time.Since(started)
	if ctx.Err() != nil {
		return fallback, "execution_failed"
	}
	if probe.Err() != nil {
		return fallback, "timed_out"
	}
	if err != nil {
		return fallback, "execution_failed"
	}
	// Store only canonical run status and numeric measurement fields for now.
	// An instant result never publishes along the scheduled-result bus.
	return canary.Result{
		Type: job.Test.Type, StartedAt: started, Duration: fallback.Duration,
		Success: result.Success, Metrics: result.Metrics,
	}, "measured"
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *testSyncer) reportInstantTest(ctx context.Context, client *Client, pending *pendingInstantResult) bool {
	ctx, cancel := context.WithDeadline(ctx, pending.expires)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if configschema.ProspectCollectionEnded(ctx) {
			return true
		}
		attempt, finish := context.WithTimeout(ctx, 2*time.Second)
		err := client.reportInstantTest(attempt, pending.request)
		finish()
		switch status.Code(err) {
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
			select {
			case <-ctx.Done():
				return !time.Now().Before(pending.expires)
			case <-ticker.C:
			}
		default:
			return true
		}
	}
	return !time.Now().Before(pending.expires)
}

// consumeInstantLease records a lease before execution. Exclusive creation
// keeps the same verified lease from repeating after an agent restart.
func (s *testSyncer) consumeInstantLease(lease string, at time.Time) error {
	dir := filepath.Join(s.cfg.StateDir, "instant-leases")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if at.Sub(s.lastInstantPrune) >= time.Hour {
		s.lastInstantPrune = at
		files, _ := os.ReadDir(dir)
		for _, item := range files {
			info, err := item.Info()
			if err == nil && info.Mode().IsRegular() && at.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(filepath.Join(dir, item.Name()))
			}
		}
	}
	marker, err := os.OpenFile(filepath.Join(dir, lease), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return marker.Close()
}
