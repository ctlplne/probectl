// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/configschema"
	"github.com/ctlplne/probectl/internal/otel"
)

func TestHostProbesIntoBuffer(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := canary.NewNoop(canary.Config{Type: "noop", Target: "t"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		scheduled: []scheduled{{canary: noop, interval: 5 * time.Millisecond, testID: "test-local-1"}},
		buffer:    buf,
		tenantID:  "tenant-1",
		agentID:   "agent-1",
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && buf.Len() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if buf.Len() < 1 {
		t.Fatalf("expected the no-op to buffer results, got %d", buf.Len())
	}
	frames, err := buf.peekAll()
	if err != nil {
		t.Fatal(err)
	}
	var env resultEnvelope
	if err := json.Unmarshal(frames[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.TenantID != "tenant-1" || env.AgentID != "agent-1" || env.Result.Type != "noop" || !env.Result.Success {
		t.Errorf("buffered envelope = %+v", env)
	}
	if env.Result.Attributes["probectl.test.id"] != "test-local-1" ||
		env.Result.Attributes["probectl.test.interval_seconds"] != "0.005" {
		t.Errorf("schedule receipt = %#v", env.Result.Attributes)
	}
}

func TestHostDoesNotPublishLocallyCanceledHTTPProbe(t *testing.T) {
	reached := make(chan struct{})
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cancel":
			close(reached)
			<-r.Context().Done()
		case "/timeout":
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(target.Close)
	certs := t.TempDir()
	canary.SetCAFileDir(certs)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	ca := filepath.Join(certs, "target-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	newSchedule := func(path string, timeout time.Duration) scheduled {
		t.Helper()
		probe, err := canary.NewHTTP(canary.Config{Type: "http", Target: target.URL + path,
			Timeout: timeout, Params: map[string]string{"allow_private_targets": "true", "ca_file": ca}})
		if err != nil {
			t.Fatal(err)
		}
		return scheduled{canary: probe, testID: "owned-http-test", interval: time.Second}
	}
	buf, err := openBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	host := &Host{buffer: buf, tenantID: "tenant-a", agentID: "agent-a",
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	schedule := newSchedule("/cancel", 5*time.Second)
	go func() { host.probe(ctx, schedule); close(done) }()
	select {
	case <-reached:
		cancel()
	case <-done:
		t.Fatal("the scheduled probe returned before making its TLS request")
	case <-time.After(5 * time.Second):
		t.Fatal("the scheduled probe did not make a verified TLS request")
	}
	<-done
	if buf.Len() != 0 {
		t.Fatal("canceling an in-flight HTTP probe published a failure")
	}

	host.probe(t.Context(), newSchedule("/failure", 5*time.Second))
	host.probe(t.Context(), newSchedule("/timeout", time.Second))
	frames, err := buf.peekAll()
	if err != nil || len(frames) != 2 {
		t.Fatalf("target failures must still be buffered: frames=%d error=%v", len(frames), err)
	}
	for i, frame := range frames {
		var original resultEnvelope
		if err := json.Unmarshal(frame, &original); err != nil || original.Result.Success ||
			original.TenantID != host.tenantID || original.AgentID != host.agentID || original.ResultID == "" {
			t.Fatalf("HTTP failure lost its result or owner: %+v error=%v", original, err)
		}
		if got, want := original.Result.Attributes[otel.AttrHTTPResponseStatusCode], []string{"503", ""}[i]; got != want {
			t.Fatalf("published HTTP status = %q, want %q", got, want)
		}
	}
}

func TestProspectCollectionStopsLocalOfflineProbeSchedule(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 200)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := canary.NewNoop(canary.Config{Type: "noop", Target: "owned-collector"})
	if err != nil {
		t.Fatal(err)
	}
	schedule := scheduled{canary: noop, interval: 10 * time.Millisecond}
	host := &Host{scheduled: []scheduled{schedule}, buffer: buf, tenantID: "completed-prospect", agentID: "temporary",
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	end := configschema.ProspectCollectionEnd{Time: time.Now().Add(time.Second)}
	ctx, cancel := end.Context(t.Context())
	defer cancel()
	finished := make(chan struct{})
	go func() { host.Run(ctx); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("offline temporary probe kept its schedule after the configured end")
	}
	before := buf.Len()
	if before < 1 {
		t.Fatal("temporary collector produced no pre-deadline observation")
	}
	host.probe(ctx, schedule) // the timer may become readable as the deadline fires
	if buf.Len() != before {
		t.Fatal("completed temporary collector accepted another local probe")
	}
}

type failedResultCanary struct{}

func (failedResultCanary) Describe() canary.Spec {
	return canary.Spec{Type: "udp", Version: "test", Description: "failed result fixture"}
}

func (failedResultCanary) Run(context.Context) (canary.Result, error) {
	start := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return canary.Result{
		Type: "udp", Target: "127.0.0.1:0", StartedAt: start,
		Duration: time.Millisecond, Success: false, Error: "udp: dial 127.0.0.1:0: invalid argument",
		Attributes: map[string]string{"network.transport": "udp"},
	}, nil
}

func TestHostProbeEnqueuesFailedResultEnvelope(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		buffer:   buf,
		tenantID: "tenant-a",
		agentID:  "agent-a",
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h.probe(context.Background(), scheduled{canary: failedResultCanary{}, interval: time.Second})

	frames, err := buf.peekAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("buffered frames = %d, want 1", len(frames))
	}
	var env resultEnvelope
	if err := json.Unmarshal(frames[0], &env); err != nil {
		t.Fatal(err)
	}
	if env.TenantID != "tenant-a" || env.AgentID != "agent-a" || env.ResultID == "" {
		t.Fatalf("identity envelope = %+v", env)
	}
	if env.Result.Success || env.Result.Error == "" || env.Result.Type != "udp" {
		t.Fatalf("failed canary result was not preserved: %+v", env.Result)
	}
}

// DPR-139: the scheduler waited a full interval before a canary's first probe,
// so an agent with a five-minute check showed an empty screen for five minutes
// and "time to first data" carried one whole interval of dead time for no
// reason. The first probe is immediate now, jittered so a host with many
// canaries — or a fleet restarted together — does not burst.
func TestFirstProbeDoesNotWaitAFullInterval(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := canary.NewNoop(canary.Config{Type: "noop", Target: "t"})
	if err != nil {
		t.Fatal(err)
	}
	// An interval far longer than the test's patience: if the first probe waited
	// for the ticker, nothing would ever be buffered here.
	h := &Host{
		scheduled: []scheduled{{canary: noop, interval: time.Hour, testID: "test-local-1"}},
		buffer:    buf,
		tenantID:  "tenant-1",
		agentID:   "agent-1",
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()

	deadline := time.Now().Add(15 * time.Second) // jitter is bounded well under this
	for time.Now().Before(deadline) && buf.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if buf.Len() == 0 {
		t.Fatal("the first probe must not wait for the first tick of a long interval")
	}
}

// The jitter must never exceed the interval: a sub-second canary in a test or a
// tight monitoring loop cannot be delayed by the fleet-friendly offset.
func TestFirstProbeJitterNeverExceedsTheInterval(t *testing.T) {
	buf, err := openBuffer(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	noop, err := canary.NewNoop(canary.Config{Type: "noop", Target: "t"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{
		scheduled: []scheduled{{canary: noop, interval: 5 * time.Millisecond, testID: "test-local-1"}},
		buffer:    buf,
		tenantID:  "tenant-1",
		agentID:   "agent-1",
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && buf.Len() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if buf.Len() < 3 {
		t.Fatalf("a 5ms canary must keep its cadence, got %d results in 2s", buf.Len())
	}
}
