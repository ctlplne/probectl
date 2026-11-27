// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/siem"
)

// barrierSender blocks every POST until the test releases it, recording the
// peak number of concurrently in-flight POSTs so a serial drain is detectable.
type barrierSender struct {
	mu          sync.Mutex
	inFlight    int
	maxInFlight int
	payloads    [][]byte
	release     chan struct{}
}

func newBarrierSender() *barrierSender { return &barrierSender{release: make(chan struct{})} }

func (s *barrierSender) Send(ctx context.Context, p []byte) error {
	s.mu.Lock()
	s.inFlight++
	if s.inFlight > s.maxInFlight {
		s.maxInFlight = s.inFlight
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	s.payloads = append(s.payloads, append([]byte(nil), p...))
	s.mu.Unlock()
	return nil
}

func (s *barrierSender) peak() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxInFlight
}

// toggleSender fails every POST while fail is set, else captures the payload.
type toggleSender struct {
	mu       sync.Mutex
	fail     bool
	payloads [][]byte
}

func (s *toggleSender) setFail(b bool) { s.mu.Lock(); s.fail = b; s.mu.Unlock() }

func (s *toggleSender) Send(_ context.Context, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("siem down")
	}
	s.payloads = append(s.payloads, append([]byte(nil), p...))
	return nil
}

func (s *toggleSender) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.payloads) }

// AUD-16: the poller drains tenants through a bounded worker pool, so several
// tenants' exports are in flight at once — one slow/large tenant cannot serialize
// (and thus starve) the rest. A serial drain would hold peak in-flight at 1 and
// this fails at waitFor.
func TestSIEMExportDrainsTenantsConcurrently(t *testing.T) {
	db := changeDB(t)
	const k = 4
	tenants := make([]string, 0, k)
	for i := 0; i < k; i++ {
		tn := freshTenant(t, db, "siem-cc")
		appendAudit(t, db, tn, "alert.create")
		tenants = append(tenants, tn)
	}

	sender := newBarrierSender()
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, sender, siem.Config{}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Safety net: always release blocked POSTs so a failing assertion cannot hang.
	var once sync.Once
	releaseAll := func() { once.Do(func() { close(sender.release) }) }
	defer releaseAll()

	tickErr := make(chan error, 1)
	go func() { tickErr <- poller.tick(ctx) }()

	// At least two tenants must be POSTing at the same time (concurrency).
	waitFor(t, func() bool { return sender.peak() >= 2 })
	releaseAll()

	select {
	case err := <-tickErr:
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tick did not finish after release")
	}

	if p := sender.peak(); p < 2 {
		t.Fatalf("peak concurrent POSTs = %d, want >= 2 (serial drain)", p)
	}
	// Every one of this test's tenants caught up — no tenant was starved.
	for _, tn := range tenants {
		if c := tenantCursor(t, db, tn); c != 1 {
			t.Fatalf("tenant %s cursor = %d, want 1 (not drained)", tn, c)
		}
	}
}

// AUD-16: the POST happens with NO transaction open and the cursor advances only
// after it succeeds. While the SIEM rejects every POST the cursor must not move;
// once it accepts, the cursor advances past exactly the delivered events.
func TestSIEMExportCursorAdvancesOnlyAfterSuccessfulPOST(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "siem-cas")
	appendAudit(t, db, tenant, "alert.create")
	appendAudit(t, db, tenant, "agent.delete")

	sender := &toggleSender{fail: true}
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, sender,
		siem.Config{RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())
	poller.postTimeout = 150 * time.Millisecond // give up fast while the SIEM is down

	// POST fails: cursor must stay at 0, nothing delivered.
	if err := poller.drainTenant(context.Background(), tenant); err != nil {
		t.Fatalf("drain (failing): %v", err)
	}
	if c := tenantCursor(t, db, tenant); c != 0 {
		t.Fatalf("cursor advanced despite failed POST: %d", c)
	}
	if d := fw.Stats().Delivered; d != 0 {
		t.Fatalf("delivered %d events despite failed POST, want 0", d)
	}

	// SIEM recovers: now the cursor advances past exactly the two events.
	sender.setFail(false)
	poller.postTimeout = 5 * time.Second
	if err := poller.drainTenant(context.Background(), tenant); err != nil {
		t.Fatalf("drain (recovered): %v", err)
	}
	if c := tenantCursor(t, db, tenant); c != 2 {
		t.Fatalf("cursor did not advance after successful POST: %d", c)
	}
	if d := fw.Stats().Delivered; d != 2 {
		t.Fatalf("delivered %d events after recovery, want 2", d)
	}
	if sender.count() == 0 {
		t.Fatal("recovered SIEM received no batch")
	}
}

// AUD-16 (G7-1): a batch POST for one tenant carries ONLY that tenant's events —
// no cross-tenant mixing in a SIEM destination.
func TestSIEMExportTenantScopedDestinationIsolation(t *testing.T) {
	db := changeDB(t)
	tenantA := freshTenant(t, db, "siem-iso-a")
	tenantB := freshTenant(t, db, "siem-iso-b")
	appendAudit(t, db, tenantA, "alert.create")
	appendAudit(t, db, tenantA, "agent.delete")
	appendAudit(t, db, tenantB, "login")

	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())

	if err := poller.drainTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("drain A: %v", err)
	}
	if err := poller.drainTenant(context.Background(), tenantB); err != nil {
		t.Fatalf("drain B: %v", err)
	}

	seenA, seenB := 0, 0
	for _, payload := range snk.records() {
		docs := ecsBatchDocs(t, payload)
		orgs := map[string]int{}
		for _, doc := range docs {
			orgs[doc["organization"].(map[string]any)["id"].(string)]++
		}
		if len(orgs) != 1 {
			t.Fatalf("a single batch mixed tenants: %v", orgs)
		}
		for org, n := range orgs {
			switch org {
			case tenantA:
				seenA += n
			case tenantB:
				seenB += n
			default:
				t.Fatalf("unexpected tenant in batch: %s", org)
			}
		}
	}
	if seenA != 2 || seenB != 1 {
		t.Fatalf("delivered per tenant = A:%d B:%d, want A:2 B:1", seenA, seenB)
	}
}

// The Splunk HEC raw fixture uses the documented HTTPS/token contract, with
// indexer acknowledgment disabled. No proprietary Splunk instance is involved.
func TestSplunkHECRawStandInRetriesWithoutMixingTenantBatches(t *testing.T) {
	const channel = "35431dba-7ab6-435d-8f91-0782a8c6abe7"
	db := changeDB(t)
	alpha := freshTenant(t, db, "hec-raw-alpha")
	beta := freshTenant(t, db, "hec-raw-beta")
	appendAudit(t, db, alpha, "alert.create")
	appendAudit(t, db, alpha, "alert.update")
	appendAudit(t, db, beta, "alert.resolve")
	var rejectAlpha atomic.Bool
	rejectAlpha.Store(true)
	var receivedAlpha, receivedBeta atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		text := string(raw)
		var hasAlpha, hasBeta bool
		for _, field := range strings.Fields(text) {
			hasAlpha = hasAlpha || field == "cs1="+alpha
			hasBeta = hasBeta || field == "cs1="+beta
		}
		if err != nil || hasAlpha == hasBeta || !strings.HasPrefix(text, "CEF:") ||
			r.Method != http.MethodPost || r.URL.Path != "/services/collector/raw" ||
			r.URL.Query().Get("channel") != channel ||
			r.Header.Get("Authorization") != "Splunk local-hec-fixture" {
			t.Error("invalid HEC raw request or mixed tenant batch")
			http.Error(w, "invalid HEC payload", http.StatusBadRequest)
			return
		}
		if hasAlpha && rejectAlpha.Load() {
			http.Error(w, "simulated HEC unavailable", http.StatusServiceUnavailable)
			return
		}
		if hasAlpha {
			receivedAlpha.Add(int64(strings.Count(text, "CEF:")))
		} else {
			receivedBeta.Add(int64(strings.Count(text, "CEF:")))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	t.Cleanup(target.Close)
	format, _ := siem.NewFormatter("cef")
	sender := siem.NewHTTPSender(siem.PresetSplunk, target.URL+"/services/collector/raw?channel="+channel, "local-hec-fixture", siem.AuthSchemeDefault, "text/plain", target.Client())
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	forwarder := siem.NewForwarder(format, sender, siem.Config{RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, logger)
	poller := NewSIEMAuditPoller(db.Pool(), forwarder, nil, true, time.Minute, testLog())
	poller.postTimeout = 500 * time.Millisecond
	for _, tenant := range []string{alpha, beta} {
		if err := poller.drainTenant(t.Context(), tenant); err != nil {
			t.Fatal(err)
		}
	}
	if tenantCursor(t, db, alpha) != 0 || tenantCursor(t, db, beta) != 1 || receivedBeta.Load() != 1 {
		t.Fatal("the failed HEC batch altered another tenant or advanced its own cursor")
	}
	if text := logs.String(); !strings.Contains(text, "HTTP 503") ||
		strings.Contains(text, channel) || strings.Contains(text, "local-hec-fixture") || strings.Contains(text, target.URL) {
		t.Fatal("delivery logs must retain status without exposing HEC endpoint or credentials")
	}
	rejectAlpha.Store(false)
	poller.postTimeout = 5 * time.Second
	if err := poller.drainTenant(t.Context(), alpha); err != nil {
		t.Fatal(err)
	}
	if tenantCursor(t, db, alpha) != 2 || tenantCursor(t, db, beta) != 1 || receivedAlpha.Load() != 2 || receivedBeta.Load() != 1 {
		t.Fatal("HEC recovery did not deliver the original two records within their own tenant")
	}
}

// AUD-16: per-tenant export backlog is visible on /metrics — as aggregates
// (OPS-005 keeps per-tenant series off the scrape, which TestMetricsEndpoint...
// guards). A tenant whose SIEM is down shows up in the backlog gauges.
func TestSIEMExportBacklogMetricExported(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "siem-backlog")
	for i := 0; i < 3; i++ {
		appendAudit(t, db, tenant, "alert.create")
	}

	sender := &toggleSender{fail: true} // SIEM down → backlog accrues
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, sender,
		siem.Config{RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())
	poller.postTimeout = 150 * time.Millisecond

	reg := metrics.New("test", "test")
	poller.RegisterMetrics(reg)

	if err := poller.drainTenant(context.Background(), tenant); err != nil {
		t.Fatalf("drain: %v", err)
	}

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		"probectl_siem_export_backlog_events 3",
		"probectl_siem_export_backlog_max_events 3",
		"probectl_siem_export_backlog_tenants 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, body)
		}
	}
	// OPS-005: backlog is exposed as aggregates, never a per-tenant series.
	if strings.Contains(body, "tenant_id=") || strings.Contains(body, tenant) {
		t.Fatalf("/metrics leaked a per-tenant series:\n%s", body)
	}
}
