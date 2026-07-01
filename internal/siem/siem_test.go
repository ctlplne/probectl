// SPDX-License-Identifier: LicenseRef-probectl-TBD

package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		Time:     time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC),
		TenantID: "t1",
		Category: CategoryThreat,
		Action:   "ioc.botnet_c2",
		Severity: SeverityCritical,
		Actor:    "threat-engine",
		Target:   "203.0.113.7",
		Outcome:  "success",
		Message:  "C2 beacon to known botnet",
		Attributes: map[string]string{
			"ioc.source": "feodo",
			"confidence": "90",
		},
	}
}

func TestNewFormatterUnknown(t *testing.T) {
	if _, ok := NewFormatter("nope"); ok {
		t.Fatal("expected unknown formatter to be rejected")
	}
	for _, name := range []string{"syslog", "CEF", " ecs ", "otlp"} {
		if _, ok := NewFormatter(name); !ok {
			t.Fatalf("formatter %q should be known", name)
		}
	}
}

func TestSyslogFormat(t *testing.T) {
	out := string(syslogFormatter{}.Format(sampleEvent()))
	// PRI = facility(13)*8 + severity(critical=2) = 106.
	if !strings.HasPrefix(out, "<106>1 2026-06-02T12:00:00Z probectl probectl - ioc.botnet_c2 [probectl@32473 ") {
		t.Fatalf("unexpected syslog header: %s", out)
	}
	for _, want := range []string{
		`tenant="t1"`, `category="threat"`, `actor="threat-engine"`,
		`target="203.0.113.7"`, `outcome="success"`, `confidence="90"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("syslog missing %s in:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "C2 beacon to known botnet") {
		t.Fatalf("syslog should end with message: %s", out)
	}
}

func TestSyslogEscapesStructuredData(t *testing.T) {
	e := sampleEvent()
	e.Attributes = map[string]string{"k": `a"b\c]d`}
	out := string(syslogFormatter{}.Format(e))
	if !strings.Contains(out, `k="a\"b\\c\]d"`) {
		t.Fatalf("syslog SD value not escaped: %s", out)
	}
}

func TestCEFFormat(t *testing.T) {
	out := string(cefFormatter{}.Format(sampleEvent()))
	if !strings.HasPrefix(out, "CEF:0|probectl|probectl|1.0|ioc.botnet_c2|C2 beacon to known botnet|9|") {
		t.Fatalf("unexpected CEF header: %s", out)
	}
	for _, want := range []string{"cs1=t1", "cs1Label=tenant", "suser=threat-engine", "dst=203.0.113.7", "cat=threat", "confidence=90"} {
		if !strings.Contains(out, want) {
			t.Fatalf("CEF missing %s in:\n%s", want, out)
		}
	}
}

func TestCEFEscaping(t *testing.T) {
	e := sampleEvent()
	e.Action = "a|b"                             // header pipe must be escaped
	e.Attributes = map[string]string{"k": "x=y"} // ext '=' must be escaped
	out := string(cefFormatter{}.Format(e))
	if !strings.Contains(out, `|a\|b|`) {
		t.Fatalf("CEF header pipe not escaped: %s", out)
	}
	if !strings.Contains(out, `k=x\=y`) {
		t.Fatalf("CEF ext '=' not escaped: %s", out)
	}
}

func TestECSFormat(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(ecsFormatter{}.Format(sampleEvent()), &doc); err != nil {
		t.Fatalf("ecs not valid json: %v", err)
	}
	if doc["@timestamp"] != "2026-06-02T12:00:00Z" {
		t.Fatalf("ecs timestamp: %v", doc["@timestamp"])
	}
	ev := doc["event"].(map[string]any)
	if ev["kind"] != "alert" { // threat → alert
		t.Fatalf("ecs threat kind should be alert, got %v", ev["kind"])
	}
	if cats := ev["category"].([]any); cats[0] != "threat" {
		t.Fatalf("ecs category: %v", cats)
	}
	if ev["action"] != "ioc.botnet_c2" || ev["outcome"] != "success" {
		t.Fatalf("ecs event fields: %v", ev)
	}
	if org := doc["organization"].(map[string]any); org["id"] != "t1" {
		t.Fatalf("ecs org id should carry tenant: %v", org)
	}
	if user := doc["user"].(map[string]any); user["name"] != "threat-engine" {
		t.Fatalf("ecs user: %v", user)
	}
}

func TestECSLabelKeyStripsDots(t *testing.T) {
	var doc map[string]any
	_ = json.Unmarshal(ecsFormatter{}.Format(sampleEvent()), &doc)
	labels := doc["labels"].(map[string]any)
	if _, ok := labels["ioc_source"]; !ok {
		t.Fatalf("ecs label dot should become underscore: %v", labels)
	}
}

func TestOTLPFormat(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(otlpFormatter{}.Format(sampleEvent()), &doc); err != nil {
		t.Fatalf("otlp not valid json: %v", err)
	}
	rl := doc["resourceLogs"].([]any)[0].(map[string]any)
	res := rl["resource"].(map[string]any)["attributes"].([]any)
	if !otlpHasAttr(res, "probectl.tenant_id", "t1") {
		t.Fatalf("otlp resource missing tenant attr: %v", res)
	}
	rec := rl["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	if rec["severityNumber"].(float64) != 21 || rec["severityText"] != "CRITICAL" {
		t.Fatalf("otlp severity: %v / %v", rec["severityNumber"], rec["severityText"])
	}
	if body := rec["body"].(map[string]any); body["stringValue"] != "C2 beacon to known botnet" {
		t.Fatalf("otlp body: %v", body)
	}
	if !otlpHasAttr(rec["attributes"].([]any), "event.action", "ioc.botnet_c2") {
		t.Fatalf("otlp record missing event.action: %v", rec["attributes"])
	}
	if ts, _ := rec["timeUnixNano"].(string); ts == "" {
		t.Fatalf("otlp timeUnixNano should be a string: %v", rec["timeUnixNano"])
	}
}

func otlpHasAttr(attrs []any, key, val string) bool {
	for _, a := range attrs {
		m := a.(map[string]any)
		if m["key"] == key && m["value"].(map[string]any)["stringValue"] == val {
			return true
		}
	}
	return false
}

func TestEventDefaults(t *testing.T) {
	e := Event{Category: CategoryAudit, Action: "x.y"}
	if e.time().IsZero() {
		t.Fatal("zero time should default to now")
	}
	if e.message() != "audit x.y" {
		t.Fatalf("default message: %q", e.message())
	}
}

func TestPreset(t *testing.T) {
	if p, ok := ParsePreset("SPLUNK"); !ok || p != PresetSplunk {
		t.Fatalf("parse splunk: %v %v", p, ok)
	}
	if _, ok := ParsePreset("nope"); ok {
		t.Fatal("unknown preset should reject")
	}
	if PresetElastic.DefaultFormat() != "ecs" || PresetChronicle.DefaultFormat() != "otlp" || PresetSplunk.DefaultFormat() != "cef" {
		t.Fatal("preset default formats wrong")
	}
}

func TestSyslogIngestReplaysRFC5424AndRFC3164PerTenant(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	store := NewMemorySyslogStore(10)
	receiver, err := NewSyslogReceiver(SyslogReceiverConfig{
		TenantID: "tenant-a",
		Now:      func() time.Time { return now },
		Sources: []SyslogSource{
			{
				Name:       "edge-fw",
				Address:    "192.0.2.10",
				HMACSecret: "edge-secret",
			},
			{
				Name:             "access-switch",
				Address:          "198.51.100.3",
				TLSClientSubject: "CN=access-switch",
			},
		},
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	rfc5424 := []byte(`<34>1 2026-06-30T13:00:00Z edge-1 firewall 731 link_down [probectlSrc@32473 ifIndex="7" role="wan"] uplink down on Gi0/1`)
	event, err := receiver.Record(context.Background(), SyslogEnvelope{
		Line:          rfc5424,
		SourceAddress: "192.0.2.10:6514",
		Signature:     SyslogSignature("edge-secret", rfc5424),
		ReceivedAt:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.TenantID != "tenant-a" || event.Source != SourceSyslog || event.SourceName != "edge-fw" {
		t.Fatalf("tenant/source stamping failed: %+v", event)
	}
	if event.Format != "rfc5424" || event.Facility != 4 || event.Severity != 2 {
		t.Fatalf("rfc5424 pri normalization failed: %+v", event)
	}
	if event.Hostname != "edge-1" || event.AppName != "firewall" || event.ProcID != "731" || event.MsgID != "link_down" {
		t.Fatalf("rfc5424 header normalization failed: %+v", event)
	}
	if event.StructuredData == "" || event.Message != "uplink down on Gi0/1" {
		t.Fatalf("rfc5424 body normalization failed: %+v", event)
	}
	if event.AuthMethod != "hmac-sha256" || event.Provenance["auth.method"] != "hmac-sha256" {
		t.Fatalf("signature provenance missing: %+v", event)
	}

	rfc3164 := []byte(`<13>Jun 30 13:00:00 access-1 snmpd[123]: linkUp ifIndex=7`)
	event, err = receiver.Record(context.Background(), SyslogEnvelope{
		Line:             rfc3164,
		SourceAddress:    "198.51.100.3:6514",
		TLSClientSubject: "CN=access-switch",
		ReceivedAt:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Format != "rfc3164" || event.Facility != 1 || event.Severity != 5 {
		t.Fatalf("rfc3164 pri normalization failed: %+v", event)
	}
	if event.Timestamp.Year() != 2026 || event.Hostname != "access-1" || event.AppName != "snmpd" || event.ProcID != "123" {
		t.Fatalf("rfc3164 header normalization failed: %+v", event)
	}
	if event.AuthMethod != "tls-client-cert" || event.AuthPrincipal != "CN=access-switch" {
		t.Fatalf("tls provenance missing: %+v", event)
	}

	if got := len(store.ListSyslogEvents("tenant-a")); got != 2 {
		t.Fatalf("tenant-a syslog rows = %d, want 2", got)
	}
	if got := len(store.ListSyslogEvents("tenant-b")); got != 0 {
		t.Fatalf("tenant-b syslog rows = %d, want 0", got)
	}
}

func TestSyslogIngestSignatureAndRateLimit(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	line := []byte(`<34>1 2026-06-30T13:00:00Z edge-1 firewall - link_down - first`)

	unsignedStore := NewMemorySyslogStore(10)
	unsigned, err := NewSyslogReceiver(SyslogReceiverConfig{
		TenantID: "tenant-a",
		Now:      func() time.Time { return now },
		Sources:  []SyslogSource{{Name: "edge-fw", HMACSecret: "edge-secret"}},
	}, unsignedStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsigned.Record(context.Background(), SyslogEnvelope{Line: line, Signature: "sha256=00", ReceivedAt: now}); !errors.Is(err, ErrSyslogUnauthenticated) {
		t.Fatalf("forged signature err = %v, want unauthenticated", err)
	}
	if got := len(unsignedStore.ListSyslogEvents("tenant-a")); got != 0 {
		t.Fatalf("forged syslog stored %d rows", got)
	}

	store := NewMemorySyslogStore(10)
	receiver, err := NewSyslogReceiver(SyslogReceiverConfig{
		TenantID: "tenant-a",
		Now:      func() time.Time { return now },
		Sources: []SyslogSource{{
			Name:            "edge-fw",
			HMACSecret:      "edge-secret",
			RateLimit:       2,
			RateLimitWindow: time.Hour,
		}},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := receiver.Record(context.Background(), SyslogEnvelope{
			Line:       line,
			Signature:  SyslogSignature("edge-secret", line),
			ReceivedAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("accepted syslog %d: %v", i, err)
		}
	}
	if _, err := receiver.Record(context.Background(), SyslogEnvelope{
		Line:       line,
		Signature:  SyslogSignature("edge-secret", line),
		ReceivedAt: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrSyslogRateLimited) {
		t.Fatalf("third syslog err = %v, want rate limited", err)
	}
	if got := len(store.ListSyslogEvents("tenant-a")); got != 2 {
		t.Fatalf("rate limited store rows = %d, want 2", got)
	}
}

func TestSyslogIngestRejectsMalformedAndPlainListener(t *testing.T) {
	store := NewMemorySyslogStore(10)
	receiver, err := NewSyslogReceiver(SyslogReceiverConfig{
		TenantID:     "tenant-a",
		MaxLineBytes: 32,
		Sources:      []SyslogSource{{Name: "edge-fw", HMACSecret: "edge-secret"}},
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	malformed := []byte(`<999>1 2026-06-30T13:00:00Z edge app - msg - bad`)
	if _, err := receiver.Record(context.Background(), SyslogEnvelope{
		Line:      malformed,
		Signature: SyslogSignature("edge-secret", malformed),
	}); !errors.Is(err, ErrSyslogParse) {
		t.Fatalf("malformed pri err = %v, want parse", err)
	}
	oversized := []byte(`<34>1 2026-06-30T13:00:00Z edge app - msg - too-long`)
	if _, err := receiver.Record(context.Background(), SyslogEnvelope{
		Line:      oversized,
		Signature: SyslogSignature("edge-secret", oversized),
	}); !errors.Is(err, ErrSyslogParse) {
		t.Fatalf("oversized err = %v, want parse", err)
	}
	if got := len(store.ListSyslogEvents("tenant-a")); got != 0 {
		t.Fatalf("malformed syslog stored %d rows", got)
	}
	if err := receiver.ListenTLS(context.Background(), "127.0.0.1:0", nil); err == nil || !strings.Contains(err.Error(), "TLS config required") {
		t.Fatalf("nil TLS config should fail closed, got %v", err)
	}
	if _, err := NewSyslogReceiver(SyslogReceiverConfig{
		TenantID: "tenant-a",
		Sources:  []SyslogSource{{Name: "plain-source"}},
	}, NewMemorySyslogStore(1)); err == nil {
		t.Fatal("source without signature or TLS client subject should fail closed")
	}
}

// fakeDoer captures the last request and returns a canned status.
type fakeDoer struct {
	last   *http.Request
	body   string
	status int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	f.last = req
	f.body = string(b)
	st := f.status
	if st == 0 {
		st = 200
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestHTTPSenderHeadersAndAuth(t *testing.T) {
	fd := &fakeDoer{}
	s := NewHTTPSender(PresetSplunk, "https://hec.example/services/collector", "tok123", "application/json", fd)
	if err := s.Send(context.Background(), []byte("payload")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := fd.last.Header.Get("Authorization"); got != "Splunk tok123" {
		t.Fatalf("splunk auth header: %q", got)
	}
	if fd.last.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type: %q", fd.last.Header.Get("Content-Type"))
	}
	if fd.body != "payload" {
		t.Fatalf("body: %q", fd.body)
	}
}

func TestHTTPSenderElasticAuthAndNon2xx(t *testing.T) {
	fd := &fakeDoer{status: 503}
	s := NewHTTPSender(PresetElastic, "https://es.example/_bulk", "apikey", "application/json", fd)
	err := s.Send(context.Background(), []byte("x"))
	if err == nil {
		t.Fatal("non-2xx should error (so the forwarder retries)")
	}
	if got := fd.last.Header.Get("Authorization"); got != "ApiKey apikey" {
		t.Fatalf("elastic auth header: %q", got)
	}
}

// funcSender adapts a func to a Sender.
type funcSender func(ctx context.Context, payload []byte) error

func (f funcSender) Send(ctx context.Context, payload []byte) error { return f(ctx, payload) }

func TestForwarderDeliverRetriesUntilSuccess(t *testing.T) {
	var calls int32
	s := funcSender(func(_ context.Context, _ []byte) error {
		if atomic.AddInt32(&calls, 1) < 3 {
			return errors.New("transient")
		}
		return nil
	})
	fw := NewForwarder(cefFormatter{}, s, Config{RetryBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, nil)
	if err := fw.Deliver(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if st := fw.Stats(); st.Delivered != 1 || st.Retried < 2 {
		t.Fatalf("stats after retry: %+v", st)
	}
}

func TestForwarderDeliverCancelDoesNotClaimDelivery(t *testing.T) {
	s := funcSender(func(_ context.Context, _ []byte) error { return errors.New("always fails") })
	fw := NewForwarder(cefFormatter{}, s, Config{RetryBackoff: 5 * time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(15 * time.Millisecond); cancel() }()
	err := fw.Deliver(ctx, sampleEvent())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancel error, got %v", err)
	}
	if fw.Stats().Delivered != 0 {
		t.Fatal("a never-acked event must not count as delivered (cursor must not advance)")
	}
}

// TestForwarderBackpressureNoDrop is the core S32 guarantee: a slow/flaky sink
// must not drop events. With a tiny buffer and a flaky sender, every enqueued
// event must still arrive exactly once.
func TestForwarderBackpressureNoDrop(t *testing.T) {
	const n = 200
	var mu sync.Mutex
	seen := map[string]int{}
	var flip int32
	s := funcSender(func(_ context.Context, payload []byte) error {
		// Fail every other call to exercise retry under backpressure.
		if atomic.AddInt32(&flip, 1)%2 == 0 {
			return errors.New("flaky")
		}
		mu.Lock()
		seen[string(payload)]++
		mu.Unlock()
		return nil
	})
	fw := NewForwarder(otlpFormatter{}, s, Config{BufferSize: 4, RetryBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Run(ctx); close(done) }()

	for i := 0; i < n; i++ {
		e := sampleEvent()
		e.Target = fmt.Sprintf("host-%d", i) // make each payload unique
		if err := fw.Enqueue(ctx, e); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	deadline := time.After(5 * time.Second)
	for fw.Stats().Delivered < n {
		select {
		case <-deadline:
			t.Fatalf("timeout: delivered %d/%d", fw.Stats().Delivered, n)
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != n {
		t.Fatalf("expected %d distinct events delivered, got %d (drops!)", n, len(seen))
	}
	for k, c := range seen {
		if c != 1 {
			t.Fatalf("event %q delivered %d times (want exactly once)", k, c)
		}
	}
}

func TestForwarderEnqueueCancel(t *testing.T) {
	fw := NewForwarder(cefFormatter{}, funcSender(func(context.Context, []byte) error { return nil }), Config{BufferSize: 1}, nil)
	// Fill the buffer (no Run draining), then a second Enqueue blocks until cancel.
	_ = fw.Enqueue(context.Background(), sampleEvent())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if err := fw.Enqueue(ctx, sampleEvent()); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked enqueue should return cancel, got %v", err)
	}
}
