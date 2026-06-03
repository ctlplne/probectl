package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/audit"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/siem"
)

func testLog() *slog.Logger { return logging.New(io.Discard, "error", "json") }

// capSender captures delivered payloads and can fail its first N calls (to
// exercise retry). Shared by the unit + integration SIEM tests.
type capSender struct {
	mu        sync.Mutex
	got       [][]byte
	failFirst int
	calls     int
}

func (c *capSender) Send(_ context.Context, p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls <= c.failFirst {
		return errors.New("siem unavailable")
	}
	c.got = append(c.got, append([]byte(nil), p...))
	return nil
}

func (c *capSender) records() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.got))
	copy(out, c.got)
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

// A threat signal mapped through the forwarder reaches the sink as a CEF record
// tagged cat=threat — the SOC sees the raw confidence-scored signal.
func TestSIEMThreatSignalForwardedAsCEF(t *testing.T) {
	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{BufferSize: 8, RetryBackoff: time.Millisecond}, testLog())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Run(ctx); close(done) }()

	sig := incident.Signal{
		TenantID: "t-threat", Plane: "threat", Kind: "ioc.botnet_c2",
		Severity: incident.SeverityCritical, Title: "C2 beacon", Target: "203.0.113.7",
		OccurredAt: time.Now(),
	}
	if err := fw.Enqueue(ctx, signalToSIEM(sig)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	waitFor(t, func() bool { return len(snk.records()) == 1 })
	cancel()
	<-done

	rec := string(snk.records()[0])
	if !strings.HasPrefix(rec, "CEF:0|netctl|netctl|") || !strings.Contains(rec, "cat=threat") {
		t.Fatalf("unexpected threat record: %s", rec)
	}
}

func TestAuditToSIEMRedactsAndMaps(t *testing.T) {
	redact := redactionSet([]string{"Department"}) // case-insensitive extension
	ev := audit.Event{
		Seq: 7, Actor: "alice@example.com", Action: "alert.create", Target: "rule-1",
		Hash: "deadbeef", CreatedAt: time.Now(),
		Data: map[string]any{
			"outcome":    "success",
			"password":   "hunter2",
			"department": "secops",
			"count":      float64(3),
			"enabled":    true,
		},
	}
	got := auditToSIEM("tenant-A", ev, redact)
	if got.TenantID != "tenant-A" || got.Category != siem.CategoryAudit {
		t.Fatalf("tenant/category: %+v", got)
	}
	if got.Actor != "alice@example.com" || got.Action != "alert.create" || got.Target != "rule-1" {
		t.Fatalf("core fields: %+v", got)
	}
	if got.Outcome != "success" || got.Severity != siem.SeverityInfo {
		t.Fatalf("outcome/severity: %+v", got)
	}
	if got.Attributes["password"] != "[redacted]" || got.Attributes["department"] != "[redacted]" {
		t.Fatalf("redaction failed: %v", got.Attributes)
	}
	if got.Attributes["count"] != "3" || got.Attributes["enabled"] != "true" {
		t.Fatalf("value stringify: %v", got.Attributes)
	}
	if got.Attributes["audit.seq"] != "7" || got.Attributes["audit.hash"] != "deadbeef" {
		t.Fatalf("traceability attrs: %v", got.Attributes)
	}
}

func TestAuditSeverityFailureWarns(t *testing.T) {
	ev := audit.Event{Action: "login", Data: map[string]any{"outcome": "failure"}}
	if got := auditToSIEM("t", ev, redactionSet(nil)); got.Severity != siem.SeverityWarning {
		t.Fatalf("failed outcome should warn, got %v", got.Severity)
	}
}

func TestSignalToSIEM(t *testing.T) {
	sig := incident.Signal{
		TenantID: "t1", Plane: "threat", Kind: "ioc.botnet_c2",
		Severity: incident.SeverityCritical, Title: "C2 beacon", Summary: "details",
		Target: "203.0.113.7", Prefix: "203.0.113.0/24",
		Attributes: map[string]string{"intel.source": "feodo"},
		OccurredAt: time.Now(),
	}
	got := signalToSIEM(sig)
	if got.Category != siem.CategoryThreat || got.Severity != siem.SeverityCritical {
		t.Fatalf("threat category/severity: %+v", got)
	}
	if got.Action != "ioc.botnet_c2" || got.Target != "203.0.113.7" || got.Message != "C2 beacon" {
		t.Fatalf("core: %+v", got)
	}
	if got.Attributes["plane"] != "threat" || got.Attributes["prefix"] != "203.0.113.0/24" ||
		got.Attributes["summary"] != "details" || got.Attributes["intel.source"] != "feodo" {
		t.Fatalf("attrs: %v", got.Attributes)
	}

	sig.Plane = "change"
	if got := signalToSIEM(sig); got.Category != siem.CategoryChange {
		t.Fatalf("change plane → configuration category, got %v", got.Category)
	}
}

func TestSignalSeverityMapping(t *testing.T) {
	cases := map[incident.Severity]siem.Severity{
		incident.SeverityCritical: siem.SeverityCritical,
		incident.SeverityWarning:  siem.SeverityWarning,
		incident.SeverityInfo:     siem.SeverityInfo,
		incident.Severity("???"):  siem.SeverityInfo,
	}
	for in, want := range cases {
		if got := siemSeverity(in); got != want {
			t.Fatalf("siemSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestStringifyAny(t *testing.T) {
	if stringifyAny(nil) != "" || stringifyAny("x") != "x" || stringifyAny(true) != "true" {
		t.Fatal("scalar stringify")
	}
	if stringifyAny(float64(2.5)) != "2.5" {
		t.Fatal("float stringify")
	}
	if got := stringifyAny(map[string]any{"a": 1}); got == "" {
		t.Fatal("composite should json-encode")
	}
}

func TestBuildSIEMGating(t *testing.T) {
	log := testLog()
	if _, ok := BuildSIEM(nil, log); ok {
		t.Fatal("nil config must disable")
	}
	if _, ok := BuildSIEM(&config.Config{SIEMEnabled: false}, log); ok {
		t.Fatal("disabled must not build")
	}
	if _, ok := BuildSIEM(&config.Config{SIEMEnabled: true, SIEMEndpoint: ""}, log); ok {
		t.Fatal("missing endpoint must not build")
	}
	if _, ok := BuildSIEM(&config.Config{SIEMEnabled: true, SIEMEndpoint: "https://x", SIEMFormat: "bogus"}, log); ok {
		t.Fatal("unknown format must not build")
	}
	fw, ok := BuildSIEM(&config.Config{
		SIEMEnabled: true, SIEMEndpoint: "https://hec.example", SIEMPreset: "splunk",
	}, log)
	if !ok || fw == nil {
		t.Fatal("valid config should build forwarder")
	}
}
