// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package alert

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- fakes ---

type fakeSource struct {
	samples []Sample
	err     error
}

func (f *fakeSource) Current(context.Context, string, map[string]string) ([]Sample, error) {
	return f.samples, f.err
}

type fakeDoer struct {
	status   int
	err      error
	lastReq  *http.Request
	lastBody []byte
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastReq = req
	if req.Body != nil {
		f.lastBody, _ = io.ReadAll(req.Body)
	}
	st := f.status
	if st == 0 {
		st = 200
	}
	return &http.Response{StatusCode: st, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

type fakeMail struct {
	sent int
	err  error
}

func (f *fakeMail) Send(context.Context, []string, string, string) error {
	if f.err != nil {
		return f.err
	}
	f.sent++
	return nil
}

func thresholdRule() Rule {
	return Rule{
		ID: "r1", TenantID: "t1", Name: "loss-high", Enabled: true,
		Metric: "probectl_probe_loss_ratio", Type: Threshold,
		Comparison: GT, Threshold: 0.5, Severity: SeverityCritical,
	}
}

// --- rule validation ---

func TestRuleValidate(t *testing.T) {
	if err := thresholdRule().Validate(); err != nil {
		t.Errorf("valid threshold rule rejected: %v", err)
	}
	base := Rule{Name: "b", Metric: "m", Type: Baseline, Window: 10, Sensitivity: 3, Severity: SeverityWarning}
	if err := base.Validate(); err != nil {
		t.Errorf("valid baseline rule rejected: %v", err)
	}
	bad := []Rule{
		{Name: "", Metric: "m", Type: Threshold, Comparison: GT},
		{Name: "n", Metric: "", Type: Threshold, Comparison: GT},
		{Name: "n", Metric: "m", Type: Threshold, Comparison: "bogus"},
		{Name: "n", Metric: "m", Type: Baseline, Window: 1, Sensitivity: 3},
		{Name: "n", Metric: "m", Type: Baseline, Window: 5, Sensitivity: 0},
		{Name: "n", Metric: "m", Type: "weird"},
		{Name: "n", Metric: "m", Type: Threshold, Comparison: GT, Channels: []ChannelSpec{{Type: "webhook"}}},
		{Name: "n", Metric: "m", Type: Threshold, Comparison: GT, Channels: []ChannelSpec{{Type: "email"}}},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("bad rule %d should have failed validation", i)
		}
	}
}

func TestThresholdBreaches(t *testing.T) {
	cases := []struct {
		cmp        Comparison
		v, thresh  float64
		wantBreach bool
	}{
		{GT, 0.6, 0.5, true}, {GT, 0.5, 0.5, false},
		{LT, 0.4, 0.5, true}, {GTE, 0.5, 0.5, true},
		{LTE, 0.5, 0.5, true}, {EQ, 1, 1, true}, {NEQ, 1, 2, true},
	}
	for _, c := range cases {
		if got := breaches(c.cmp, c.v, c.thresh); got != c.wantBreach {
			t.Errorf("breaches(%s,%v,%v) = %v", c.cmp, c.v, c.thresh, got)
		}
	}
}

// --- baseline cold-start + anomaly ---

func TestBaselineColdStartThenAnomaly(t *testing.T) {
	b := newBaseline(4)
	for i := 0; i < 4; i++ {
		evaluation := b.evaluate(10, 3)
		if evaluation.anomalous || !evaluation.warming {
			t.Fatalf("sample %d: evaluation=%+v, want non-anomalous warmup", i, evaluation)
		}
	}
	// History established (all 10 → std 0): a different value is anomalous.
	if evaluation := b.evaluate(100, 3); !evaluation.anomalous || evaluation.warming {
		t.Errorf("spike: evaluation=%+v, want anomalous/non-warming", evaluation)
	}
}

func TestBaselineWithVariance(t *testing.T) {
	b := newBaseline(4)
	for _, v := range []float64{9, 10, 11, 10} { // mean 10, std ~0.707
		b.evaluate(v, 3)
	}
	if evaluation := b.evaluate(10.5, 3); evaluation.anomalous { // within 3 sigma (~2.12)
		t.Error("10.5 should be within baseline")
	}
	if evaluation := b.evaluate(100, 3); !evaluation.anomalous {
		t.Error("100 should be anomalous")
	}
}

// --- engine state machine ---

func sample(v float64, labels map[string]string) Sample { return Sample{Labels: labels, Value: v} }

func TestEngineThresholdDebounceFireDedupeResolve(t *testing.T) {
	src := &fakeSource{}
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())

	rule := thresholdRule()
	rule.ForN = 2
	labels := map[string]string{"server_address": "1.1.1.1"}

	src.samples = []Sample{sample(0.9, labels)}
	if a, _ := en.Evaluate(context.Background(), rule); len(a) != 0 {
		t.Fatalf("eval 1: pending, want 0 alerts, got %d", len(a))
	}
	a, _ := en.Evaluate(context.Background(), rule)
	if len(a) != 1 || a[0].State != StateFiring {
		t.Fatalf("eval 2: want 1 firing, got %+v", a)
	}
	if a, _ := en.Evaluate(context.Background(), rule); len(a) != 0 {
		t.Fatalf("eval 3: dedupe, want 0 alerts, got %d", len(a))
	}

	src.samples = []Sample{sample(0.1, labels)}
	a, _ = en.Evaluate(context.Background(), rule)
	if len(a) != 1 || a[0].State != StateResolved {
		t.Fatalf("eval 4: want 1 resolved, got %+v", a)
	}
}

func TestEngineEmitsBoundedLogicalEvaluationTransitions(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	src := &fakeSource{}
	var receipts []EvaluationReceipt
	en := NewEngine(src, nil, discard(), WithEvaluationSink(func(_ context.Context, receipt EvaluationReceipt) error {
		receipts = append(receipts, receipt)
		return nil
	}))
	en.clock = func() time.Time { return now }
	rule := thresholdRule()
	rule.ForN = 2
	rule.UpdatedAt = now.Add(-time.Hour)
	labels := map[string]string{"target": "db", "tenant_id": "t1"}

	src.samples = nil
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	src.samples = []Sample{sample(0.1, labels)}
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	src.samples = []Sample{sample(0.9, labels)}
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		if _, err := en.Evaluate(context.Background(), rule); err != nil {
			t.Fatal(err)
		}
	}
	src.samples = []Sample{sample(0.1, labels)}
	now = now.Add(time.Minute)
	if _, err := en.Evaluate(context.Background(), rule); err != nil {
		t.Fatal(err)
	}

	gotStates := make([]EvaluationState, len(receipts))
	for i, receipt := range receipts {
		gotStates[i] = receipt.State
		if receipt.ContractVersion != EvaluationReceiptVersion ||
			receipt.RuleID != rule.ID ||
			receipt.RuleRevision == "" ||
			receipt.RequiredBreaches != 2 {
			t.Fatalf("receipt %d = %+v", i, receipt)
		}
		if _, exposed := receipt.Labels["tenant_id"]; exposed {
			t.Fatalf("receipt exposed ambient tenant label: %+v", receipt)
		}
		if !strings.HasPrefix(receipt.Fingerprint, "eval:") ||
			len(receipt.Fingerprint) != len("eval:")+64 ||
			strings.Contains(receipt.Fingerprint, "tenant_id") ||
			strings.Contains(receipt.Fingerprint, "target=db") {
			t.Fatalf("receipt fingerprint is not bounded and opaque: %q", receipt.Fingerprint)
		}
	}
	wantStates := []EvaluationState{
		EvaluationNoData, EvaluationNormal, EvaluationPending,
		EvaluationFiring, EvaluationSteady, EvaluationResolved,
	}
	if fmt.Sprint(gotStates) != fmt.Sprint(wantStates) {
		t.Fatalf("states = %v, want %v", gotStates, wantStates)
	}
	if receipts[0].ObservedValue != nil {
		t.Fatalf("no-data receipt has observed value: %+v", receipts[0])
	}
	if receipts[3].ObservedValue == nil || *receipts[3].ObservedValue != 0.9 ||
		receipts[3].Expectation.Threshold == nil ||
		*receipts[3].Expectation.Threshold != rule.Threshold {
		t.Fatalf("firing math receipt = %+v", receipts[3])
	}
}

func TestEngineBaselineReceiptsExposeWarmupAndExpectedBand(t *testing.T) {
	src := &fakeSource{}
	var receipts []EvaluationReceipt
	en := NewEngine(src, nil, discard(), WithEvaluationSink(func(_ context.Context, receipt EvaluationReceipt) error {
		receipts = append(receipts, receipt)
		return nil
	}))
	rule := Rule{
		ID: "b1", TenantID: "t1", Name: "latency", Enabled: true,
		Metric: "rtt", Type: Baseline, Window: 2, Sensitivity: 2,
		Severity: SeverityWarning,
	}
	for _, value := range []float64{10, 10, 100} {
		src.samples = []Sample{sample(value, map[string]string{"target": "db"})}
		if _, err := en.Evaluate(context.Background(), rule); err != nil {
			t.Fatal(err)
		}
	}
	if len(receipts) != 3 ||
		receipts[0].State != EvaluationWarming ||
		receipts[1].WarmupSamples != 2 ||
		receipts[2].State != EvaluationFiring ||
		receipts[2].Expectation.Mean == nil ||
		*receipts[2].Expectation.Mean != 10 ||
		receipts[2].Expectation.Upper == nil ||
		*receipts[2].Expectation.Upper != 10 {
		t.Fatalf("baseline receipts = %+v", receipts)
	}
}

func TestEngineRenotify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	src := &fakeSource{samples: []Sample{sample(0.9, map[string]string{"x": "y"})}}
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())
	en.clock = func() time.Time { return now }

	rule := thresholdRule()
	rule.ForN = 1
	rule.RenotifySeconds = 60

	if a, _ := en.Evaluate(context.Background(), rule); len(a) != 1 {
		t.Fatalf("initial fire: want 1, got %d", len(a))
	}
	now = now.Add(30 * time.Second)
	if a, _ := en.Evaluate(context.Background(), rule); len(a) != 0 {
		t.Fatalf("within renotify window: want 0, got %d", len(a))
	}
	now = now.Add(31 * time.Second) // 61s total
	if a, _ := en.Evaluate(context.Background(), rule); len(a) != 1 {
		t.Fatalf("after renotify window: want 1, got %d", len(a))
	}
}

func TestEngineMultiSeriesIndependent(t *testing.T) {
	src := &fakeSource{samples: []Sample{
		sample(0.9, map[string]string{"server_address": "1.1.1.1"}),
		sample(0.1, map[string]string{"server_address": "8.8.8.8"}),
	}}
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())
	a, _ := en.Evaluate(context.Background(), thresholdRule())
	if len(a) != 1 || a[0].Labels["server_address"] != "1.1.1.1" {
		t.Fatalf("only the breaching series should fire, got %+v", a)
	}
}

func TestEngineDisabledRuleIsSkipped(t *testing.T) {
	src := &fakeSource{err: io.ErrUnexpectedEOF} // would error if queried
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())
	rule := thresholdRule()
	rule.Enabled = false
	if a, err := en.Evaluate(context.Background(), rule); err != nil || len(a) != 0 {
		t.Errorf("disabled rule should be a no-op, got %v / %d", err, len(a))
	}
}

func TestEngineBaselineFires(t *testing.T) {
	src := &fakeSource{}
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())
	rule := Rule{
		ID: "b1", TenantID: "t1", Name: "latency-anomaly", Enabled: true,
		Metric: "probectl_probe_rtt_avg_ms", Type: Baseline, Window: 3, Sensitivity: 2,
		Severity: SeverityWarning,
	}
	labels := map[string]string{"server_address": "1.1.1.1"}

	for _, v := range []float64{20, 21, 19} { // warming
		src.samples = []Sample{sample(v, labels)}
		if a, _ := en.Evaluate(context.Background(), rule); len(a) != 0 {
			t.Fatalf("warming sample %v should not fire", v)
		}
	}
	src.samples = []Sample{sample(500, labels)} // spike
	a, _ := en.Evaluate(context.Background(), rule)
	if len(a) != 1 || a[0].State != StateFiring {
		t.Fatalf("baseline spike should fire, got %+v", a)
	}
}

// --- channels ---

func TestWebhookChannelSignsAndDelivers(t *testing.T) {
	doer := &fakeDoer{status: 200}
	ch := NewWebhookChannel("https://hooks.example/alert", "topsecret", doer)
	alert := Alert{RuleID: "r1", RuleName: "loss-high", TenantID: "t1", State: StateFiring,
		Severity: SeverityCritical, Metric: "probectl_probe_loss_ratio", Value: 0.9, Threshold: 0.5,
		Comparison: GT, Reason: "loss high", At: time.Unix(1_700_000_000, 0)}

	if err := ch.Notify(context.Background(), alert); err != nil {
		t.Fatal(err)
	}

	sigHeader := doer.lastReq.Header.Get(SignatureHeader)
	if !strings.HasPrefix(sigHeader, "sha256=") {
		t.Fatalf("missing/invalid signature header %q", sigHeader)
	}
	mac, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "sha256="))
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.Verify([]byte("topsecret"), doer.lastBody, mac) {
		t.Error("HMAC signature does not verify against the body")
	}

	var payload WebhookPayload
	if err := json.Unmarshal(doer.lastBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != WebhookPayloadVersion || payload.State != "firing" || payload.Rule.Name != "loss-high" {
		t.Errorf("payload = %+v", payload)
	}
	if payload.Value != 0.9 || payload.Comparison != "gt" {
		t.Errorf("payload value/comparison = %v/%s", payload.Value, payload.Comparison)
	}
}

func TestWebhookChannelNon2xxErrors(t *testing.T) {
	ch := NewWebhookChannel("https://hooks.example/alert", "", &fakeDoer{status: 500})
	if err := ch.Notify(context.Background(), Alert{At: time.Now()}); err == nil {
		t.Error("a 5xx webhook response should error")
	}
}

func TestEmailChannel(t *testing.T) {
	mail := &fakeMail{}
	ch := NewEmailChannel([]string{"ops@example.com"}, mail)
	if err := ch.Notify(context.Background(), Alert{RuleName: "x", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if mail.sent != 1 {
		t.Errorf("mail sent = %d, want 1", mail.sent)
	}
}

// --- notifier degradation ---

func TestNotifierDeliversAndDegrades(t *testing.T) {
	rule := thresholdRule()
	rule.Channels = []ChannelSpec{
		{Type: "webhook", URL: "https://hooks.example/a"},
		{Type: "email", Recipients: []string{"ops@example.com"}},
	}
	alert := Alert{RuleName: "loss-high", At: time.Now()}

	// Webhook fails, email succeeds → 1 delivered, not 0 (a bad channel doesn't block others).
	n := NewNotifier(ChannelDeps{HTTPClient: &fakeDoer{err: io.ErrClosedPipe}, Mail: &fakeMail{}}, discard())
	if got := n.Deliver(context.Background(), rule, alert); got != 1 {
		t.Errorf("delivered = %d, want 1 (email despite webhook failure)", got)
	}

	// Both succeed → 2.
	n2 := NewNotifier(ChannelDeps{HTTPClient: &fakeDoer{status: 202}, Mail: &fakeMail{}}, discard())
	if got := n2.Deliver(context.Background(), rule, alert); got != 2 {
		t.Errorf("delivered = %d, want 2", got)
	}
}

func TestEvaluatorTickEvaluatesAllRules(t *testing.T) {
	src := &fakeSource{samples: []Sample{sample(0.9, map[string]string{"x": "y"})}}
	en := NewEngine(src, NewNotifier(ChannelDeps{}, discard()), discard())
	rp := ruleSlice{thresholdRule()}
	ev := NewEvaluator(en, rp, time.Minute, discard())
	if err := ev.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type ruleSlice []Rule

func (rs ruleSlice) Rules(context.Context) ([]Rule, error) { return rs, nil }
