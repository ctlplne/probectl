// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func sampleIncident() incident.Incident {
	return incident.Incident{ID: "i1", TenantID: "t1", Title: "packet loss high", Severity: incident.SeverityCritical, Target: "10.0.0.5"}
}

func drain(t *testing.T, d *Dispatcher, tenant string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := d.Drain(ctx, tenant); err != nil {
		t.Fatalf("drain dispatcher: %v", err)
	}
}

// --- fake HTTP client ---

type capReq struct {
	method, url string
	header      http.Header
	body        []byte
}

type fakeDoer struct {
	mu      sync.Mutex
	reqs    []capReq
	respond func(method, url string, body []byte) (int, string)
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, capReq{req.Method, req.URL.String(), req.Header.Clone(), b})
	f.mu.Unlock()
	status, body := 200, "{}"
	if f.respond != nil {
		status, body = f.respond(req.Method, req.URL.String(), b)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
}

func (f *fakeDoer) calls() []capReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]capReq, len(f.reqs))
	copy(out, f.reqs)
	return out
}

func bodyJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("body not json: %v (%s)", err, b)
	}
	return m
}

// --- in-memory link store ---

type memStore struct {
	mu        sync.Mutex
	m         map[string]*Link
	incidents map[string][]incident.Incident
}

func newMemStore() *memStore {
	return &memStore{m: map[string]*Link{}, incidents: map[string][]incident.Incident{}}
}
func lk(t, i, c string) string { return t + "|" + i + "|" + c }

func (s *memStore) Get(_ context.Context, t, i, c string) (*Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.m[lk(t, i, c)]; l != nil {
		cp := *l
		return &cp, nil
	}
	return nil, nil
}

func (s *memStore) Upsert(_ context.Context, l Link) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := l
	s.m[lk(l.TenantID, l.IncidentID, l.Connector)] = &cp
	return nil
}

func (s *memStore) FindByRef(_ context.Context, t, c, ref string) (*Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.m {
		if l.TenantID == t && l.Connector == c && l.ExternalRef == ref {
			cp := *l
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *memStore) ListIncidents(_ context.Context, tenant string) ([]incident.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]incident.Incident(nil), s.incidents[tenant]...), nil
}

func (s *memStore) setIncidents(tenant string, incidents ...incident.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.incidents[tenant] = append([]incident.Incident(nil), incidents...)
}

// --- connector payload tests ---

func TestPagerDutyOpenResolve(t *testing.T) {
	fd := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) { return 202, "{}" }}
	pd := newPagerDuty("https://pd.test/enqueue", "rk-1", fd)
	inc := sampleIncident()

	del, err := pd.Open(context.Background(), inc)
	if err != nil || del.ExternalRef != "probectl-i1" {
		t.Fatalf("open: %v ref=%q", err, del.ExternalRef)
	}
	got := bodyJSON(t, fd.calls()[0].body)
	if got["routing_key"] != "rk-1" || got["event_action"] != "trigger" || got["dedup_key"] != "probectl-i1" {
		t.Fatalf("trigger payload: %v", got)
	}
	if p, _ := got["payload"].(map[string]any); p["severity"] != "critical" {
		t.Fatalf("severity: %v", got["payload"])
	}

	if err := pd.Resolve(context.Background(), inc, del.ExternalRef); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got2 := bodyJSON(t, fd.calls()[1].body)
	if got2["event_action"] != "resolve" || got2["dedup_key"] != "probectl-i1" {
		t.Fatalf("resolve payload: %v", got2)
	}
}

func TestOpsgenieOpenResolve(t *testing.T) {
	fd := &fakeDoer{}
	og := newOpsgenie("https://og.test/v2/alerts", "key1", fd)
	inc := sampleIncident()

	del, err := og.Open(context.Background(), inc)
	if err != nil || del.ExternalRef != "probectl-i1" {
		t.Fatalf("open: %v", err)
	}
	c0 := fd.calls()[0]
	if c0.header.Get("Authorization") != "GenieKey key1" {
		t.Fatalf("auth header: %q", c0.header.Get("Authorization"))
	}
	if b := bodyJSON(t, c0.body); b["alias"] != "probectl-i1" || b["priority"] != "P1" {
		t.Fatalf("open body: %v", b)
	}
	if err := og.Resolve(context.Background(), inc, del.ExternalRef); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if u := fd.calls()[1].url; !strings.Contains(u, "/probectl-i1/close?identifierType=alias") {
		t.Fatalf("close url: %s", u)
	}
}

func TestChatOpenResolve(t *testing.T) {
	fd := &fakeDoer{}
	c := newChat("slack", "https://hooks.slack.test/x", fd)
	inc := sampleIncident()
	if _, err := c.Open(context.Background(), inc); err != nil {
		t.Fatalf("open: %v", err)
	}
	if txt, _ := bodyJSON(t, fd.calls()[0].body)["text"].(string); !strings.Contains(txt, "incident opened") {
		t.Fatalf("open text: %q", txt)
	}
	if err := c.Resolve(context.Background(), inc, "i1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if txt, _ := bodyJSON(t, fd.calls()[1].body)["text"].(string); !strings.Contains(txt, "resolved") {
		t.Fatalf("resolve text: %q", txt)
	}
}

func TestServiceNowOpenResolve(t *testing.T) {
	fd := &fakeDoer{respond: func(method, _ string, _ []byte) (int, string) {
		if method == "POST" {
			return 201, `{"result":{"sys_id":"sys-9","number":"INC0010"}}`
		}
		return 200, "{}"
	}}
	sn := newServiceNow("https://snow.test/api/now/table/incident", "user:pw", fd)
	inc := sampleIncident()

	del, err := sn.Open(context.Background(), inc)
	if err != nil || del.ExternalRef != "sys-9" || del.Status != "INC0010" {
		t.Fatalf("open: %v ref=%q status=%q", err, del.ExternalRef, del.Status)
	}
	if a := fd.calls()[0].header.Get("Authorization"); !strings.HasPrefix(a, "Basic ") {
		t.Fatalf("auth: %q", a)
	}
	if err := sn.Resolve(context.Background(), inc, "sys-9"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rc := fd.calls()[1]
	if rc.method != "PATCH" || !strings.HasSuffix(rc.url, "/sys-9") {
		t.Fatalf("resolve req: %s %s", rc.method, rc.url)
	}
	if b := bodyJSON(t, rc.body); b["state"] != "6" {
		t.Fatalf("resolve state: %v", b)
	}
}

func TestJiraEndpointParseAndOpenResolve(t *testing.T) {
	fd := &fakeDoer{respond: func(method, url string, _ []byte) (int, string) {
		if method == "POST" && strings.HasSuffix(url, "/issue") {
			return 201, `{"key":"OPS-1","id":"100"}`
		}
		return 204, "{}"
	}}
	j := newJira("https://jira.test/rest/api/2/issue?project=OPS&resolve_transition=41", "email:tok", fd)
	if j.project != "OPS" || j.transition != "41" || j.createURL != "https://jira.test/rest/api/2/issue" {
		t.Fatalf("jira parse: project=%q transition=%q createURL=%q", j.project, j.transition, j.createURL)
	}
	inc := sampleIncident()
	del, err := j.Open(context.Background(), inc)
	if err != nil || del.ExternalRef != "OPS-1" {
		t.Fatalf("open: %v ref=%q", err, del.ExternalRef)
	}
	fields := bodyJSON(t, fd.calls()[0].body)["fields"].(map[string]any)
	if proj := fields["project"].(map[string]any); proj["key"] != "OPS" {
		t.Fatalf("project: %v", proj)
	}
	if err := j.Resolve(context.Background(), inc, "OPS-1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rc := fd.calls()[1]
	if rc.url != "https://jira.test/rest/api/2/issue/OPS-1/transitions" {
		t.Fatalf("transition url: %s", rc.url)
	}
	if tr := bodyJSON(t, rc.body)["transition"].(map[string]any); tr["id"] != "41" {
		t.Fatalf("transition id: %v", tr)
	}
}

func TestPSALifecycleContractIsSignedRedactedAndStable(t *testing.T) {
	fd := &fakeDoer{respond: func(_ string, _ string, body []byte) (int, string) {
		var event psaEvent
		_ = json.Unmarshal(body, &event)
		if event.Action == "create" {
			return 201, `{"external_ref":"TICKET-7","status":"open"}`
		}
		return 202, `{}`
	}}
	p := newPSA("https://psa.test/probectl", "shared-hmac-secret", fd)
	inc := sampleIncident()
	inc.Title = "customer password=hunter22 at 10.0.0.5"
	inc.StartedAt = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	inc.LastSeenAt = inc.StartedAt.Add(time.Minute)
	inc.SignalCount = 3

	delivery, err := p.Open(context.Background(), inc)
	if err != nil || delivery.ExternalRef != "TICKET-7" {
		t.Fatalf("create = %+v err=%v", delivery, err)
	}
	if err := p.Update(context.Background(), inc, delivery.ExternalRef); err != nil {
		t.Fatal(err)
	}
	inc.Status = incident.StatusResolved
	if err := p.Resolve(context.Background(), inc, delivery.ExternalRef); err != nil {
		t.Fatal(err)
	}
	inc.Status = incident.StatusOpen
	if err := p.Reopen(context.Background(), inc, delivery.ExternalRef); err != nil {
		t.Fatal(err)
	}

	calls := fd.calls()
	if len(calls) != 4 {
		t.Fatalf("calls=%d want=4", len(calls))
	}
	for i, wantAction := range []string{"create", "update", "resolve", "reopen"} {
		call := calls[i]
		var event psaEvent
		if err := json.Unmarshal(call.body, &event); err != nil {
			t.Fatal(err)
		}
		if event.Contract != PSAContractVersion || event.Action != wantAction || event.IdempotencyKey != call.header.Get("Idempotency-Key") {
			t.Fatalf("event %d = %+v headers=%v", i, event, call.header)
		}
		mac, err := hex.DecodeString(strings.TrimPrefix(call.header.Get(PSASignatureHeader), "sha256="))
		if err != nil || !crypto.Verify([]byte("shared-hmac-secret"), call.body, mac) {
			t.Fatalf("event %d signature invalid: %v", i, err)
		}
		body := string(call.body)
		for _, forbidden := range []string{"t1", "10.0.0.5", "hunter22", "customer password"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("PSA event leaked %q: %s", forbidden, body)
			}
		}
	}
	// Repeating the same revision yields the same receiver-side idempotency key.
	if _, err := p.Open(context.Background(), inc); err != nil {
		t.Fatal(err)
	}
	if got := fd.calls()[4].header.Get("Idempotency-Key"); got != calls[0].header.Get("Idempotency-Key") {
		t.Fatalf("create idempotency key drifted: %q != %q", got, calls[0].header.Get("Idempotency-Key"))
	}
}

func TestDispatcherPSARetriesAndMirrorsFullLifecycle(t *testing.T) {
	store := newMemStore()
	attempts := 0
	fd := &fakeDoer{respond: func(_ string, _ string, body []byte) (int, string) {
		var event psaEvent
		_ = json.Unmarshal(body, &event)
		if event.Action == "create" {
			attempts++
			if attempts < 3 {
				return 503, `{}`
			}
			return 201, `{"external_ref":"PSA-1","status":"open"}`
		}
		return 202, `{}`
	}}
	d := NewDispatcher(store, quiet()).withDispatchControls(4, time.Second)
	d.Register("t1", newPSA("https://psa.test/hook", "secret", fd))
	inc := sampleIncident()
	inc.SignalCount = 1
	inc.StartedAt = time.Now().Add(-time.Minute)
	inc.LastSeenAt = time.Now()

	d.Opened(context.Background(), inc)
	d.Updated(context.Background(), func() incident.Incident { inc.SignalCount = 2; return inc }())
	d.Resolved(context.Background(), func() incident.Incident { inc.Status = incident.StatusResolved; return inc }(), "api")
	d.Reopened(context.Background(), func() incident.Incident { inc.Status = incident.StatusOpen; return inc }())
	drain(t, d, "t1")

	actions := []string{}
	for _, call := range fd.calls() {
		var event psaEvent
		if json.Unmarshal(call.body, &event) == nil {
			actions = append(actions, event.Action)
		}
	}
	if got := strings.Join(actions, ","); got != "create,create,create,update,resolve,reopen" {
		t.Fatalf("lifecycle/retry actions = %s", got)
	}
	link, _ := store.Get(context.Background(), "t1", "i1", "psa")
	if link == nil || link.ExternalRef != "PSA-1" || link.Status != "open" {
		t.Fatalf("final link = %+v", link)
	}
}

// --- dispatcher: idempotency, loop protection, graceful degrade ---

func countAction(calls []capReq, action string) int {
	n := 0
	for _, c := range calls {
		var m map[string]any
		if json.Unmarshal(c.body, &m) == nil && m["event_action"] == action {
			n++
		}
	}
	return n
}

func TestDispatcherOpenIsIdempotent(t *testing.T) {
	store := newMemStore()
	fd := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) { return 202, "{}" }}
	d := NewDispatcher(store, quiet())
	d.Register("t1", newPagerDuty("https://pd.test/enqueue", "rk", fd))
	inc := sampleIncident()

	d.Opened(context.Background(), inc)
	d.Opened(context.Background(), inc) // a retry / control-plane restart
	drain(t, d, "t1")

	if n := countAction(fd.calls(), "trigger"); n != 1 {
		t.Fatalf("expected exactly one page on retry, got %d", n)
	}
	if l, _ := store.Get(context.Background(), "t1", "i1", "pagerduty"); l == nil || l.ExternalRef != "probectl-i1" {
		t.Fatalf("link not persisted: %+v", l)
	}
}

func TestDispatcherLoopProtection(t *testing.T) {
	store := newMemStore()
	snFD := &fakeDoer{respond: func(method, _ string, _ []byte) (int, string) {
		if method == "POST" {
			return 201, `{"result":{"sys_id":"sys-9","number":"INC1"}}`
		}
		return 200, "{}"
	}}
	pdFD := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) { return 202, "{}" }}
	d := NewDispatcher(store, quiet())
	d.Register("t1", newServiceNow("https://snow.test/api/now/table/incident", "u:p", snFD))
	d.Register("t1", newPagerDuty("https://pd.test/enqueue", "rk", pdFD))
	inc := sampleIncident()

	d.Opened(context.Background(), inc)
	// Resolution ARRIVED from servicenow → sync pagerduty, do NOT echo servicenow.
	d.Resolved(context.Background(), inc, "servicenow")
	drain(t, d, "t1")

	if got := countAction(pdFD.calls(), "resolve"); got != 1 {
		t.Fatalf("pagerduty should be resolved once, got %d", got)
	}
	for _, c := range snFD.calls() {
		if c.method == "PATCH" {
			t.Fatal("servicenow must NOT be resolved again (echo loop)")
		}
	}
	// Both links are nonetheless marked resolved (mirror stays accurate).
	for _, conn := range []string{"servicenow", "pagerduty"} {
		if l, _ := store.Get(context.Background(), "t1", "i1", conn); l == nil || l.Status != "resolved" {
			t.Fatalf("%s link status: %+v", conn, l)
		}
	}

	// A duplicate inbound resolve is a no-op (idempotent).
	before := len(pdFD.calls())
	d.Resolved(context.Background(), inc, "servicenow")
	drain(t, d, "t1")
	if len(pdFD.calls()) != before {
		t.Fatal("duplicate resolve should be a no-op")
	}
}

func TestDispatcherGracefulDegrade(t *testing.T) {
	store := newMemStore()
	badFD := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) { return 500, "boom" }}
	okFD := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) { return 202, "{}" }}
	d := NewDispatcher(store, quiet())
	d.Register("t1", newOpsgenie("https://og.test/v2/alerts", "k", badFD)) // fails
	d.Register("t1", newPagerDuty("https://pd.test/enqueue", "rk", okFD))  // succeeds
	inc := sampleIncident()

	d.Opened(context.Background(), inc) // must not panic
	drain(t, d, "t1")

	if l, _ := store.Get(context.Background(), "t1", "i1", "opsgenie"); l != nil {
		t.Fatal("a failed open must not persist a link (so it retries next time)")
	}
	if l, _ := store.Get(context.Background(), "t1", "i1", "pagerduty"); l == nil {
		t.Fatal("the healthy connector should still have opened")
	}
}

func TestDispatcherReconcileRecoversPSALifecycle(t *testing.T) {
	store := newMemStore()
	fd := &fakeDoer{respond: func(_, _ string, body []byte) (int, string) {
		var event psaEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Fatalf("decode PSA event: %v", err)
		}
		if event.Action == "create" {
			return http.StatusCreated, `{"external_ref":"PSA-1","status":"open"}`
		}
		return http.StatusOK, `{}`
	}}
	d := NewDispatcher(store, quiet())
	d.Register("t1", newPSA("https://psa.test/tickets", "signing-secret", fd))

	inc := sampleIncident()
	inc.Status = incident.StatusOpen
	inc.SignalCount = 3
	store.setIncidents("t1", inc)
	d.Reconcile(context.Background())
	link, _ := store.Get(context.Background(), "t1", inc.ID, "psa")
	if link == nil || link.ExternalRef != "PSA-1" || link.Revision != 3 || link.Status != "open" {
		t.Fatalf("create reconciliation link = %+v", link)
	}

	inc.SignalCount = 4
	store.setIncidents("t1", inc)
	d.Reconcile(context.Background())
	link, _ = store.Get(context.Background(), "t1", inc.ID, "psa")
	if link == nil || link.Revision != 4 || link.Status != "open" {
		t.Fatalf("update reconciliation link = %+v", link)
	}

	inc.Status = incident.StatusResolved
	store.setIncidents("t1", inc)
	d.Reconcile(context.Background())
	link, _ = store.Get(context.Background(), "t1", inc.ID, "psa")
	if link == nil || link.Status != "resolved" {
		t.Fatalf("resolve reconciliation link = %+v", link)
	}

	inc.Status = incident.StatusOpen
	inc.SignalCount = 5
	store.setIncidents("t1", inc)
	d.Reconcile(context.Background())
	link, _ = store.Get(context.Background(), "t1", inc.ID, "psa")
	if link == nil || link.Status != "open" || link.Revision != 5 {
		t.Fatalf("reopen reconciliation link = %+v", link)
	}

	actions := make([]string, 0, len(fd.calls()))
	for _, call := range fd.calls() {
		var event psaEvent
		if err := json.Unmarshal(call.body, &event); err != nil {
			t.Fatalf("decode action: %v", err)
		}
		actions = append(actions, event.Action)
	}
	if got, want := strings.Join(actions, ","), "create,update,resolve,reopen"; got != want {
		t.Fatalf("reconciled actions = %q, want %q", got, want)
	}

	// Once the mirror matches the tenant-scoped incident, another pass is a no-op.
	d.Reconcile(context.Background())
	if got := len(fd.calls()); got != 4 {
		t.Fatalf("converged reconciliation sent %d requests, want 4", got)
	}
}

type blockingConnector struct {
	name    string
	started chan struct{}
	once    sync.Once
}

func (c *blockingConnector) Name() string           { return c.name }
func (c *blockingConnector) Capability() Capability { return CapabilityPager }
func (c *blockingConnector) Open(ctx context.Context, _ incident.Incident) (Delivery, error) {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return Delivery{}, ctx.Err()
}
func (c *blockingConnector) Resolve(ctx context.Context, _ incident.Incident, _ string) error {
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return ctx.Err()
}

func TestDispatcherConnectorTimeoutReleasesTenantQueue(t *testing.T) {
	store := newMemStore()
	slow := &blockingConnector{name: "slow", started: make(chan struct{})}
	d := NewDispatcher(store, quiet()).withDispatchControls(4, 25*time.Millisecond)
	d.Register("t1", slow)

	start := time.Now()
	d.Opened(context.Background(), sampleIncident())
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("slow connector did not start")
	}
	drain(t, d, "t1")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("connector timeout did not release queue promptly; elapsed=%s", elapsed)
	}
	if l, _ := store.Get(context.Background(), "t1", "i1", "slow"); l != nil {
		t.Fatal("timed-out connector must not persist an open link")
	}
}

// --- inbound verification + parsing ---

func TestVerifyInbound(t *testing.T) {
	secret, body := "s3cr3t", []byte(`{"external_ref":"x"}`)
	good := http.Header{}
	good.Set(InboundSignatureHeader, "sha256="+hex.EncodeToString(crypto.Sign([]byte(secret), body)))
	if !VerifyInbound(secret, body, good) {
		t.Fatal("valid HMAC should verify")
	}
	bad := http.Header{}
	bad.Set(InboundSignatureHeader, "sha256=deadbeef")
	if VerifyInbound(secret, body, bad) {
		t.Fatal("forged HMAC must fail")
	}
	tok := http.Header{}
	tok.Set(InboundTokenHeader, secret)
	if !VerifyInbound(secret, body, tok) {
		t.Fatal("matching token should verify")
	}
	wrong := http.Header{}
	wrong.Set(InboundTokenHeader, "nope")
	if VerifyInbound(secret, body, wrong) || VerifyInbound("", body, tok) || VerifyInbound(secret, body, http.Header{}) {
		t.Fatal("wrong token / empty secret / no proof must fail closed")
	}
}

func TestParseInbound(t *testing.T) {
	// ServiceNow native: state 6 = resolved.
	if r, ok := ParseInbound("servicenow", []byte(`{"sys_id":"sys-9","number":"INC1","state":"6"}`)); !ok || r.ExternalRef != "sys-9" || !r.Resolved {
		t.Fatalf("servicenow resolved: %+v ok=%v", r, ok)
	}
	if r, ok := ParseInbound("servicenow", []byte(`{"sys_id":"sys-9","state":"2"}`)); !ok || r.Resolved {
		t.Fatalf("servicenow in-progress should not be resolved: %+v", r)
	}
	// Jira native: done category = resolved.
	jb := []byte(`{"issue":{"key":"OPS-1","fields":{"status":{"statusCategory":{"key":"done"}}}}}`)
	if r, ok := ParseInbound("jira", jb); !ok || r.ExternalRef != "OPS-1" || !r.Resolved {
		t.Fatalf("jira resolved: %+v ok=%v", r, ok)
	}
	// Portable contract (also the PagerDuty/Opsgenie path).
	if r, ok := ParseInbound("pagerduty", []byte(`{"external_ref":"probectl-i1","status":"resolved"}`)); !ok || r.ExternalRef != "probectl-i1" || !r.Resolved {
		t.Fatalf("generic resolved: %+v ok=%v", r, ok)
	}
	if _, ok := ParseInbound("pagerduty", []byte(`{"external_ref":" ","status":"resolved"}`)); ok {
		t.Fatal("generic whitespace external_ref should not parse")
	}
	if _, ok := ParseInbound("servicenow", []byte(`{"sys_id":" ","state":"6"}`)); ok {
		t.Fatal("servicenow whitespace sys_id should not parse")
	}
	if _, ok := ParseInbound("jira", []byte(`{"issue":{"key":" ","fields":{"status":{"statusCategory":{"key":"done"}}}}}`)); ok {
		t.Fatal("jira whitespace issue key should not parse")
	}
	if _, ok := ParseInbound("jira", []byte(`not json`)); ok {
		t.Fatal("garbage should not parse")
	}
}

func TestFactory(t *testing.T) {
	for _, p := range []string{"pagerduty", "opsgenie", "slack", "teams", "servicenow", "jira", "psa"} {
		c, ok := NewConnector(p, "https://x.test", "secret", &fakeDoer{})
		if !ok || c.Name() != p {
			t.Fatalf("connector %q: ok=%v name=%q", p, ok, c.Name())
		}
		if !knownProvider(p) {
			t.Fatalf("KnownProvider(%q) should be true", p)
		}
	}
	if _, ok := NewConnector("nope", "x", "y", nil); ok || knownProvider("nope") {
		t.Fatal("unknown provider must be rejected")
	}
}
