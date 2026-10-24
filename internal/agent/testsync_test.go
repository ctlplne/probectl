// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/testsync"
)

const syncTenant = "55555555-5555-4555-8555-555555555555"

type syncFixture struct {
	t    *testing.T
	priv []byte
	sync *testSyncer
	host *Host
	cfg  TestSyncConfig
}

func newSyncFixture(t *testing.T, mutate ...func(*TestSyncConfig)) *syncFixture {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubFile := filepath.Join(dir, TestSyncPublicKeyFileName)
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	buf, err := openBuffer(filepath.Join(dir, "buffer"), 10000)
	if err != nil {
		t.Fatal(err)
	}
	cfg := TestSyncConfig{PublicKeyFile: pubFile}
	cfg.applyDefaults(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "buffer"))
	for _, m := range mutate {
		m(&cfg)
	}
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	reg.Register("http", canary.NewHTTP)
	reg.Register("tcp", canary.NewTCP)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	host := &Host{buffer: buf, tenantID: syncTenant, agentID: "agent-1", log: log}
	s, err := newTestSyncer(cfg, syncTenant, reg, host, log)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("test sync must be active when the public key is present")
	}
	return &syncFixture{t: t, priv: priv, sync: s, host: host, cfg: cfg}
}

func (f *syncFixture) sign(b testsync.Bundle) []byte {
	f.t.Helper()
	signed, err := testsync.Sign(b, f.priv)
	if err != nil {
		f.t.Fatal(err)
	}
	return signed
}

func noopTest(id string) testsync.Test {
	return testsync.Test{ID: id, Type: "noop", Target: "x", IntervalSeconds: 30, TimeoutSeconds: 5}
}

func refusalReason(err error) string {
	var r *errTestSyncRefused
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}

// G9 fail-closed proof: every bundle that must not run is refused BEFORE it
// reaches the host — the agent keeps running exactly its last verified set.
func TestTestSyncRefusesUnsafeBundles(t *testing.T) {
	f := newSyncFixture(t)
	good := f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 3, Tests: []testsync.Test{noopTest("t-1")}})
	if err := f.sync.accept(good, true); err != nil {
		t.Fatalf("a valid bundle was refused: %v", err)
	}
	if got := f.host.centralIDs(); !slices.Equal(got, []string{"t-1"}) {
		t.Fatalf("central tests = %v, want [t-1]", got)
	}

	otherPriv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := testsync.Sign(testsync.Bundle{TenantID: syncTenant, Epoch: 9, Tests: []testsync.Test{noopTest("evil")}}, otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamper(t, f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 9, Tests: []testsync.Test{noopTest("t-2")}}))
	tooMany := make([]testsync.Test, f.cfg.MaxTests+1)
	for i := range tooMany {
		tooMany[i] = noopTest("cap-" + string(rune('a'+i%26)) + "-" + time.Duration(i).String())
	}
	cases := []struct {
		name, reason string
		signed       []byte
	}{
		{"tampered", "bad_signature", tampered},
		{"wrong key", "bad_signature", forged},
		{"garbage", "malformed", []byte("not json")},
		{"foreign tenant", "foreign_tenant", f.sign(testsync.Bundle{TenantID: "66666666-6666-4666-8666-666666666666", Epoch: 9,
			Tests: []testsync.Test{noopTest("t-foreign")}})},
		{"replayed same version", "stale_version", good},
		{"older version", "stale_version", f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 2, Tests: []testsync.Test{noopTest("t-old")}})},
		{"over cap", "over_cap", f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 9, Tests: tooMany})},
	}
	for _, tc := range cases {
		err := f.sync.accept(tc.signed, true)
		if got := refusalReason(err); got != tc.reason {
			t.Errorf("%s: refusal = %q (%v), want %q", tc.name, got, err, tc.reason)
		}
		if got := f.host.centralIDs(); !slices.Equal(got, []string{"t-1"}) {
			t.Fatalf("%s: refused bundle changed the running set to %v", tc.name, got)
		}
		if v := f.sync.appliedVersion(); v != 3 {
			t.Fatalf("%s: refused bundle moved the applied version to %d", tc.name, v)
		}
	}
}

func tamper(t *testing.T, signed []byte) []byte {
	t.Helper()
	var s testsync.Signed
	if err := json.Unmarshal(signed, &s); err != nil {
		t.Fatal(err)
	}
	var b testsync.Bundle
	if err := json.Unmarshal(s.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	b.Tests[0].Target = "203.0.113.66" // a different target under the old signature
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	s.Bundle = raw
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The per-test policy drops exactly the tests this agent's operator does not
// allow, counts each by reason, and applies the rest.
func TestTestSyncPolicyFiltersTests(t *testing.T) {
	f := newSyncFixture(t, func(c *TestSyncConfig) { c.AllowedTypes = []string{"noop", "http"} })
	tests := []testsync.Test{
		noopTest("ok-noop"),
		{ID: "ok-http", Type: "http", Target: "https://example.com", IntervalSeconds: 60, TimeoutSeconds: 5},
		{ID: "unknown-type", Type: "quantum", Target: "x", IntervalSeconds: 60},
		{ID: "not-allowed-type", Type: "tcp", Target: "example.com:443", IntervalSeconds: 60},
		{ID: "private-literal", Type: "http", Target: "http://10.0.0.5/admin", IntervalSeconds: 60},
		{ID: "metadata", Type: "http", Target: "http://169.254.169.254/latest/meta-data", IntervalSeconds: 60},
		{ID: "loopback-name", Type: "http", Target: "http://localhost:8080/", IntervalSeconds: 60},
		{ID: "private-override", Type: "http", Target: "https://example.com", IntervalSeconds: 60,
			Params: map[string]string{canary.AllowPrivateParam: "true"}},
		{ID: "too-fast", Type: "noop", Target: "x", IntervalSeconds: 1},
		{ID: "zero-interval", Type: "noop", Target: "x"},
		{ID: "bad id with spaces", Type: "noop", Target: "x", IntervalSeconds: 60},
		noopTest("ok-noop"), // duplicate id
	}
	if err := f.sync.accept(f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 1, Tests: tests}), false); err != nil {
		t.Fatal(err)
	}
	if got := f.host.centralIDs(); !slices.Equal(got, []string{"ok-http", "ok-noop"}) {
		t.Fatalf("admitted = %v, want [ok-http ok-noop]", got)
	}
	reasons := map[string]string{}
	for _, tc := range tests {
		reason, _ := f.sync.admitOne(tc, map[string]bool{})
		reasons[tc.ID] = reason
	}
	want := map[string]string{
		"ok-noop": "", "ok-http": "", "unknown-type": "type_not_allowed", "not-allowed-type": "type_not_allowed",
		"private-literal": "private_target", "metadata": "private_target", "loopback-name": "private_target",
		"private-override": "private_target", "too-fast": "interval_below_floor", "zero-interval": "interval_below_floor",
		"bad id with spaces": "invalid_test",
	}
	for id, w := range want {
		if reasons[id] != w {
			t.Errorf("%s: reason %q, want %q", id, reasons[id], w)
		}
	}

	// An agent whose operator allows private targets honors the audited
	// per-test override.
	g := newSyncFixture(t, func(c *TestSyncConfig) { c.AllowPrivateTargets = true })
	if reason, _ := g.sync.admitOne(testsync.Test{ID: "lab", Type: "http", Target: "http://10.0.0.5/",
		IntervalSeconds: 60, Params: map[string]string{canary.AllowPrivateParam: "true"}}, map[string]bool{}); reason != "" {
		t.Fatalf("allow_private_targets agent refused an overridden private test: %s", reason)
	}
	// DPR-306: ...but a private test WITHOUT the exception is refused as
	// private_target (the canary guard's refusal), never as invalid_test.
	for _, target := range []string{"http://10.0.0.5/", "https://127.0.0.1:8443/readyz", "http://localhost:8080/"} {
		if reason, _ := g.sync.admitOne(testsync.Test{ID: "lab-no-exception", Type: "http", Target: target,
			IntervalSeconds: 60}, map[string]bool{}); reason != "private_target" {
			t.Errorf("allow_private_targets agent refused %s without the per-test exception as %q, want private_target", target, reason)
		}
	}
}

// Diff apply: an unchanged test keeps its goroutine; a changed test restarts;
// a removed test stops (no further results carry its id); a new test starts.
func TestTestSyncDiffApplyStartsAndStopsTheRightTests(t *testing.T) {
	f := newSyncFixture(t, func(c *TestSyncConfig) { c.MinInterval = Duration(time.Millisecond) })
	fast := func(id, target string) testsync.Test {
		return testsync.Test{ID: id, Type: "noop", Target: target, IntervalSeconds: 1, TimeoutSeconds: 1}
	}
	if err := f.sync.accept(f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 1,
		Tests: []testsync.Test{fast("keep", "k"), fast("change", "c1"), fast("drop", "d")}}), false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.host.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, func() bool { return len(resultIDs(t, f.host.buffer)["drop"]) > 0 })
	f.host.mu.Lock()
	keepBefore := f.host.central["keep"]
	f.host.mu.Unlock()

	if err := f.sync.accept(f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 2,
		Tests: []testsync.Test{fast("keep", "k"), fast("change", "c2"), fast("new", "n")}}), false); err != nil {
		t.Fatal(err)
	}
	f.host.mu.Lock()
	keepAfter := f.host.central["keep"]
	f.host.mu.Unlock()
	if keepBefore != keepAfter {
		t.Fatal("an unchanged test was restarted")
	}
	if got := f.host.centralIDs(); !slices.Equal(got, []string{"change", "keep", "new"}) {
		t.Fatalf("central tests after v2 = %v", got)
	}
	dropCount := len(resultIDs(t, f.host.buffer)["drop"])
	waitFor(t, func() bool {
		ids := resultIDs(t, f.host.buffer)
		return len(ids["new"]) > 0 && slices.Contains(ids["change"], "c2")
	})
	time.Sleep(1200 * time.Millisecond) // more than one interval of the dropped test
	if got := len(resultIDs(t, f.host.buffer)["drop"]); got != dropCount {
		t.Fatalf("the removed test kept probing: %d results, was %d", got, dropCount)
	}

	// An empty bundle stops every central test.
	if err := f.sync.accept(f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 3}), false); err != nil {
		t.Fatal(err)
	}
	if got := f.host.centralIDs(); len(got) != 0 {
		t.Fatalf("empty bundle left %v running", got)
	}
}

// resultIDs maps each buffered result's test id to the targets it probed.
func resultIDs(t *testing.T, buf *Buffer) map[string][]string {
	t.Helper()
	frames, err := buf.peekAll()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, fr := range frames {
		var env resultEnvelope
		if err := json.Unmarshal(fr, &env); err != nil {
			t.Fatal(err)
		}
		if env.TenantID != syncTenant {
			t.Fatalf("result stamped with tenant %q", env.TenantID)
		}
		id := env.Result.Attributes["probectl.test.id"]
		out[id] = append(out[id], env.Result.Target)
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// The verified bundle is persisted owner-only and re-verified at start; a
// persisted file that no longer verifies is refused, never applied.
func TestTestSyncPersistsAndReverifiesAtStart(t *testing.T) {
	f := newSyncFixture(t)
	signed := f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 4, Tests: []testsync.Test{noopTest("t-1")}})
	if err := f.sync.accept(signed, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f.sync.statePath)
	if err != nil {
		t.Fatalf("verified bundle not persisted: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("persisted bundle mode %v, want 0600", fi.Mode().Perm())
	}

	restart := func() *testSyncer {
		host := &Host{buffer: f.host.buffer, tenantID: syncTenant, log: f.host.log}
		s, err := newTestSyncer(f.cfg, syncTenant, f.sync.reg, host, f.host.log)
		if err != nil {
			t.Fatal(err)
		}
		s.restore()
		return s
	}
	s := restart()
	if s.appliedVersion() != 4 || !slices.Equal(s.host.centralIDs(), []string{"t-1"}) {
		t.Fatalf("restart restored version %d tests %v, want 4 [t-1]", s.appliedVersion(), s.host.centralIDs())
	}

	if err := os.WriteFile(f.sync.statePath, tamper(t, signed), 0o600); err != nil {
		t.Fatal(err)
	}
	s = restart()
	if s.appliedVersion() != 0 || len(s.host.centralIDs()) != 0 {
		t.Fatalf("a tampered persisted bundle was applied at start: version %d tests %v", s.appliedVersion(), s.host.centralIDs())
	}
}

type fakeFetcher struct {
	resp  *agentv1.FetchTestBundleResponse
	err   error
	known []uint64
}

func (f *fakeFetcher) FetchTestBundle(_ context.Context, known uint64) (*agentv1.FetchTestBundleResponse, error) {
	f.known = append(f.known, known)
	return f.resp, f.err
}

// The pull reports the applied version, applies a newer bundle, treats a
// control plane with distribution off as "local tests only", and never lets a
// failed pull change the running set.
func TestTestSyncPull(t *testing.T) {
	f := newSyncFixture(t)
	ctx := context.Background()
	fetch := &fakeFetcher{resp: &agentv1.FetchTestBundleResponse{Version: 2,
		SignedBundle: f.sign(testsync.Bundle{TenantID: syncTenant, Epoch: 2, Tests: []testsync.Test{noopTest("t-1")}})}}
	if !f.sync.due(time.Now()) {
		t.Fatal("a fresh session must pull at once")
	}
	f.sync.pull(ctx, fetch)
	if f.sync.appliedVersion() != 2 || fetch.known[0] != 0 {
		t.Fatalf("pull applied %d (asked with known %v), want 2 / 0", f.sync.appliedVersion(), fetch.known)
	}
	if f.sync.due(time.Now()) {
		t.Fatal("a pull just ran; the next is not due before the interval")
	}
	f.sync.nudge()
	if !f.sync.due(time.Now()) {
		t.Fatal("a heartbeat nudge must make the pull due")
	}

	fetch.resp = &agentv1.FetchTestBundleResponse{NotModified: true, Version: 2}
	f.sync.pull(ctx, fetch)
	fetch.resp, fetch.err = nil, status.Error(codes.FailedPrecondition, "off")
	f.sync.pull(ctx, fetch)
	fetch.err = status.Error(codes.Unavailable, "down")
	f.sync.pull(ctx, fetch)
	if f.sync.appliedVersion() != 2 || !slices.Equal(f.host.centralIDs(), []string{"t-1"}) {
		t.Fatalf("not-modified / off / failed pulls changed the set: version %d tests %v",
			f.sync.appliedVersion(), f.host.centralIDs())
	}
	if !slices.Equal(fetch.known, []uint64{0, 2, 2, 2}) {
		t.Fatalf("known versions sent = %v", fetch.known)
	}
}

// With no public key the agent runs local canaries only; enabled without a key
// is a configuration error, never central tests it cannot verify.
func TestTestSyncActivation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pub")
	on, off := true, false
	if ok, err := (TestSyncConfig{PublicKeyFile: missing}).Active(); ok || err != nil {
		t.Fatalf("no key, unset: active=%v err=%v; want inactive, no error", ok, err)
	}
	if _, err := (TestSyncConfig{PublicKeyFile: missing, Enabled: &on}).Active(); err == nil {
		t.Fatal("enabled without a key must fail closed")
	}
	f := newSyncFixture(t)
	if ok, _ := (TestSyncConfig{PublicKeyFile: f.cfg.PublicKeyFile, Enabled: &off}).Active(); ok {
		t.Fatal("explicitly disabled must stay off")
	}
	bad := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(bad, []byte("-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := f.cfg
	cfg.PublicKeyFile = bad
	if _, err := newTestSyncer(cfg, syncTenant, f.sync.reg, f.host, f.host.log); err == nil {
		t.Fatal("an unparsable public key must refuse to start test sync")
	}
}
