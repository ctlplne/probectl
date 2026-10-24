// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/testsync"
)

// Central test sync, the agent half (G9, D-41,
// docs/adr/central-test-distribution.md). The agent PULLS its tenant's signed
// test set over the mTLS session it already has and applies it only after:
//
//  1. testsync.Verify — the Ed25519 signature checks against the deployment
//     key the agent received at enrollment, and the version is newer than the
//     one it runs (no replay, no rollback);
//  2. the bundle's tenant equals this agent's certificate tenant;
//  3. the local policy (test_sync.*) admits each test: compiled-in and allowed
//     type, no private target unless this agent allows it, an interval at or
//     above the floor, and a bundle no larger than the cap.
//
// Anything refused is counted by reason and the agent keeps its last verified
// set; it is never "applied a little". The verified bundle is persisted (0600)
// and re-verified at start, so central tests survive restarts and outages.

const (
	testSyncStateFile   = "bundle.json"
	testSyncPullTimeout = 30 * time.Second
)

// errTestSyncRefused wraps every whole-bundle refusal with its reason code.
type errTestSyncRefused struct {
	reason string
	err    error
}

func (e *errTestSyncRefused) Error() string {
	return fmt.Sprintf("central test bundle refused (%s): %v", e.reason, e.err)
}

func (e *errTestSyncRefused) Unwrap() error { return e.err }

// testBundleFetcher is the slice of the control-plane client the pull uses.
type testBundleFetcher interface {
	FetchTestBundle(ctx context.Context, knownVersion uint64) (*agentv1.FetchTestBundleResponse, error)
}

type testSyncer struct {
	cfg       TestSyncConfig
	pub       []byte
	tenantID  string
	reg       *canary.Registry
	host      *Host
	log       *slog.Logger
	metrics   *agentmetrics.Runtime
	allowed   map[string]bool
	statePath string

	applied atomic.Uint64 // version verified and applied (0 = none)
	nudged  atomic.Bool   // the last heartbeat said the tenant's set is newer

	mu        sync.Mutex // serializes accept; guards lastPull/serverOff
	lastPull  time.Time
	serverOff bool
}

// newTestSyncer returns nil when central test sync is not active for this
// agent (no public key, or disabled), and an error when it is enabled but
// cannot run safely.
func newTestSyncer(cfg TestSyncConfig, tenantID string, reg *canary.Registry, host *Host, log *slog.Logger) (*testSyncer, error) {
	active, err := cfg.Active()
	if err != nil || !active {
		return nil, err
	}
	pub, err := os.ReadFile(cfg.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("test_sync: read public key: %w", err)
	}
	// Prove the key parses now (fail closed at start, not at the first pull):
	// verifying an empty message must fail with a bad signature, not a bad key.
	if _, err := crypto.VerifyEd25519(pub, []byte("probectl-testsync-key-check"), make([]byte, 64)); err != nil {
		return nil, fmt.Errorf("test_sync: public key %s: %w", cfg.PublicKeyFile, err)
	}
	compiled := reg.Types()
	allowed := map[string]bool{}
	if len(cfg.AllowedTypes) == 0 {
		for _, t := range compiled {
			allowed[t] = true
		}
	} else {
		for _, t := range cfg.AllowedTypes {
			for _, c := range compiled {
				if c == t {
					allowed[t] = true
				}
			}
		}
	}
	return &testSyncer{
		cfg: cfg, pub: pub, tenantID: tenantID, reg: reg, host: host, log: log,
		allowed: allowed, statePath: filepath.Join(cfg.StateDir, testSyncStateFile),
	}, nil
}

// restore re-verifies and re-applies the persisted bundle at start. A missing
// file is the normal first boot; an unverifiable one is refused and ignored.
func (s *testSyncer) restore() {
	raw, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.log.Warn("test sync: persisted bundle unreadable; starting without central tests", "error", err.Error())
		return
	}
	if err := s.accept(raw, false); err != nil {
		s.log.Warn("test sync: persisted bundle refused; starting without central tests", "error", err.Error())
	}
}

// appliedVersion is reported in every heartbeat (config_epoch).
func (s *testSyncer) appliedVersion() uint64 {
	if s == nil {
		return 0
	}
	return s.applied.Load()
}

// nudge records a heartbeat's config_stale: pull at the next session tick.
func (s *testSyncer) nudge() {
	if s != nil {
		s.nudged.Store(true)
	}
}

// due reports whether a pull is owed: never pulled this session, a nudge, or
// the interval elapsed.
func (s *testSyncer) due(now time.Time) bool {
	if s == nil {
		return false
	}
	if s.nudged.Load() {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPull.IsZero() || now.Sub(s.lastPull) >= s.cfg.Interval.Std()
}

// resetSession makes the first tick of a new session pull at once.
func (s *testSyncer) resetSession() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lastPull = time.Time{}
	s.mu.Unlock()
}

// pull fetches the bundle and applies it if it passes every check. A failed
// pull never ends the session: the agent keeps its verified set and results.
func (s *testSyncer) pull(ctx context.Context, c testBundleFetcher) {
	s.nudged.Store(false)
	s.mu.Lock()
	s.lastPull = time.Now()
	s.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, testSyncPullTimeout)
	defer cancel()
	resp, err := c.FetchTestBundle(pctx, s.applied.Load())
	if err != nil {
		s.pullFailed(err)
		return
	}
	s.mu.Lock()
	s.serverOff = false
	s.mu.Unlock()
	if resp.GetNotModified() {
		return
	}
	if err := s.accept(resp.GetSignedBundle(), true); err != nil {
		s.log.Warn("test sync: refused the pulled bundle; keeping the last verified set",
			"applied_version", s.applied.Load(), "offered_version", resp.GetVersion(), "error", err.Error())
	}
}

func (s *testSyncer) pullFailed(err error) {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.Unimplemented:
		// The control plane has distribution off (or predates it): not a
		// failure, and said once rather than every interval.
		s.mu.Lock()
		first := !s.serverOff
		s.serverOff = true
		s.mu.Unlock()
		if first {
			s.log.Info("test sync: central test distribution is off on the control plane; running local tests only",
				"detail", status.Convert(err).Message())
		}
	default:
		if s.metrics != nil {
			s.metrics.TestSyncFetchFailure()
		}
		s.log.Warn("test sync: pull failed; keeping the last verified set", "error", err.Error())
	}
}

// accept verifies, checks the tenant, filters by policy, applies, and (for a
// freshly pulled bundle) persists. The order is the security property: nothing
// reaches the host before Verify and the tenant check pass.
func (s *testSyncer) accept(signed []byte, persist bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := testsync.Verify(signed, s.pub, int64(s.applied.Load()))
	if err != nil {
		return s.refuse(verifyRefusal(err), err)
	}
	if b.TenantID != s.tenantID {
		return s.refuse("foreign_tenant", fmt.Errorf("bundle names tenant %q, this agent's certificate names %q", b.TenantID, s.tenantID))
	}
	if len(b.Tests) > s.cfg.MaxTests {
		return s.refuse("over_cap", fmt.Errorf("bundle has %d tests, test_sync.max_tests is %d", len(b.Tests), s.cfg.MaxTests))
	}
	defs := s.admit(b.Tests)
	started, stopped := s.host.applyCentral(defs)
	s.applied.Store(uint64(b.Epoch))
	if s.metrics != nil {
		s.metrics.SetTestSyncVersion(uint64(b.Epoch))
	}
	if persist {
		if err := s.persist(signed); err != nil {
			s.log.Warn("test sync: could not persist the verified bundle (it applies now, but not across a restart)",
				"error", err.Error())
		}
	}
	s.log.Info("test sync: applied central test set",
		"version", b.Epoch, "tests", len(defs), "refused", len(b.Tests)-len(defs),
		"started", started, "stopped", stopped)
	return nil
}

func (s *testSyncer) refuse(reason string, err error) error {
	if s.metrics != nil {
		s.metrics.TestSyncRefused(reason)
	}
	return &errTestSyncRefused{reason: reason, err: err}
}

func verifyRefusal(err error) string {
	switch {
	case errors.Is(err, testsync.ErrStaleEpoch):
		return "stale_version"
	case errors.Is(err, testsync.ErrBadSignature):
		return "bad_signature"
	default:
		return "malformed"
	}
}

// admit applies the per-test policy and builds the canaries; a refused test
// is dropped (and counted), the rest of the bundle still applies.
func (s *testSyncer) admit(tests []testsync.Test) []centralDef {
	seen := make(map[string]bool, len(tests))
	defs := make([]centralDef, 0, len(tests))
	for _, t := range tests {
		reason, def := s.admitOne(t, seen)
		if reason != "" {
			if s.metrics != nil {
				s.metrics.TestSyncRefused(reason)
			}
			s.log.Warn("test sync: refused a central test", "test_id", t.ID, "type", t.Type, "reason", reason)
			continue
		}
		seen[t.ID] = true
		defs = append(defs, def)
	}
	return defs
}

func (s *testSyncer) admitOne(t testsync.Test, seen map[string]bool) (string, centralDef) {
	if checkTestID(t.ID) != nil || seen[t.ID] {
		return "invalid_test", centralDef{}
	}
	if !s.allowed[t.Type] {
		return "type_not_allowed", centralDef{}
	}
	interval := time.Duration(t.IntervalSeconds) * time.Second
	if interval <= 0 || interval < s.cfg.MinInterval.Std() {
		return "interval_below_floor", centralDef{}
	}
	if !s.cfg.AllowPrivateTargets && (t.Params[canary.AllowPrivateParam] == "true" || privateTarget(t.Target)) {
		return "private_target", centralDef{}
	}
	// DPR-306: an agent that allows private targets still runs one only when
	// the test carries the audited per-test exception; without it the canary's
	// own SSRF guard refuses the target below. Name that private_target too —
	// it used to surface as invalid_test, which sent the operator looking for a
	// malformed test instead of the missing exception.
	if privateTarget(t.Target) && t.Params[canary.AllowPrivateParam] != "true" {
		return "private_target", centralDef{}
	}
	c, err := s.reg.New(canary.Config{
		Type: t.Type, Target: t.Target, Interval: interval,
		Timeout: time.Duration(t.TimeoutSeconds) * time.Second,
		Params:  copyParams(t.Params), TenantID: s.tenantID,
	})
	if err != nil {
		return "invalid_test", centralDef{}
	}
	return "", centralDef{id: t.ID, hash: testHash(t), sched: scheduled{canary: c, interval: interval, testID: t.ID}}
}

// privateTarget reports a target whose host is a literal private, loopback,
// link-local or ambiguous-numeric address, or a localhost name. Hostnames that
// RESOLVE to such addresses are still denied at dial time by the canary's own
// SSRF guard.
func privateTarget(target string) bool {
	host := targetHost(target)
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	return canary.NewTargetGuard(false).CheckHost(host) != nil
}

func targetHost(target string) string {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return strings.Trim(target, "[]")
}

func copyParams(p map[string]string) map[string]string {
	if p == nil {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// testHash identifies a test's definition so an unchanged test keeps running
// across bundle versions.
func testHash(t testsync.Test) string {
	raw, err := json.Marshal(t)
	if err != nil {
		return t.ID
	}
	h := crypto.Hash(raw)
	return hex.EncodeToString(h)
}

// persist writes the verified signed bundle atomically, owner-only.
func (s *testSyncer) persist(signed []byte) error {
	if err := os.MkdirAll(s.cfg.StateDir, 0o700); err != nil {
		return err
	}
	return writeOwnerOnly(s.statePath, signed)
}
