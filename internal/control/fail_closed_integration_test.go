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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/otel/otlp"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFailClosedSignatureTenantBindingCredentialLicenseRealStack is the
// real-stack receipt for CLM-FAIL-CLOSED ("Missing channel security,
// credential, signature, tenant binding, or license state degrades closed,
// never open"). The black-box E2E covers transport and enrollment failures;
// this covers the rest of the claim on the production assembly: control.New in
// session-auth mode over real PostgreSQL, the agent mTLS transport and the
// OTLP receiver (DB token auth + freshness HMAC) publishing to real Kafka, the
// production result fan feeding the latest-results view, a real signed license,
// and the real CLI. Two tenants; every case is driven through a public surface:
//
//   - signature: unsigned / wrong-tenant-signed change webhooks, OTLP without,
//     with a forged, or with a replayed freshness signature, a rollout whose
//     artifact was never signature-verified, and a forged license file are all
//     refused, and nothing they carried is stored or published;
//   - tenant binding: a result whose payload names another tenant is bound to
//     the agent certificate's tenant, a shared-lane record whose payload
//     disagrees with its bus key reaches no tenant, and an OTLP push, API token
//     or CLI call naming another tenant is refused;
//   - credential: no credential, a revoked API token, a missing or revoked OTLP
//     token, a /metrics scrape without its token, a CLI without a token, and an
//     agent without a client certificate all get nothing;
//   - license: past its grace period the license reads read_only, commercial
//     config writes are refused while reads stay up (withdrawing remote-AI
//     consent still works), and agent telemetry keeps flowing.
func TestFailClosedSignatureTenantBindingCredentialLicenseRealStack(t *testing.T) {
	st := newFailClosedStack(t)
	ctx := context.Background()

	t.Run("signature", func(t *testing.T) {
		// Change webhooks: unsigned, and signed with the OTHER tenant's secret.
		body := []byte(`{"title":"fc unsigned deploy","target":"a.example.com"}`)
		if rec := postWebhook(t, st.h, "generic", st.webhookID[st.tenantA], body, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("unsigned change webhook = %d, want 401", rec.Code)
		}
		forged := []byte(`{"title":"fc cross-signed deploy","target":"a.example.com"}`)
		if rec := postWebhook(t, st.h, "generic", st.webhookID[st.tenantA], forged,
			signedGenericHeaders(st.webhookSecret[st.tenantB], forged, "fc-cross-"+st.suffix, time.Now().UTC())); rec.Code != http.StatusUnauthorized {
			t.Fatalf("change webhook signed with tenant B's secret = %d, want 401", rec.Code)
		}
		good := []byte(`{"title":"fc signed deploy","target":"a.example.com"}`)
		if rec := postWebhook(t, st.h, "generic", st.webhookID[st.tenantA], good,
			signedGenericHeaders(st.webhookSecret[st.tenantA], good, "fc-good-"+st.suffix, time.Now().UTC())); rec.Code != http.StatusAccepted {
			t.Fatalf("correctly signed change webhook = %d, want 202", rec.Code)
		}
		changesA, changesB := st.alice.text(t, "/v1/changes"), st.carol.text(t, "/v1/changes")
		if !strings.Contains(changesA, "fc signed deploy") || strings.Contains(changesA, "fc unsigned deploy") || strings.Contains(changesA, "fc cross-signed deploy") {
			t.Fatalf("tenant A's timeline must hold only the signed change: %s", changesA)
		}
		if strings.Contains(changesB, "fc ") {
			t.Fatalf("tenant B's timeline received tenant A's changes: %s", changesB)
		}

		// OTLP: the freshness signature is required, must verify, and is single-use.
		token, _ := st.alice.mintOTLPToken(t)
		req := fcMetrics(st.tenantA)
		if code := st.pushOTLP(t, token, req, nil); code != http.StatusUnauthorized {
			t.Fatalf("OTLP push without a freshness signature = %d, want 401", code)
		}
		if code := st.pushOTLP(t, token, req, st.otlpSignature(t, []byte("not-the-freshness-key"), req, "fc-forged-"+st.suffix)); code != http.StatusUnauthorized {
			t.Fatalf("OTLP push with a forged freshness signature = %d, want 401", code)
		}
		signed := st.otlpSignature(t, st.freshKey, req, "fc-once-"+st.suffix)
		if code := st.pushOTLP(t, token, req, signed); code != http.StatusOK {
			t.Fatalf("correctly signed OTLP push = %d, want 200", code)
		}
		if code := st.pushOTLP(t, token, req, signed); code != http.StatusUnauthorized {
			t.Fatalf("replayed OTLP push = %d, want 401", code)
		}
		st.awaitOTLPMessages(t, st.tenantA, 1)
		time.Sleep(2 * time.Second) // a wrongly accepted push would have been published by now
		if got := st.otlpMessages(st.tenantA); got != 1 {
			t.Fatalf("OTLP records published for tenant A = %d, want exactly 1 (refused pushes must publish nothing)", got)
		}

		// Rollouts: an artifact that was never signature-verified never plans.
		digest := "sha256:" + hex.EncodeToString(crypto.Hash([]byte("fc-artifact-"+st.suffix)))
		for _, method := range []string{"none", "skipped cosign"} {
			code, body := st.alice.do(t, http.MethodPost, "/v1/rollouts",
				map[string]any{"version": "v9.9.9", "digest": digest, "verify_method": method})
			// Refused BY the signature-verification check, not by anything later.
			if code != http.StatusBadRequest || !strings.Contains(string(body), "is not a recognized signature verification") {
				t.Fatalf("rollout with verify_method %q = %d %s, want 400 refusing the unverified artifact", method, code, body)
			}
		}
		if rollouts := st.alice.text(t, "/v1/rollouts"); strings.Contains(rollouts, "v9.9.9") {
			t.Fatalf("an unverified rollout was stored: %s", rollouts)
		}

		// License files: forged, tampered, or configured-but-missing refuse startup.
		for name, path := range map[string]string{
			"signed by an untrusted key": st.licenseFile(t, time.Now().Add(90*24*time.Hour), false),
			"tampered after signing":     st.licenseFile(t, time.Now().Add(90*24*time.Hour), true),
			"configured but missing":     filepath.Join(t.TempDir(), "absent-license.json"),
		} {
			if _, err := BuildLicense(&config.Config{LicenseFile: path}, quietLog()); err == nil {
				t.Fatalf("a license %s must refuse startup, BuildLicense accepted it", name)
			}
		}
		if m, err := BuildLicense(&config.Config{}, quietLog()); err != nil || m.Tier() != license.TierCore {
			t.Fatalf("no license configured = %v, %v; want the Community core", m, err)
		}
	})

	t.Run("tenant binding", func(t *testing.T) {
		// An agent of tenant A sends a result whose payload names tenant B: the
		// certificate decides, so it is A's result and B never sees it.
		st.streamAgentResult(t, st.tenantA, &resultv1.Result{TenantId: st.tenantB, CanaryType: "http",
			ServerAddress: "fc-agent-claims-b.example", Success: true, StartTimeUnixNano: time.Now().UnixNano()})
		st.alice.awaitLatest(t, "fc-agent-claims-b.example")
		if latestB := st.carol.text(t, "/v1/results/latest"); strings.Contains(latestB, "fc-agent-claims-b.example") {
			t.Fatalf("a result from tenant A's agent reached tenant B: %s", latestB)
		}

		// A shared-lane record keyed to tenant A but claiming tenant B reaches no
		// one. The sentinel shares its key (so its partition and order): once A
		// sees the sentinel, the forged record ahead of it has been consumed.
		key := bus.TenantKey(st.tenantA, "fc-forger")
		st.publishResult(t, key, &resultv1.Result{TenantId: st.tenantB, AgentId: "fc-forger", CanaryType: "http",
			ServerAddress: "fc-forged-into-b.example", Success: true, StartTimeUnixNano: time.Now().UnixNano()})
		st.publishResult(t, key, &resultv1.Result{TenantId: st.tenantA, AgentId: "fc-forger", CanaryType: "http",
			ServerAddress: "fc-sentinel-a.example", Success: true, StartTimeUnixNano: time.Now().UnixNano()})
		st.alice.awaitLatest(t, "fc-sentinel-a.example")
		for who, u := range map[string]*fcUser{"A": st.alice, "B": st.carol} {
			if latest := u.text(t, "/v1/results/latest"); strings.Contains(latest, "fc-forged-into-b.example") {
				t.Fatalf("a record whose payload disagreed with its bus key reached tenant %s: %s", who, latest)
			}
		}

		// OTLP: tenant A's token cannot write a resource that names tenant B.
		token, _ := st.alice.mintOTLPToken(t)
		cross := fcMetrics(st.tenantB)
		if code := st.pushOTLP(t, token, cross, st.otlpSignature(t, st.freshKey, cross, "fc-cross-otlp-"+st.suffix)); code != http.StatusForbidden {
			t.Fatalf("OTLP push naming another tenant = %d, want 403", code)
		}

		// API and CLI: tenant A's token naming tenant B is refused.
		apiToken, _ := st.alice.mintAPIToken(t)
		if code := st.bearer(t, apiToken, st.tenantB, "/v1/results/latest"); code != http.StatusUnauthorized {
			t.Fatalf("tenant A's API token naming tenant B = %d, want 401", code)
		}
		if out, code := st.cli(t, apiToken, st.tenantB, "isolation", "status"); code == 0 {
			t.Fatalf("CLI with tenant A's token naming tenant B exited 0: %s", out)
		}
	})

	t.Run("credential", func(t *testing.T) {
		for _, path := range []string{"/v1/results/latest", "/v1/isolation/status"} {
			if code := st.bearer(t, "", "", path); code != http.StatusUnauthorized {
				t.Fatalf("%s with no credential = %d, want 401", path, code)
			}
		}

		apiToken, id := st.alice.mintAPIToken(t)
		if code := st.bearer(t, apiToken, "", "/v1/isolation/status"); code != http.StatusOK {
			t.Fatalf("live API token = %d, want 200", code)
		}
		if out, code := st.cli(t, apiToken, "", "isolation", "status"); code != 0 {
			t.Fatalf("CLI with a live token exited %d: %s", code, out)
		}
		if code, body := st.alice.do(t, http.MethodDelete, "/v1/api-tokens/"+id, nil); code != http.StatusOK && code != http.StatusNoContent {
			t.Fatalf("revoke API token = %d: %s", code, body)
		}
		if code := st.bearer(t, apiToken, "", "/v1/isolation/status"); code != http.StatusUnauthorized {
			t.Fatalf("revoked API token = %d, want 401", code)
		}
		if out, code := st.cli(t, "", "", "isolation", "status"); code == 0 {
			t.Fatalf("CLI without a token exited 0: %s", out)
		}

		otlpToken, otlpID := st.alice.mintOTLPToken(t)
		req := fcMetrics(st.tenantA)
		if code := st.pushOTLP(t, "", req, st.otlpSignature(t, st.freshKey, req, "fc-notoken-"+st.suffix)); code != http.StatusUnauthorized {
			t.Fatalf("OTLP push without a token = %d, want 401", code)
		}
		if code, body := st.alice.do(t, http.MethodDelete, "/v1/otlp-tokens/"+otlpID, nil); code != http.StatusOK && code != http.StatusNoContent {
			t.Fatalf("revoke OTLP token = %d: %s", code, body)
		}
		if code := st.pushOTLP(t, otlpToken, req, st.otlpSignature(t, st.freshKey, req, "fc-revoked-"+st.suffix)); code != http.StatusUnauthorized {
			t.Fatalf("OTLP push with a revoked token = %d, want 401", code)
		}

		if code := st.bearer(t, "", "", "/metrics"); code != http.StatusUnauthorized {
			t.Fatalf("/metrics without the scrape token = %d, want 401", code)
		}
		if code := st.bearer(t, st.scrapeToken, "", "/metrics"); code != http.StatusOK {
			t.Fatalf("/metrics with the scrape token = %d, want 200", code)
		}

		if err := st.agentWithoutClientCert(t); err == nil {
			t.Fatal("an agent without a client certificate registered over the transport")
		}
	})

	t.Run("license", func(t *testing.T) {
		var editions struct {
			State string `json:"state"`
		}
		code, body := st.alice.do(t, http.MethodGet, "/v1/editions", nil)
		if code != http.StatusOK {
			t.Fatalf("editions = %d: %s", code, body)
		}
		fcJSON(t, body, &editions)
		if editions.State != string(license.StateReadOnly) {
			t.Fatalf("editions state = %q, want read_only", editions.State)
		}

		// Tenant A had consented to remote-AI egress before the license lapsed.
		if err := govern.NewPolicyStore(st.db.Pool()).SetTenantPolicy(ctx, st.tenantA, govern.Policy{AIRemoteEgress: true}, "fc-seed",
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := audit.TenantAppend(ctx, sc, "fc-seed", "governance.policy_set", st.tenantA, map[string]any{"ai_remote_egress": true})
				return err
			}); err != nil {
			t.Fatalf("seed tenant A's consent: %v", err)
		}
		if code, body := st.alice.do(t, http.MethodGet, "/v1/governance/policy", nil); code != http.StatusOK || !strings.Contains(string(body), `"ai_remote_egress":true`) {
			t.Fatalf("read-only license must keep the policy readable: %d %s", code, body)
		}
		if code, body := st.alice.do(t, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": true, "redact_export": true}); code != http.StatusForbidden ||
			!strings.Contains(string(body), "license_read_only") {
			t.Fatalf("governance edit on a read-only license = %d %s, want 403 license_read_only", code, body)
		}
		if code, body := st.alice.do(t, http.MethodPut, "/v1/governance/policy", map[string]any{"ai_remote_egress": false}); code != http.StatusOK {
			t.Fatalf("withdrawing remote-AI consent on a read-only license = %d %s, want 200", code, body)
		}
		if code, body := st.carol.do(t, http.MethodGet, "/v1/governance/policy", nil); code != http.StatusOK || strings.Contains(string(body), `"ai_remote_egress":true`) {
			t.Fatalf("tenant B's policy must be its own: %d %s", code, body)
		}

		// Telemetry never breaks: an agent result still flows end to end.
		st.streamAgentResult(t, st.tenantB, &resultv1.Result{CanaryType: "http", ServerAddress: "fc-readonly-b.example",
			Success: true, StartTimeUnixNano: time.Now().UnixNano()})
		st.carol.awaitLatest(t, "fc-readonly-b.example")
	})
}

// failClosedStack is the production assembly the receipt drives.
type failClosedStack struct {
	db            *store.DB
	bus           bus.Bus
	h             http.Handler
	baseURL       string
	tenantA       string
	tenantB       string
	alice, carol  *fcUser
	webhookID     map[string]string
	webhookSecret map[string]string
	scrapeToken   string
	freshKey      []byte
	ca            *crypto.CA
	caFile        string
	agentAddr     string
	otlpURL       string
	otlpClient    *http.Client
	licenseKey    []byte // an Ed25519 key the build does NOT trust
	suffix        string

	mu        sync.Mutex
	otlpByKey map[string]int // OTLP metrics records on the bus, by key tenant
}

func newFailClosedStack(t *testing.T) *failClosedStack {
	t.Helper()
	ctx := context.Background()
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the fail-closed receipt needs a real bus")
	}
	db := changeDB(t) // real PostgreSQL, migrated
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)

	st := &failClosedStack{db: db, bus: b, suffix: fmt.Sprintf("%d", time.Now().UnixNano()),
		webhookID: map[string]string{}, webhookSecret: map[string]string{}}
	st.tenantA, st.tenantB = freshTenant(t, db, "fc-a"), freshTenant(t, db, "fc-b")
	for _, tn := range []string{st.tenantA, st.tenantB} {
		st.webhookID[tn], st.webhookSecret[tn] = "fc-wh-"+tn[:8], "fc-webhook-secret-"+tn[:8]
	}
	hmacKey, freshKey, scrape := fcRandom(t), fcRandom(t), hex.EncodeToString(fcRandom(t))
	st.freshKey, st.scrapeToken = freshKey, scrape

	// An Enterprise license that lapsed 31 days ago: past the 30-day grace, so
	// commercial features are read-only while telemetry keeps running.
	lic := st.readOnlyLicense(t)
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: hmacKey,
		MetricsScrapeToken:      scrape,
		ChangeCorrelationWindow: 24 * time.Hour, AIMaxEvidence: 50,
		ChangeWebhooks: map[string]config.ChangeWebhook{
			st.webhookID[st.tenantA]: {TenantID: st.tenantA, Provider: "generic", Secret: st.webhookSecret[st.tenantA]},
			st.webhookID[st.tenantB]: {TenantID: st.tenantB, Provider: "generic", Secret: st.webhookSecret[st.tenantB]},
		},
	}
	log := quietLog()
	latest := NewLatestResults(0)
	otlpAuth := otlp.NewDBTokenAuthenticator(store.NewOTLPTokens(db.Pool()), nil, log)
	srv := New(cfg, log, db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0)).
		WithLatestResults(latest).
		WithLicense(lic).
		WithOTLPTokenAuth(otlpAuth).
		// The governance attach exactly as ee_attach.go wires it.
		WithGovernance(govern.GatePolicyWrites(govern.NewPolicyStore(db.Pool()), lic.WriteCapability()))
	st.h = srv.Handler()
	httpSrv := httptest.NewServer(st.h)
	t.Cleanup(httpSrv.Close)
	st.baseURL = httpSrv.URL

	// The production result fan feeding the latest-results view from Kafka.
	fan := NewResultFan(b, log, ResultSink{Name: "result-view", Fn: NewResultViewConsumer(b, latest, log).SinkResult}).
		WithGroup("fail-closed-proof-views")
	go func() { _ = fan.Run(runCtx) }()

	sessions := srv.SessionManager()
	st.alice = st.tenantAdmin(t, srv, sessions, st.tenantA, "alice")
	st.carol = st.tenantAdmin(t, srv, sessions, st.tenantB, "carol")

	// The agent mTLS transport, publishing to the same Kafka bus.
	dir := t.TempDir()
	st.ca, err = crypto.GenerateCA("fc-agent-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st.caFile = fcWrite(t, dir, "ca.crt", st.ca.CertPEM())
	serverCert, serverKey, err := st.ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := fcWrite(t, dir, "server.crt", serverCert), fcWrite(t, dir, "server.key", serverKey)
	transport, err := agenttransport.New(certFile, keyFile, st.caFile, db.Pool(), b, nil, log)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st.agentAddr = ln.Addr().String()
	go func() { _ = transport.ServeListener(runCtx, ln) }()

	// The OTLP receiver: DB-backed tokens, the freshness HMAC, the bus sink.
	tlsCfg, err := crypto.ServerTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	otlpAddr := fcFreeAddr(t)
	publish := func(topic string) func(context.Context, string, string, []byte) error {
		return func(ctx context.Context, tenant, entropy string, payload []byte) error {
			return b.Publish(ctx, topic, bus.TenantKey(tenant, entropy), payload)
		}
	}
	sinks := otlp.Sinks{
		Metrics: otlp.NewBusSinkWithLimit(0, publish(bus.OTLPMetricsTopic)),
		Traces:  otlp.NewBusTraceSinkWithLimit(0, publish(bus.OTLPTracesTopic)),
		Logs:    otlp.NewBusLogSinkWithLimit(0, publish(bus.OTLPLogsTopic)),
	}
	otlpSrv, err := otlp.NewServer(otlp.ServerConfig{HTTPAddr: otlpAddr, Freshness: otlp.NewFreshnessVerifier(freshKey, time.Minute)},
		tlsCfg, otlpAuth, sinks, log)
	if err != nil {
		t.Fatalf("otlp receiver: %v", err)
	}
	go func() { _ = otlpSrv.Run(runCtx) }()
	// Count what actually reaches the bus. A fresh group reads from the start
	// of the topic, so nothing published during the test is missed.
	st.otlpByKey = map[string]int{}
	go func() {
		_ = b.Subscribe(runCtx, bus.OTLPMetricsTopic, "fc-otlp-count-"+st.suffix, func(_ context.Context, m bus.Message) error {
			st.mu.Lock()
			st.otlpByKey[bus.TenantFromKey(m.Key)]++
			st.mu.Unlock()
			return nil
		})
	}()
	st.otlpURL = "https://" + otlpAddr + "/v1/metrics"
	st.otlpClient, err = crypto.HardenedHTTPClientWithCAFile(10*time.Second, st.caFile)
	if err != nil {
		t.Fatal(err)
	}
	fcAwaitDial(t, otlpAddr)
	st.licenseKey, _, err = crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// readOnlyLicense signs and loads an Enterprise license that expired past its
// grace period, trusting only the test key that signed it.
func (st *failClosedStack) readOnlyLicense(t *testing.T) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := license.Sign(license.Claims{V: 1, ID: "lic_fc", Customer: "Fail Closed Ltd", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-400 * 24 * time.Hour), ExpiresAt: now.Add(-license.GracePeriod - 24*time.Hour)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := license.Load(fcWrite(t, t.TempDir(), "license.json", raw), [][]byte{pub})
	if err != nil {
		t.Fatalf("load the lapsed license: %v", err)
	}
	if !m.Has(license.FeatureGovernance) || m.WriteCapability().Enabled() {
		t.Fatalf("lapsed license: governance=%v writes=%v, want governance readable and writes off", m.Has(license.FeatureGovernance), m.WriteCapability().Enabled())
	}
	return m
}

// licenseFile writes a license signed by a key this build does not trust,
// optionally tampering with its payload after signing.
func (st *failClosedStack) licenseFile(t *testing.T, expires time.Time, tamper bool) string {
	t.Helper()
	raw, err := license.Sign(license.Claims{V: 1, ID: "lic_fc_forged", Customer: "Forged", Tier: license.TierEnterprise,
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: expires}, st.licenseKey)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		var f license.File
		fcJSON(t, raw, &f)
		payload, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		f.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte("Forged"), []byte("Altered"), 1))
		if raw, err = json.Marshal(f); err != nil {
			t.Fatal(err)
		}
	}
	return fcWrite(t, t.TempDir(), "license.json", raw)
}

// tenantAdmin seeds the tenant's system roles, binds a user to admin, and
// issues a session the way login does.
func (st *failClosedStack) tenantAdmin(t *testing.T, srv *Server, sessions *auth.Manager, tenant, name string) *fcUser {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	email := name + "-" + tenant[:8] + "@fail-closed.example"
	var userID string
	if err := tenancy.InTenant(ctx, st.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.Roles{}).EnsureSystemRoles(ctx, sc); err != nil {
			return err
		}
		u, err := store.Users{}.Create(ctx, sc, email, name)
		if err != nil {
			return err
		}
		userID = u.ID
		var roleID string
		if err := sc.Q.QueryRow(ctx, `SELECT id::text FROM roles WHERE slug = 'admin'`).Scan(&roleID); err != nil {
			return err
		}
		_, err = store.RoleBindings{}.Create(ctx, sc, "user", userID, roleID, "tenant", nil)
		return err
	}); err != nil {
		t.Fatalf("tenant admin %s: %v", email, err)
	}
	grants, err := srv.PermissionLoader().ForUser(context.Background(), tenant, userID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sessions.Issue(context.Background(), auth.Session{TenantID: tenant, UserID: userID, Email: email, DisplayName: name,
		AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatalf("issue session for %s: %v", email, err)
	}
	return &fcUser{h: st.h, cookie: &http.Cookie{Name: auth.SessionCookie, Value: token}}
}

// streamAgentResult registers an agent of tenant over mTLS and streams one
// result through the production transport.
func (st *failClosedStack) streamAgentResult(t *testing.T, tenant string, r *resultv1.Result) {
	t.Helper()
	agentID := uuid(t)
	certPEM, keyPEM, err := st.ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tenant, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clientCfg, err := crypto.ClientMTLSConfig(fcWrite(t, dir, "client.crt", certPEM), fcWrite(t, dir, "client.key", keyPEM), st.caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"
	conn, err := grpc.NewClient(st.agentAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := client.Register(ctx, &agentv1.RegisterRequest{Hostname: "fc-host", AgentVersion: "0.0.0-dev", Capabilities: []string{"http"}}); err != nil {
		t.Fatalf("register agent: %v", err)
	}
	freshCtx, err := agenttransport.FreshnessMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.StreamResults(freshCtx)
	if err != nil {
		t.Fatalf("open results stream: %v", err)
	}
	payload, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.StreamResultsRequest{Type: r.GetCanaryType(), Payload: payload}); err != nil {
		t.Fatalf("send result: %v", err)
	}
	ack, err := stream.CloseAndRecv()
	if err != nil || ack.GetAccepted() != 1 {
		t.Fatalf("results ack = %v, %v; want 1 accepted", ack, err)
	}
}

// agentWithoutClientCert dials the transport with server trust but no client
// certificate and attempts to register.
func (st *failClosedStack) agentWithoutClientCert(t *testing.T) error {
	t.Helper()
	tlsCfg, err := crypto.HardenedClientTLSConfigWithCAFile(st.caFile)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.ServerName = "localhost"
	conn, err := grpc.NewClient(st.agentAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = agentv1.NewAgentServiceClient(conn).Register(ctx, &agentv1.RegisterRequest{Hostname: "fc-anon", AgentVersion: "0.0.0-dev"})
	return err
}

func (st *failClosedStack) publishResult(t *testing.T, key []byte, r *resultv1.Result) {
	t.Helper()
	payload, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.bus.Publish(context.Background(), bus.NetworkResultsTopic, key, payload); err != nil {
		t.Fatalf("publish result: %v", err)
	}
}

// pushOTLP posts one metrics request to the OTLP receiver; headers carries the
// freshness envelope (nil = none).
func (st *failClosedStack) pushOTLP(t *testing.T, token string, req *colmetricspb.ExportMetricsServiceRequest, headers map[string]string) int {
	t.Helper()
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, st.otlpURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := st.otlpClient.Do(httpReq)
	if err != nil {
		t.Fatalf("otlp push: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// otlpSignature builds the freshness envelope a sender computes: an HMAC over
// the surface, operation, send time, nonce and body digest.
func (st *failClosedStack) otlpSignature(t *testing.T, key []byte, req *colmetricspb.ExportMetricsServiceRequest, nonce string) map[string]string {
	t.Helper()
	body, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().UTC().Format(time.RFC3339Nano)
	canonical := strings.Join([]string{"probectl-otlp-freshness-v1", "http", "POST /v1/metrics", sentAt, nonce,
		hex.EncodeToString(crypto.Hash(body))}, "\n")
	return map[string]string{
		otlp.FreshnessSentAtHeader:    sentAt,
		otlp.FreshnessNonceHeader:     nonce,
		otlp.FreshnessSignatureHeader: "sha256=" + hex.EncodeToString(crypto.Sign(key, []byte(canonical))),
	}
}

// otlpMessages is how many OTLP metrics records keyed to tenant reached the bus.
func (st *failClosedStack) otlpMessages(tenant string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.otlpByKey[tenant]
}

func (st *failClosedStack) awaitOTLPMessages(t *testing.T, tenant string, want int) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if st.otlpMessages(tenant) >= want {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the signed OTLP push never reached the bus for tenant %s", tenant)
}

// bearer GETs path with an optional bearer token and tenant header.
func (st *failClosedStack) bearer(t *testing.T, token, tenant, path string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Probectl-Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	st.h.ServeHTTP(rec, req)
	return rec.Code
}

// cli runs the real CLI against the live server with an optional token and tenant.
func (st *failClosedStack) cli(t *testing.T, token, tenant string, args ...string) (string, int) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_URL": st.baseURL, "PROBECTL_API_TOKEN": token, "PROBECTL_TENANT": tenant}
	var out bytes.Buffer
	code := cli.RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return env[k] }, strings.NewReader(""), &out, &out)
	return out.String(), code
}

// fcUser is one tenant human with a production session cookie.
type fcUser struct {
	h      http.Handler
	cookie *http.Cookie
}

func (u *fcUser) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(u.cookie)
	rec := httptest.NewRecorder()
	u.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" && c.MaxAge >= 0 {
			u.cookie = c
		}
	}
	return rec.Code, rec.Body.Bytes()
}

func (u *fcUser) text(t *testing.T, path string) string {
	t.Helper()
	code, body := u.do(t, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, code, body)
	}
	return string(body)
}

func (u *fcUser) awaitLatest(t *testing.T, target string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(u.text(t, "/v1/results/latest"), target) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("result %s never reached the tenant's latest results", target)
}

func (u *fcUser) mintAPIToken(t *testing.T) (token, id string) {
	t.Helper()
	code, body := u.do(t, http.MethodPost, "/v1/api-tokens", map[string]any{"name": "fc-automation",
		"scopes": []string{"tenant.read", "test.read"}})
	if code != http.StatusCreated {
		t.Fatalf("mint API token = %d: %s", code, body)
	}
	var out struct{ ID, Token string }
	fcJSON(t, body, &out)
	return out.Token, out.ID
}

func (u *fcUser) mintOTLPToken(t *testing.T) (token, id string) {
	t.Helper()
	code, body := u.do(t, http.MethodPost, "/v1/otlp-tokens", map[string]any{"name": "fc-collector"})
	if code != http.StatusCreated {
		t.Fatalf("mint OTLP token = %d: %s", code, body)
	}
	var out struct{ ID, Token string }
	fcJSON(t, body, &out)
	return out.Token, out.ID
}

// fcMetrics is one gauge point whose resource names tenant.
func fcMetrics(tenant string) *colmetricspb.ExportMetricsServiceRequest {
	return &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: otel.AttrTenantID,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tenant}}}}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{Name: "fc.probe.up",
			Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
				TimeUnixNano: uint64(time.Now().UnixNano()), Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: 1}}}}}}}}},
	}}}
}

func fcRandom(t *testing.T) []byte {
	t.Helper()
	b, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fcWrite(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fcFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func fcAwaitDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("OTLP receiver never listened on %s", addr)
}

func fcJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}
