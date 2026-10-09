// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestProviderPlaneRealStack is the real-stack receipt for F51 (Provider/MSP
// plane): provider lifecycle, fleet, break-glass, API, CLI and rendered UI,
// across two tenants.
//
// The stack is the production assembly on a fresh PostgreSQL database of the
// dev stack (fresh so the console renders exactly this receipt's tenants):
// control.New over the real stores with the production tenant-status cache,
// provider.Build attached at the ee_attach.go seam with the encrypted IR
// sidecar and the core session and RBAC loaders, the agent mTLS transport
// publishing to real Kafka, and the production result fan feeding the
// latest-results read model that break-glass reads. The two provider keys are
// parsed by the production config loader. The CLI is the shipped one
// (cmd/probectl is cli.RunWithStdin over argv and the environment) against the
// live listener, and the UI is the real web bundle the control plane embeds,
// rendered in Chromium as the signed-in operator and tenant admin.
//
//  1. Onboarding through the CLI: the one-time bootstrap token
//     (PROBECTL_PROVIDER_BOOTSTRAP_TOKEN) refuses a wrong token and works once;
//     TOTP enrollment and MFA login follow.
//  2. Lifecycle: provisioning through the API and the CLI is held to the
//     license tenant band; configure renames; suspend locks one tenant's users
//     out at the API while the other keeps working; the console's Resume
//     control readmits them without a restart; offboarding is one-way and
//     frees its band slot.
//  3. Fleet: agents registered over mTLS show per tenant as counts and
//     versions in the API, the CLI and the console — never telemetry.
//  4. Break-glass: the TTL cap is PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES;
//     each tenant sees and decides only its own requests (the tenant-session
//     CLI commands and the rendered consent card); an approved grant reads only
//     that tenant's telemetry off the bus; tenant revoke and expiry end access;
//     an expired grant does not lock the operator out; the console's Revoke
//     control ends the last grant.
//  5. The provider audit stream records the lifecycle under the operator.
func TestProviderPlaneRealStack(t *testing.T) {
	ps := newPlaneStack(t)

	// 1. Onboarding through the CLI.
	op := ps.onboardOperator(t)
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op.token}

	// 2a. Provisioning: one tenant through the API, one through the CLI, and a
	// third refused by the license's tenant band (three, with the seeded
	// default tenant).
	slugA, slugB, slugC := "acme-"+ps.slug, "globex-"+ps.slug, "initech-"+ps.slug
	code, body := op.do(t, ps, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": slugA, "name": "Acme"})
	if code != http.StatusCreated {
		t.Fatalf("provision %s through the API = %d: %s", slugA, code, body)
	}
	var tenantA Tenant
	planeJSON(t, body, &tenantA)
	var tenantB Tenant
	ps.mustCLI(t, opEnv, &tenantB, "provider", "create-tenant", "--body", fmt.Sprintf(`{"slug":%q,"name":"Globex"}`, slugB))
	ps.refusedCLI(t, opEnv, "tenant_band_exhausted", "provider", "create-tenant", "--body", fmt.Sprintf(`{"slug":%q,"name":"Initech"}`, slugC))
	ps.mustCLI(t, opEnv, nil, "provider", "update-tenant", tenantB.ID, "--body", `{"name":"Globex Industries"}`)
	tenants := ps.tenantsCLI(t, opEnv)
	if a, b := tenants[tenantA.ID], tenants[tenantB.ID]; len(tenants) != 3 || tenants[defaultTenantID].Slug != "default" ||
		a.Status != "active" || b.Status != "active" || b.Name != "Globex Industries" {
		t.Fatalf("tenant inventory after provisioning = %+v, want the default tenant, Acme and the renamed Globex, all active, and nothing else", tenants)
	}
	A, B := tenantA.ID, tenantB.ID
	ps.installIRKey(t, A)
	ps.installIRKey(t, B)
	alice := ps.tenantAdmin(t, A, "alice@"+slugA+".example")
	carol := ps.tenantAdmin(t, B, "carol@"+slugB+".example")
	aliceEnv := map[string]string{"PROBECTL_SESSION_COOKIE_FILE": ps.cookieFile(t, alice)}
	carolEnv := map[string]string{"PROBECTL_SESSION_COOKIE_FILE": ps.cookieFile(t, carol)}

	// 3. Fleet: agents register over mTLS; their results ride Kafka into the
	// read model each tenant (and only a consented break-glass) can read.
	acmeEdge, acmeAPI, globexEdge := "acme-edge."+ps.slug+".example", "acme-api."+ps.slug+".example", "globex-edge."+ps.slug+".example"
	ps.agentResult(t, A, "1.4.0", acmeEdge)
	ps.agentResult(t, A, "1.5.0", acmeAPI)
	ps.agentResult(t, B, "1.5.0", globexEdge)
	planeAwaitLatest(t, alice, acmeEdge, acmeAPI)
	planeAwaitLatest(t, carol, globexEdge)
	if code, body := alice.do(t, http.MethodGet, "/v1/results/latest", nil); code != http.StatusOK || strings.Contains(string(body), globexEdge) {
		t.Fatalf("tenant A's latest results = %d and carry tenant B's telemetry: %s", code, body)
	}
	code, body = op.do(t, ps, http.MethodGet, "/provider/v1/fleet", nil)
	if code != http.StatusOK {
		t.Fatalf("fleet = %d: %s", code, body)
	}
	for _, target := range []string{acmeEdge, acmeAPI, globexEdge} {
		if strings.Contains(string(body), target) {
			t.Fatalf("the fleet view exposes tenant telemetry (%s): %s", target, body)
		}
	}
	var apiFleet struct{ Items []TenantFleet }
	planeJSON(t, body, &apiFleet)
	var cliFleet struct{ Items []TenantFleet }
	ps.mustCLI(t, opEnv, &cliFleet, "provider", "fleet")
	for name, items := range map[string][]TenantFleet{"API": apiFleet.Items, "CLI": cliFleet.Items} {
		fleet := map[string]TenantFleet{}
		for _, f := range items {
			fleet[f.TenantID] = f
		}
		a, b := fleet[A], fleet[B]
		if a.AgentsTotal != 2 || a.AgentsOnline != 2 || !maps.Equal(a.Versions, map[string]int{"1.4.0": 1, "1.5.0": 1}) ||
			b.AgentsTotal != 1 || b.AgentsOnline != 1 || !maps.Equal(b.Versions, map[string]int{"1.5.0": 1}) {
			t.Fatalf("%s fleet: acme=%+v globex=%+v, want 2 online agents (1.4.0, 1.5.0) and 1 online agent (1.5.0)", name, a, b)
		}
	}

	// 2b. Suspend through the CLI: tenant B's users are refused at the API
	// once the replica's status cache turns over; tenant A is untouched.
	planeAwaitStatus(t, carol, http.StatusOK)
	var suspended Tenant
	ps.mustCLI(t, opEnv, &suspended, "provider", "suspend-tenant", B)
	if suspended.Status != "suspended" {
		t.Fatalf("suspend-tenant answered %+v", suspended)
	}
	planeAwaitStatus(t, carol, http.StatusForbidden)
	planeAwaitStatus(t, alice, http.StatusOK)
	if code, body := op.do(t, ps, http.MethodPost, "/provider/v1/tenants/"+B+"/suspend", nil); code != http.StatusConflict {
		t.Fatalf("suspending a suspended tenant = %d, want 409: %s", code, body)
	}

	// The operator console renders the fleet and the inventory — counts and
	// lifecycle, never telemetry — and its Resume control readmits tenant B.
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:     ps.baseURL + "/ui/provider",
		Cookies: []testsupport.RenderCookie{{Name: SessionCookie, Value: op.token}},
		Expect:  []string{"Fleet across tenants", slugA, slugB, "1.4.0×1", "Globex Industries", "Suspended"},
		Absent:  []string{acmeEdge, acmeAPI, globexEdge},
		Steps:   []testsupport.RenderStep{{Click: "Resume", Gone: true}},
	})
	if got := ps.tenantsCLI(t, opEnv)[B].Status; got != "active" {
		t.Fatalf("after the console's Resume, tenant B is %q, want active", got)
	}
	planeAwaitStatus(t, carol, http.StatusOK) // readmitted without a restart

	// 4. Break-glass. The TTL cap comes from the loaded config (30 minutes).
	reasonA, reasonB := "INC-51 acme edge probes flapping "+ps.slug, "INC-52 globex audit "+ps.slug
	ps.refusedCLI(t, opEnv, "bad_request", "provider", "request-breakglass", "--body",
		fmt.Sprintf(`{"tenant_id":%q,"reason":%q,"ttl_minutes":45}`, A, reasonA))
	var g1, g2 Grant
	ps.mustCLI(t, opEnv, &g1, "provider", "request-breakglass", "--body",
		fmt.Sprintf(`{"tenant_id":%q,"reason":%q,"ttl_minutes":30}`, A, reasonA))
	code, body = op.do(t, ps, http.MethodPost, "/provider/v1/breakglass", map[string]any{"tenant_id": B, "reason": reasonB, "ttl_minutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("request break-glass for tenant B = %d: %s", code, body)
	}
	planeJSON(t, body, &g2)
	ps.refusedCLI(t, opEnv, "breakglass_not_active", "provider", "breakglass-results", g1.ID)

	// Each tenant sees only its own request: tenant B through the CLI, tenant A
	// in the rendered consent card, where the admin approves it.
	if ids := ps.consentCLI(t, carolEnv); !ids[g2.ID] || ids[g1.ID] {
		t.Fatalf("tenant B's consent list = %v, want its own request %s and not tenant A's %s", ids, g2.ID, g1.ID)
	}
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:     ps.baseURL + "/ui/admin",
		Cookies: []testsupport.RenderCookie{{Name: alice.cookie.Name, Value: alice.cookie.Value}},
		Expect:  []string{"Break-glass requests", reasonA, op.email},
		Absent:  []string{reasonB},
		Steps:   []testsupport.RenderStep{{Click: "Approve " + op.email, Expect: []string{"Approved: " + op.email}, Gone: true}},
	})
	if state := ps.grantStates(t, op)[g1.ID]; state != "active" {
		t.Fatalf("after the consent card's Approve, grant %s is %q, want active", g1.ID, state)
	}
	ps.mustCLI(t, carolEnv, nil, "provider", "decide-consent", g2.ID, "--body", `{"decision":"deny"}`)

	// The approved grant reads tenant A's telemetry, off the bus, and nothing
	// of tenant B's; the denied one reads nothing.
	for read := 1; read <= 2; read++ {
		out, stderr, code := ps.cli(t, opEnv, "provider", "breakglass-results", g1.ID)
		if code != 0 || !strings.Contains(out, acmeEdge) || !strings.Contains(out, acmeAPI) || strings.Contains(out, globexEdge) {
			t.Fatalf("break-glass read %d of tenant A: exit %d, want acme's results and none of globex's: %s%s", read, code, stderr, out)
		}
	}
	ps.refusedCLI(t, opEnv, "breakglass_not_active", "provider", "breakglass-results", g2.ID)

	// The tenant revokes through the CLI: access ends, and the operator cannot
	// revoke it a second time.
	ps.mustCLI(t, aliceEnv, nil, "provider", "revoke-consent", g1.ID)
	ps.refusedCLI(t, opEnv, "breakglass_not_active", "provider", "breakglass-results", g1.ID)
	ps.refusedCLI(t, opEnv, "breakglass_decided", "provider", "revoke-breakglass", g1.ID)

	// Expiry ends a grant, and the operator can be granted again afterwards.
	var g3, g4 Grant
	ps.mustCLI(t, opEnv, &g3, "provider", "request-breakglass", "--body",
		fmt.Sprintf(`{"tenant_id":%q,"reason":"INC-53 acme follow-up %s","ttl_minutes":30}`, A, ps.slug))
	ps.mustCLI(t, aliceEnv, nil, "provider", "decide-consent", g3.ID, "--body", `{"decision":"approve"}`)
	ps.mustCLI(t, opEnv, nil, "provider", "breakglass-results", g3.ID)
	// The grant runs out (0004 requires expires_at > granted_at, so both move).
	if _, err := ps.db.Pool().Exec(context.Background(), `UPDATE break_glass_grants
		    SET granted_at = granted_at - interval '2 hours', expires_at = expires_at - interval '2 hours'
		  WHERE id = $1`, g3.ID); err != nil {
		t.Fatalf("age grant %s past its expiry: %v", g3.ID, err)
	}
	ps.refusedCLI(t, opEnv, "breakglass_not_active", "provider", "breakglass-results", g3.ID)
	ps.mustCLI(t, opEnv, &g4, "provider", "request-breakglass", "--body",
		fmt.Sprintf(`{"tenant_id":%q,"reason":"INC-54 acme recurrence %s","ttl_minutes":30}`, A, ps.slug))
	ps.mustCLI(t, aliceEnv, nil, "provider", "decide-consent", g4.ID, "--body", `{"decision":"approve"}`)
	ps.mustCLI(t, opEnv, nil, "provider", "breakglass-results", g4.ID)

	// 2c. Offboarding is one-way and frees tenant B's band slot.
	code, body = op.do(t, ps, http.MethodPost, "/provider/v1/tenants/"+B+"/offboard", nil)
	if code != http.StatusOK {
		t.Fatalf("offboard tenant B = %d: %s", code, body)
	}
	planeAwaitStatus(t, carol, http.StatusForbidden)
	ps.refusedCLI(t, opEnv, "conflict", "provider", "resume-tenant", B)
	ps.refusedCLI(t, opEnv, "conflict", "provider", "suspend-tenant", B)
	var tenantC Tenant
	ps.mustCLI(t, opEnv, &tenantC, "provider", "create-tenant", "--body", fmt.Sprintf(`{"slug":%q,"name":"Initech"}`, slugC))
	if tenants := ps.tenantsCLI(t, opEnv); tenants[A].Status != "active" || tenants[B].Status != "offboarding" || tenants[tenantC.ID].Status != "active" {
		t.Fatalf("tenant inventory after offboarding = %+v, want acme active, globex offboarding, initech active", tenants)
	}

	// The console shows the grant ledger and the offboarded tenant, and its
	// Revoke control ends the one grant still active.
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:     ps.baseURL + "/ui/provider",
		Cookies: []testsupport.RenderCookie{{Name: SessionCookie, Value: op.token}},
		Expect:  []string{"Break-glass", reasonA, reasonB, "INC-54 acme recurrence " + ps.slug, "offboarding", slugC},
		Absent:  []string{acmeEdge, acmeAPI, globexEdge},
		Steps:   []testsupport.RenderStep{{Click: "Revoke", Gone: true}},
	})
	states := ps.grantStates(t, op)
	want := map[string]string{g1.ID: "revoked", g2.ID: "denied", g3.ID: "expired", g4.ID: "revoked"}
	for id, state := range want {
		if states[id] != state {
			t.Errorf("grant %s is %q, want %q (all: %v)", id, states[id], state, states)
		}
	}
	ps.refusedCLI(t, opEnv, "breakglass_not_active", "provider", "breakglass-results", g4.ID)

	// 5. The provider stream holds tenant B's lifecycle under the operator.
	var stream struct{ Items []audit.Event }
	ps.mustCLI(t, opEnv, &stream, "provider", "audit", "--query", "target="+B)
	got := map[string]string{}
	for _, ev := range stream.Items {
		got[ev.Action] = ev.Actor
	}
	for _, action := range []string{"provider.tenant_provision", "provider.tenant_configure", "provider.tenant_suspend", "provider.tenant_resume", "provider.tenant_offboard"} {
		if got[action] != op.email {
			t.Errorf("provider stream for tenant B: %s by %q, want by %s (all: %v)", action, got[action], op.email, got)
		}
	}
}

// defaultTenantID is the tenant migration 0008 seeds on every install.
const defaultTenantID = "00000000-0000-0000-0000-000000000001"

// planeStack is the production assembly the F51 receipt drives, reusing the
// separation receipt's tenant-session helpers over it.
type planeStack struct {
	*sepStack
	baseURL        string
	ca             *crypto.CA
	caFile         string
	agentAddr      string
	bootstrapToken string
	slug           string
	dir            string
}

func newPlaneStack(t *testing.T) *planeStack {
	t.Helper()
	ctx := context.Background()
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the provider-plane receipt reads break-glass telemetry off the real bus")
	}
	db, dsn := planeDB(t)
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)

	// The two provider keys (and the session key) go through the production
	// loader.
	bootstrap := hex.EncodeToString(planeRandom(t))
	providerEnv := map[string]string{
		"PROBECTL_DATABASE_URL":                        dsn,
		"PROBECTL_AUTH_MODE":                           "session",
		"PROBECTL_SESSION_HMAC_KEY":                    hex.EncodeToString(planeRandom(t)),
		"PROBECTL_PROVIDER_BOOTSTRAP_TOKEN":            bootstrap,
		"PROBECTL_PROVIDER_BREAKGLASS_MAX_TTL_MINUTES": "30",
	}
	loaded, err := config.Load(func(k string) string { return providerEnv[k] })
	if err != nil {
		t.Fatalf("load the provider configuration: %v", err)
	}
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: loaded.SessionHMACKey,
		DeploymentProfile:               "multi-tenant",
		EnvelopeKey:                     base64.StdEncoding.EncodeToString(planeRandom(t)),
		EnvelopeKeyID:                   "f51-it",
		ProviderBootstrapToken:          loaded.ProviderBootstrapToken,
		ProviderBreakGlassMaxTTLMinutes: loaded.ProviderBreakGlassMaxTTLMinutes,
	}
	log := logging.New(io.Discard, "error", "json")
	latest := control.NewLatestResults(0)
	// An MSP license with a tenant band of three: every install's seeded
	// default tenant (migration 0008), then Acme and Globex.
	lic := licenseManager(t, license.TierMSP, 3, 90*24*time.Hour)
	srv := control.New(cfg, log, db, db.Pool(), nil, nil).
		WithTenantStatus(control.NewTenantStatusCache(db.Pool(), 0)).
		WithLatestResults(latest).
		WithLicense(lic)

	irDir := t.TempDir()
	irKeys, err := audit.NewLocalIRPublicKeyResolver(irDir)
	if err != nil {
		t.Fatal(err)
	}
	signPriv, signPub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := audit.NewIRStagePG(db.Pool(), irKeys, signPriv, signPub)
	if err != nil {
		t.Fatal(err)
	}
	plane, err := Build(cfg, Deps{
		Pool:      db.Pool(),
		License:   lic,
		Log:       log,
		Results:   latest,
		Sessions:  srv.SessionManager(),
		Perms:     srv.PermissionLoader(),
		IRSidecar: sidecar,
	})
	if err != nil {
		t.Fatalf("build provider plane: %v", err)
	}
	srv.WithProviderPlane(plane)
	h := srv.Handler()
	httpSrv := httptest.NewServer(h)
	t.Cleanup(httpSrv.Close)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	// The production result fan feeding the latest-results view from Kafka.
	fan := control.NewResultFan(b, log, control.ResultSink{Name: "result-view", Fn: control.NewResultViewConsumer(b, latest, log).SinkResult}).
		WithGroup("f51-proof-views-" + suffix)
	go func() { _ = fan.Run(runCtx) }()

	// The agent mTLS transport, publishing to the same Kafka bus.
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("f51-agent-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := planeWrite(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := agenttransport.New(planeWrite(t, dir, "server.crt", serverCert), planeWrite(t, dir, "server.key", serverKey),
		caFile, db.Pool(), b, nil, log)
	if err != nil {
		t.Fatalf("agent transport: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = transport.ServeListener(runCtx, ln) }()

	return &planeStack{
		sepStack: &sepStack{db: db, srv: srv, h: h, sessions: srv.SessionManager(), latest: latest, irDir: irDir, suffix: suffix},
		baseURL:  httpSrv.URL, ca: ca, caFile: caFile, agentAddr: ln.Addr().String(),
		bootstrapToken: bootstrap, slug: suffix[len(suffix)-9:], dir: dir,
	}
}

// planeDB is a fresh, migrated database on the dev stack's PostgreSQL, dropped
// afterwards, so the provider console lists exactly this receipt's tenants.
func planeDB(t *testing.T) (*store.DB, string) {
	t.Helper()
	ctx := context.Background()
	base, err := url.Parse(testsupport.PostgresDSN())
	if err != nil || base.Scheme == "" {
		t.Fatalf("PROBECTL_DATABASE_URL must be a postgres:// URL: %v", err)
	}
	adminURL := *base
	adminURL.Path = "/postgres"
	admin, err := pgxpool.New(ctx, adminURL.String())
	if err != nil {
		testsupport.SkipOrFatal(t, "open postgres admin connection: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	name := fmt.Sprintf("probectl_f51_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoted); err != nil {
		admin.Close()
		t.Fatalf("create the receipt's database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+quoted+` WITH (FORCE)`)
		admin.Close()
	})
	dsn := *base
	dsn.Path = "/" + name
	db, err := store.Open(ctx, dsn.String(), 10, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open the receipt's database: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db, dsn.String()
}

// planeOperator is an enrolled operator holding an MFA login token.
type planeOperator struct{ email, token string }

// do calls the provider API through the production handler as the operator.
func (o planeOperator) do(t *testing.T, ps *planeStack, method, path string, body any) (int, []byte) {
	t.Helper()
	return (&sepOperator{h: ps.h, email: o.email, token: o.token}).do(t, method, path, body)
}

// onboardOperator is the first operator's whole path through the CLI: the
// bootstrap token, TOTP enrollment, MFA login.
func (ps *planeStack) onboardOperator(t *testing.T) planeOperator {
	t.Helper()
	email := "root-" + ps.slug + "@msp.example"
	bootstrap := func(token string) string {
		return ps.secretFile(t, map[string]string{"token": token, "email": email, "name": "Root"})
	}
	ps.refusedCLI(t, nil, "forbidden", "provider", "bootstrap", "--body-file", bootstrap("not-"+ps.bootstrapToken))
	var boot struct {
		EnrollToken string `json:"enroll_token"`
	}
	ps.mustCLI(t, nil, &boot, "provider", "bootstrap", "--body-file", bootstrap(ps.bootstrapToken))
	ps.refusedCLI(t, nil, "forbidden", "provider", "bootstrap", "--body-file", bootstrap(ps.bootstrapToken))

	var start struct {
		TOTPSecret string `json:"totp_secret"`
	}
	ps.mustCLI(t, nil, &start, "provider", "enroll-start", "--body-file", ps.secretFile(t, map[string]string{"token": boot.EnrollToken}))
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(start.TOTPSecret)
	if err != nil {
		t.Fatalf("decode the TOTP secret: %v", err)
	}
	password := "a-long-operator-password-" + ps.slug
	ps.mustCLI(t, nil, nil, "provider", "enroll-complete", "--body-file", ps.secretFile(t,
		map[string]string{"token": boot.EnrollToken, "password": password, "totp": crypto.TOTPNow(secret, time.Now())}))
	var login struct {
		Token string `json:"token"`
	}
	ps.mustCLI(t, nil, &login, "provider", "login", "--body-file", ps.secretFile(t,
		map[string]string{"email": email, "password": password, "totp": crypto.TOTPNow(secret, time.Now())}))
	if login.Token == "" {
		t.Fatal("login returned no session token")
	}
	return planeOperator{email: email, token: login.Token}
}

// installIRKey installs a tenant's IR public key the way
// `probectl-control ir-key-install` does, so break-glass into it can be requested.
func (ps *planeStack) installIRKey(t *testing.T, tenant string) {
	t.Helper()
	_, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	name, err := audit.IRPublicKeyFilename(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ps.irDir, name), publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

// agentResult registers one agent of tenant over mTLS, reporting version, and
// streams one result for target.
func (ps *planeStack) agentResult(t *testing.T, tenant, version, target string) {
	t.Helper()
	agentID := uuid.NewString()
	certPEM, keyPEM, err := ps.ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tenant, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clientCfg, err := crypto.ClientMTLSConfig(planeWrite(t, dir, "client.crt", certPEM), planeWrite(t, dir, "client.key", keyPEM), ps.caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"
	conn, err := grpc.NewClient(ps.agentAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := client.Register(ctx, &agentv1.RegisterRequest{Hostname: "f51-" + version, AgentVersion: version, Capabilities: []string{"http"}}); err != nil {
		t.Fatalf("register agent %s: %v", version, err)
	}
	freshCtx, err := agenttransport.FreshnessMetadata(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.StreamResults(freshCtx)
	if err != nil {
		t.Fatalf("open results stream: %v", err)
	}
	payload, err := proto.Marshal(&resultv1.Result{CanaryType: "http", ServerAddress: target, Success: true, StartTimeUnixNano: time.Now().UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&agentv1.StreamResultsRequest{Type: "http", Payload: payload}); err != nil {
		t.Fatalf("send result: %v", err)
	}
	if ack, err := stream.CloseAndRecv(); err != nil || ack.GetAccepted() != 1 {
		t.Fatalf("results ack = %v, %v; want 1 accepted", ack, err)
	}
}

// cli runs the shipped probectl CLI in-process (cmd/probectl is
// cli.RunWithStdin over argv and the environment) against the live listener.
func (ps *planeStack) cli(t *testing.T, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	full := map[string]string{"PROBECTL_API_URL": ps.baseURL}
	maps.Copy(full, env)
	var stdout, stderr bytes.Buffer
	code := cli.RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return full[k] },
		strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

// mustCLI runs a command that must succeed and decodes its JSON output into out.
func (ps *planeStack) mustCLI(t *testing.T, env map[string]string, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := ps.cli(t, env, args...)
	if code != 0 {
		t.Fatalf("probectl %s: exit %d: %s%s", strings.Join(args, " "), code, stderr, stdout)
	}
	if out != nil {
		planeJSON(t, []byte(stdout), out)
	}
}

// refusedCLI runs a command the API must refuse with the error code want.
func (ps *planeStack) refusedCLI(t *testing.T, env map[string]string, want string, args ...string) {
	t.Helper()
	stdout, stderr, code := ps.cli(t, env, args...)
	if code == 0 || !strings.Contains(stderr, "("+want) {
		t.Fatalf("probectl %s: exit %d, want a refusal with %q: %s%s", strings.Join(args, " "), code, want, stderr, stdout)
	}
}

// tenantsCLI is the provider's tenant inventory through `probectl provider tenants`.
func (ps *planeStack) tenantsCLI(t *testing.T, env map[string]string) map[string]Tenant {
	t.Helper()
	var out struct{ Items []Tenant }
	ps.mustCLI(t, env, &out, "provider", "tenants")
	tenants := map[string]Tenant{}
	for _, tn := range out.Items {
		tenants[tn.ID] = tn
	}
	return tenants
}

// consentCLI is a tenant admin's consent list through `probectl provider consent`.
func (ps *planeStack) consentCLI(t *testing.T, env map[string]string) map[string]bool {
	t.Helper()
	var out struct{ Items []Grant }
	ps.mustCLI(t, env, &out, "provider", "consent")
	ids := map[string]bool{}
	for _, g := range out.Items {
		ids[g.ID] = true
	}
	return ids
}

// grantStates is the operator's grant ledger: id → derived state.
func (ps *planeStack) grantStates(t *testing.T, op planeOperator) map[string]string {
	t.Helper()
	code, body := op.do(t, ps, http.MethodGet, "/provider/v1/breakglass", nil)
	if code != http.StatusOK {
		t.Fatalf("list break-glass grants = %d: %s", code, body)
	}
	var out struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	planeJSON(t, body, &out)
	states := map[string]string{}
	for _, g := range out.Items {
		states[g.ID] = g.State
	}
	return states
}

// secretFile writes v as JSON to an owner-only file, the way credential-bearing
// CLI bodies are supplied.
func (ps *planeStack) secretFile(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(ps.dir, "body-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// cookieFile writes a tenant user's session cookie to an owner-only file for
// the tenant-session CLI commands.
func (ps *planeStack) cookieFile(t *testing.T, u *sepTenantUser) string {
	t.Helper()
	return planeWrite(t, t.TempDir(), "session.cookie", []byte(u.cookie.Value+"\n"))
}

// planeAwaitStatus polls a tenant API read until it answers want: the
// lifecycle gate re-reads a tenant's status within the 15-second cache.
func planeAwaitStatus(t *testing.T, u *sepTenantUser, want int) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for {
		code, body := u.do(t, http.MethodGet, "/v1/results/latest", nil)
		if code == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s reading its tenant's results = %d, want %d: %s", u.email, code, want, body)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// planeAwaitLatest waits for targets to reach the tenant's latest results.
func planeAwaitLatest(t *testing.T, u *sepTenantUser, targets ...string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		code, body := u.do(t, http.MethodGet, "/v1/results/latest", nil)
		missing := ""
		for _, target := range targets {
			if !strings.Contains(string(body), target) {
				missing = target
			}
		}
		if code == http.StatusOK && missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("result %s never reached %s's latest results (%d): %s", missing, u.email, code, body)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func planeRandom(t *testing.T) []byte {
	t.Helper()
	b, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func planeWrite(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func planeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}
