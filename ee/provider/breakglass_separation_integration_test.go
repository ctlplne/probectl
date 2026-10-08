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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestBreakGlassIsSeparatelyAuditedRealStack is the real-stack receipt for
// CLM-SEP-AUDITED ("Provider/break-glass operations are separately audited
// from tenant streams").
//
// The control plane is the production constructor over real PostgreSQL and the
// provider plane is the production provider.Build assembly attached at the
// same seam ee_attach.go uses: the encrypted IR attribution sidecar over the
// local tenant keyring (PROBECTL_IR_PUBLIC_KEY_DIR), the core tenant session
// manager and RBAC loader for the consent leg, and the core latest-results read
// model as the break-glass telemetry surface. Operators enroll and log in with
// TOTP through the public provider API, the two tenants are provisioned through
// it, and tenant admins hold production sessions. Public HTTP only:
//
//  1. the planes are separate privilege domains: a tenant session cannot reach
//     operator routes, and an operator token cannot read a tenant's audit;
//  2. request → consent → access → revoke all land on the provider stream, each
//     with a sealed IR attribution record, and none lands on either tenant's
//     stream;
//  3. only the owning tenant can see and decide its grant, and an operator
//     identity can never approve it (separation of duties);
//  4. access is operator-bound, needs the tenant's consent, returns only that
//     tenant's telemetry, and is audited once per read;
//  5. the tenant finds the active grant it approved and revokes it: that one
//     tenant decision is recorded on BOTH streams, access ends at once, and the
//     operator cannot revoke it again;
//  6. the provider chain and both tenant chains still verify.
func TestBreakGlassIsSeparatelyAuditedRealStack(t *testing.T) {
	ctx := context.Background()
	st := newSepStack(t)
	anchor, err := audit.ProviderHeadSeq(ctx, st.db.Pool())
	if err != nil {
		t.Fatalf("provider head: %v", err)
	}

	admin := st.seedAdminOperator(t)
	other := st.createOperator(t, admin, RoleOperator)
	tenantA := st.provisionTenant(t, admin, "sep-a")
	tenantB := st.provisionTenant(t, admin, "sep-b")
	alice := st.tenantAdmin(t, tenantA, "alice-"+st.suffix+"@tenant-a.example")
	carol := st.tenantAdmin(t, tenantB, "carol-"+st.suffix+"@tenant-b.example")
	// A tenant-A administrator account that IS a provider operator identity.
	insider := st.tenantAdmin(t, tenantA, other.email)

	st.latest.Record(tenantA, control.ResultView{AgentID: "agent-a", Type: "http", Target: "https://a.example", Success: true, ObservedAt: time.Now()})
	st.latest.Record(tenantB, control.ResultView{AgentID: "agent-b", Type: "http", Target: "https://b.example", Success: true, ObservedAt: time.Now()})
	baseA, baseB := alice.auditActions(t), carol.auditActions(t)

	// 1. Separate privilege domains.
	if code, body := alice.do(t, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": tenantA, "reason": "tenant self-grant", "ttl_minutes": 30}); code != http.StatusUnauthorized {
		t.Fatalf("tenant session requesting break-glass = %d, want 401: %s", code, body)
	}
	if code, body := alice.do(t, http.MethodGet, "/provider/v1/audit", nil); code != http.StatusUnauthorized {
		t.Fatalf("tenant session reading the provider stream = %d, want 401: %s", code, body)
	}
	if code, body := admin.do(t, http.MethodGet, "/v1/audit", nil); code != http.StatusUnauthorized {
		t.Fatalf("operator token reading a tenant audit stream = %d, want 401: %s", code, body)
	}

	// 2. The operator asks; nothing is readable until the tenant decides.
	code, body := admin.do(t, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": tenantA, "reason": "incident INC-42: tenant A probes flapping", "ttl_minutes": 30})
	if code != http.StatusCreated {
		t.Fatalf("request break-glass = %d: %s", code, body)
	}
	var grant Grant
	sepJSON(t, body, &grant)
	if grant.TenantID != tenantA || grant.State(time.Now()) != GrantPending {
		t.Fatalf("new grant = %+v, want a pending grant for tenant A", grant)
	}
	if code, body := admin.do(t, http.MethodGet, "/provider/v1/breakglass/"+grant.ID+"/results", nil); code != http.StatusForbidden {
		t.Fatalf("results before consent = %d, want 403: %s", code, body)
	}

	// 3. Only the owning tenant sees and decides it; an operator identity never approves it.
	if ids := carol.consentIDs(t); ids[grant.ID] {
		t.Fatalf("tenant B's consent list shows tenant A's grant %s", grant.ID)
	}
	if code, body := carol.do(t, http.MethodPost, "/provider/v1/consent/"+grant.ID, map[string]string{"decision": "approve"}); code != http.StatusForbidden {
		t.Fatalf("tenant B approving tenant A's grant = %d, want 403: %s", code, body)
	}
	if code, body := carol.do(t, http.MethodPost, "/provider/v1/consent/"+grant.ID+"/revoke", nil); code != http.StatusForbidden {
		t.Fatalf("tenant B revoking tenant A's grant = %d, want 403: %s", code, body)
	}
	if code, body := insider.do(t, http.MethodPost, "/provider/v1/consent/"+grant.ID, map[string]string{"decision": "approve"}); code != http.StatusForbidden ||
		!strings.Contains(string(body), "separation_of_duties") {
		t.Fatalf("operator identity approving = %d, want 403 separation_of_duties: %s", code, body)
	}
	if ids := alice.consentIDs(t); !ids[grant.ID] {
		t.Fatalf("tenant A's consent list is missing its pending grant %s", grant.ID)
	}
	if code, body := alice.do(t, http.MethodPost, "/provider/v1/consent/"+grant.ID, map[string]string{"decision": "approve"}); code != http.StatusOK {
		t.Fatalf("tenant A approving = %d: %s", code, body)
	}

	// 4. Access: operator-bound, this tenant only, one audit record per read.
	if code, body := other.do(t, http.MethodGet, "/provider/v1/breakglass/"+grant.ID+"/results", nil); code != http.StatusForbidden {
		t.Fatalf("a different operator using the grant = %d, want 403: %s", code, body)
	}
	for read := 1; read <= 2; read++ {
		code, body := admin.do(t, http.MethodGet, "/provider/v1/breakglass/"+grant.ID+"/results", nil)
		if code != http.StatusOK {
			t.Fatalf("break-glass read %d = %d: %s", read, code, body)
		}
		if !strings.Contains(string(body), "https://a.example") || strings.Contains(string(body), "https://b.example") {
			t.Fatalf("break-glass read %d returned the wrong tenant's telemetry: %s", read, body)
		}
	}

	// 5. The tenant finds the active grant it approved and revokes it.
	if ids := alice.consentIDs(t); !ids[grant.ID] {
		t.Fatalf("tenant A's consent list does not show the active grant %s it approved, so it cannot revoke it", grant.ID)
	}
	if code, body := alice.do(t, http.MethodPost, "/provider/v1/consent/"+grant.ID+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("tenant A revoking = %d: %s", code, body)
	}
	if code, body := admin.do(t, http.MethodGet, "/provider/v1/breakglass/"+grant.ID+"/results", nil); code != http.StatusForbidden {
		t.Fatalf("read after the tenant revoked = %d, want 403: %s", code, body)
	}
	if code, body := admin.do(t, http.MethodPost, "/provider/v1/breakglass/"+grant.ID+"/revoke", nil); code != http.StatusConflict {
		t.Fatalf("operator revoking an already revoked grant = %d, want 409: %s", code, body)
	}

	// The provider stream holds every step, each with sealed IR attribution.
	events := admin.providerEvents(t, grant.ID)
	want := map[string]int{
		"provider.breakglass_request": 1,
		"provider.breakglass_consent": 1,
		"provider.breakglass_access":  2,
		"provider.breakglass_revoke":  1,
	}
	got := map[string]int{}
	var refs []string
	for _, ev := range events {
		got[ev.Action]++
		refs = append(refs, ev.Hash)
		if tn, _ := ev.Data["tenant"].(string); tn != tenantA {
			t.Errorf("provider event %s names tenant %q, want %s", ev.Action, tn, tenantA)
		}
	}
	for action, n := range want {
		if got[action] != n {
			t.Errorf("provider stream has %d %s for the grant, want %d (all: %v)", got[action], action, n, got)
		}
	}
	if actor := actorOf(events, "provider.breakglass_consent"); actor != alice.email {
		t.Errorf("consent recorded as %q, want the tenant admin %q", actor, alice.email)
	}
	var sealed int
	if err := st.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM ir_attribution_records WHERE tenant_id = $1 AND event_ref = ANY($2)`, tenantA, refs).Scan(&sealed); err != nil {
		t.Fatalf("count IR attribution records: %v", err)
	}
	if sealed != len(refs) {
		t.Errorf("%d of %d break-glass provider events carry a sealed IR attribution record", sealed, len(refs))
	}

	// Tenant streams: the tenant's own revoke decision lands on A's chain and
	// nothing else of the break-glass lifecycle reaches either tenant.
	afterA, afterB := alice.auditActions(t), carol.auditActions(t)
	if n := afterA["breakglass.revoke"] - baseA["breakglass.revoke"]; n != 1 {
		t.Errorf("tenant A's chain gained %d breakglass.revoke records, want 1", n)
	}
	for action, n := range afterA {
		if strings.HasPrefix(action, "provider.") && n > 0 {
			t.Errorf("tenant A's chain carries provider-stream action %s", action)
		}
	}
	for action, n := range afterB {
		if (strings.HasPrefix(action, "provider.") || strings.HasPrefix(action, "breakglass.")) && n > baseB[action] {
			t.Errorf("tenant B's chain gained %s from tenant A's break-glass", action)
		}
	}
	var leaked int
	if err := st.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE tenant_id = ANY($1::uuid[]) AND action LIKE 'provider.%'`,
		[]string{tenantA, tenantB}).Scan(&leaked); err != nil {
		t.Fatalf("count tenant-stream provider events: %v", err)
	}
	if leaked != 0 {
		t.Errorf("%d provider-stream events were written to the tenant audit table", leaked)
	}

	// 6. Every chain still verifies.
	if err := audit.ProviderVerifyFrom(ctx, st.db.Pool(), anchor); err != nil {
		t.Errorf("provider chain does not verify after the break-glass lifecycle: %v", err)
	}
	if !alice.auditVerifies(t) || !carol.auditVerifies(t) {
		t.Error("a tenant audit chain does not verify")
	}
}

// sepStack is the production control plane with the production provider plane
// attached at the ee_attach.go seam.
type sepStack struct {
	db       *store.DB
	srv      *control.Server
	h        http.Handler
	sessions *auth.Manager
	latest   *control.LatestResults
	irDir    string
	suffix   string
}

func newSepStack(t *testing.T) *sepStack {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("PROBECTL_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
	}
	db, err := store.Open(ctx, dsn, 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)

	hmacKey, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	envelopeKey, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: hmacKey,
		DeploymentProfile:               "multi-tenant",
		EnvelopeKey:                     base64.StdEncoding.EncodeToString(envelopeKey),
		EnvelopeKeyID:                   "sep-it",
		ProviderBreakGlassMaxTTLMinutes: 60,
	}
	log := logging.New(io.Discard, "error", "json")
	latest := control.NewLatestResults(0)
	srv := control.New(cfg, log, db, db.Pool(), nil, nil).WithLatestResults(latest)

	// The production IR attribution sidecar: the operator-owned local keyring
	// plus a chain signing key (cmd/probectl-control/ir_investigator.go).
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
		License:   licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
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
	return &sepStack{
		db: db, srv: srv, h: srv.Handler(), sessions: srv.SessionManager(), latest: latest,
		irDir: irDir, suffix: time.Now().UTC().Format("150405.000000"),
	}
}

// seedAdminOperator stands in for the one-time bootstrap (which refuses once
// any operator exists on a shared database): the roster row plus its enroll
// token, then enrollment and MFA login through the public routes.
func (s *sepStack) seedAdminOperator(t *testing.T) *sepOperator {
	t.Helper()
	token, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	email := "root-" + strings.ReplaceAll(s.suffix, ".", "-") + "@msp.example"
	if _, err := NewPGStore(s.db.Pool()).CreateOperator(context.Background(),
		Operator{Email: email, Name: "Root", Role: RoleAdmin, Status: "disabled"}, crypto.Hash([]byte(token))); err != nil {
		t.Fatalf("seed admin operator: %v", err)
	}
	return s.enroll(t, token, email)
}

// createOperator adds an operator through the admin API and enrolls them.
func (s *sepStack) createOperator(t *testing.T, admin *sepOperator, role string) *sepOperator {
	t.Helper()
	email := "ops-" + strings.ReplaceAll(s.suffix, ".", "-") + "@msp.example"
	code, body := admin.do(t, http.MethodPost, "/provider/v1/operators", map[string]string{"email": email, "name": "Ops", "role": role})
	if code != http.StatusCreated {
		t.Fatalf("create operator = %d: %s", code, body)
	}
	var out struct {
		EnrollToken string `json:"enroll_token"`
	}
	sepJSON(t, body, &out)
	return s.enroll(t, out.EnrollToken, email)
}

func (s *sepStack) enroll(t *testing.T, enrollToken, email string) *sepOperator {
	t.Helper()
	anon := &sepOperator{h: s.h}
	code, body := anon.do(t, http.MethodPost, "/provider/v1/auth/enroll/start", map[string]string{"token": enrollToken})
	if code != http.StatusOK {
		t.Fatalf("enroll start = %d: %s", code, body)
	}
	var start struct {
		TOTPSecret string `json:"totp_secret"`
	}
	sepJSON(t, body, &start)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(start.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	const password = "a-long-operator-password"
	if code, body := anon.do(t, http.MethodPost, "/provider/v1/auth/enroll/complete",
		map[string]string{"token": enrollToken, "password": password, "totp": crypto.TOTPNow(secret, time.Now())}); code != http.StatusOK {
		t.Fatalf("enroll complete = %d: %s", code, body)
	}
	code, body = anon.do(t, http.MethodPost, "/provider/v1/auth/login",
		map[string]string{"email": email, "password": password, "totp": crypto.TOTPNow(secret, time.Now())})
	if code != http.StatusOK {
		t.Fatalf("login = %d: %s", code, body)
	}
	var login struct {
		Token string `json:"token"`
	}
	sepJSON(t, body, &login)
	return &sepOperator{h: s.h, email: email, token: login.Token}
}

// provisionTenant provisions a pooled tenant through the provider API and
// installs its IR public key the way `probectl-control ir-key-install` does.
func (s *sepStack) provisionTenant(t *testing.T, admin *sepOperator, prefix string) string {
	t.Helper()
	slug := prefix + "-" + strings.ReplaceAll(s.suffix, ".", "-")
	code, body := admin.do(t, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": slug, "name": prefix})
	if code != http.StatusCreated {
		t.Fatalf("provision %s = %d: %s", slug, code, body)
	}
	var tn Tenant
	sepJSON(t, body, &tn)
	_, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	name, err := audit.IRPublicKeyFilename(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.irDir, name), publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return tn.ID
}

// tenantAdmin binds a user to the tenant's seeded admin role and issues a
// session the way login does (carrying the permission fingerprint).
func (s *sepStack) tenantAdmin(t *testing.T, tenant, email string) *sepTenantUser {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	var userID string
	if err := tenancy.InTenant(ctx, s.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, err := store.Users{}.Create(ctx, sc, email, email)
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
	grants, err := s.srv.PermissionLoader().ForUser(context.Background(), tenant, userID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.sessions.Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: userID, Email: email, DisplayName: email,
		AuthorizationHash: auth.PermissionGrantFingerprint(grants),
	})
	if err != nil {
		t.Fatalf("issue session for %s: %v", email, err)
	}
	return &sepTenantUser{h: s.h, email: email, cookie: &http.Cookie{Name: auth.SessionCookie, Value: token}}
}

// sepOperator drives the provider API with an operator session token.
type sepOperator struct {
	h     http.Handler
	email string
	token string
}

func (o *sepOperator) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	req := sepRequest(t, method, path, body)
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	rec := httptest.NewRecorder()
	o.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// providerEvents pages the provider stream (admin) for one target.
func (o *sepOperator) providerEvents(t *testing.T, target string) []audit.Event {
	t.Helper()
	code, body := o.do(t, http.MethodGet, "/provider/v1/audit?limit=500&target="+target, nil)
	if code != http.StatusOK {
		t.Fatalf("provider audit = %d: %s", code, body)
	}
	var out struct {
		Items []audit.Event `json:"items"`
	}
	sepJSON(t, body, &out)
	return out.Items
}

// sepTenantUser is one tenant human with a real session cookie, following
// rotation the way a browser does.
type sepTenantUser struct {
	h      http.Handler
	email  string
	cookie *http.Cookie
}

func (u *sepTenantUser) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	req := sepRequest(t, method, path, body)
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

// consentIDs is the tenant's own view of the grants it can act on.
func (u *sepTenantUser) consentIDs(t *testing.T) map[string]bool {
	t.Helper()
	code, body := u.do(t, http.MethodGet, "/provider/v1/consent", nil)
	if code != http.StatusOK {
		t.Fatalf("consent list = %d: %s", code, body)
	}
	var out struct {
		Items []Grant `json:"items"`
	}
	sepJSON(t, body, &out)
	ids := map[string]bool{}
	for _, g := range out.Items {
		ids[g.ID] = true
	}
	return ids
}

func (u *sepTenantUser) auditActions(t *testing.T) map[string]int {
	t.Helper()
	code, body := u.do(t, http.MethodGet, "/v1/audit?limit=500", nil)
	if code != http.StatusOK {
		t.Fatalf("tenant audit = %d: %s", code, body)
	}
	var out struct {
		Items []audit.Event `json:"items"`
	}
	sepJSON(t, body, &out)
	actions := map[string]int{}
	for _, ev := range out.Items {
		actions[ev.Action]++
	}
	return actions
}

func (u *sepTenantUser) auditVerifies(t *testing.T) bool {
	t.Helper()
	code, body := u.do(t, http.MethodGet, "/v1/audit/verify", nil)
	if code != http.StatusOK {
		t.Fatalf("tenant audit verify = %d: %s", code, body)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	sepJSON(t, body, &out)
	return out.OK
}

func actorOf(events []audit.Event, action string) string {
	for _, ev := range events {
		if ev.Action == action {
			return ev.Actor
		}
	}
	return ""
}

func sepRequest(t *testing.T, method, path string, body any) *http.Request {
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
	return req
}

func sepJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}
