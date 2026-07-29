// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/license"
)

// --- shared fixtures ---

// memAudit captures provider-stream audit events for assertions.
type memAudit struct {
	mu     sync.Mutex
	events []auditEvent
}

var errAuditUnavailable = errors.New("provider audit unavailable")

type failingAudit struct{}

func (failingAudit) Append(context.Context, string, string, string, map[string]any) error {
	return errAuditUnavailable
}

type auditEvent struct {
	Actor, Action, Target string
	Data                  map[string]any
}

func (a *memAudit) Append(_ context.Context, actor, action, target string, data map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, auditEvent{actor, action, target, data})
	return nil
}

func (a *memAudit) count(action string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// memFairnessStore is a DB-less provider/fairness seam: it behaves like the
// PGStore methods the handler uses and like the PolicySource the gate uses.
type memFairnessStore struct {
	mu       sync.Mutex
	policies map[string]fairness.Policy
}

func (m *memFairnessStore) PolicyFor(_ context.Context, tenantID string) (fairness.Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[tenantID]
	return p, ok, nil
}

func (m *memFairnessStore) All(_ context.Context) (map[string]fairness.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]fairness.Policy, len(m.policies))
	for k, v := range m.policies {
		out[k] = v
	}
	return out, nil
}

func (m *memFairnessStore) Upsert(_ context.Context, tenantID string, p fairness.Policy, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[tenantID] = p
	return nil
}

// fakeTelemetry stands in for the latest-results read model, tenant-keyed so
// the tests can prove grant-scoped access returns ONLY the grant's tenant.
type fakeTelemetry struct{ byTenant map[string][]string }

func (f fakeTelemetry) LatestResults(tenantID string) any { return f.byTenant[tenantID] }

// fakeTenantAuth resolves fixed tenant sessions: token -> (tenant, user, perms).
type fakeTenantAuth struct {
	sessions   map[string]*auth.Session
	perms      map[string][]string // userID -> permission keys
	attributes map[string]map[string]string
	policies   map[string][]auth.Policy
	policyErr  map[string]error
}

func (f fakeTenantAuth) ResolveSession(_ context.Context, token string) (*auth.Session, error) {
	return f.sessions[token], nil
}

func (f fakeTenantAuth) AuthorizationContext(_ context.Context, sess *auth.Session) (*auth.Principal, []auth.Policy, error) {
	if err := f.policyErr[sess.TenantID]; err != nil {
		return nil, nil, err
	}
	permissions := make(map[string]bool, len(f.perms[sess.UserID]))
	for _, key := range f.perms[sess.UserID] {
		permissions[key] = true
	}
	attributes := make(map[string]string, len(f.attributes[sess.UserID]))
	for key, value := range f.attributes[sess.UserID] {
		attributes[key] = value
	}
	principal := &auth.Principal{
		TenantID:    sess.TenantID,
		UserID:      sess.UserID,
		Email:       sess.Email,
		DisplayName: sess.DisplayName,
		Permissions: permissions,
		Attributes:  attributes,
	}
	return principal, append([]auth.Policy(nil), f.policies[sess.TenantID]...), nil
}

// licenseManager signs and loads a real license so the tests exercise the
// true S-T0 ladder. expiresIn may be negative (expired states).
func licenseManager(t *testing.T, tier license.Tier, band int, expiresIn time.Duration) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_test", Customer: "MSP Test GmbH", Tier: tier, TenantBand: band,
		IssuedAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(expiresIn),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := license.Load(path, [][]byte{pub})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func testEnvelope(t *testing.T) *crypto.Envelope {
	t.Helper()
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	kp, err := crypto.NewStaticKeyProviderFromBase64("test", kek)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.NewEnvelope(kp)
}

type fixture struct {
	h          *Handler
	store      *MemStore
	svc        *Service
	audit      *memAudit
	tenantAuth *fakeTenantAuth
	now        *time.Time // movable clock
}

const bootToken = "boot-secret-0123456789"

func newFixture(t *testing.T, lic *license.Manager) *fixture {
	t.Helper()
	store := NewMemStore()
	sink := &memAudit{}
	now := time.Now()
	telemetry := fakeTelemetry{byTenant: map[string][]string{}}
	svc, err := NewService(store, sink, lic, telemetry, testEnvelope(t), 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: store, svc: svc, audit: sink, now: &now}
	svc.WithClock(func() time.Time { return *f.now })
	ta := &fakeTenantAuth{
		sessions: map[string]*auth.Session{
			"tenant-admin-A": {ID: "s1", TenantID: "tnA", UserID: "uA", Email: "admin@a.example"},
			"tenant-user-A":  {ID: "s2", TenantID: "tnA", UserID: "uA2", Email: "user@a.example"},
			"tenant-admin-B": {ID: "s3", TenantID: "tnB", UserID: "uB", Email: "admin@b.example"},
		},
		perms: map[string][]string{
			"uA": {"directory.read", "directory.write"},
			"uB": {"directory.read", "directory.write"},
			// uA2 deliberately lacks directory.write.
			"uA2": {"directory.read"},
		},
		attributes: map[string]map[string]string{},
		policies:   map[string][]auth.Policy{},
		policyErr:  map[string]error{},
	}
	f.tenantAuth = ta
	f.h = NewHandler(svc, NewSessions(nil), ta, slog.New(slog.NewTextHandler(io.Discard, nil)), bootToken, false)
	return f
}

func newTestHandler(t *testing.T) *Handler {
	return newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour)).h
}

func TestProviderMutationRollsBackWhenAuditFails(t *testing.T) {
	store := NewMemStore()
	svc, err := NewService(
		store,
		failingAudit{},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.CreateOperator(
		context.Background(),
		"admin@msp.example",
		"new-operator@msp.example",
		"New Operator",
		RoleOperator,
	); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("CreateOperator error = %v, want %v", err, errAuditUnavailable)
	}
	if got, err := store.CountOperators(context.Background()); err != nil {
		t.Fatal(err)
	} else if got != 0 {
		t.Fatalf("operators after failed audit = %d, want 0", got)
	}
}

type countingTelemetry struct {
	calls int
}

func (f *countingTelemetry) LatestResults(string) any {
	f.calls++
	return []string{"must-not-be-returned"}
}

func TestBreakGlassUseRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	telemetry := &countingTelemetry{}
	now := time.Now().UTC()
	svc, err := NewService(
		store,
		failingAudit{},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		telemetry,
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	svc.WithClock(func() time.Time { return now })

	op, err := store.CreateOperator(ctx, Operator{
		Email: "operator@msp.example",
		Name:  "Operator",
		Role:  RoleOperator,
	}, crypto.Hash([]byte("enrollment-token")))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(ctx, "audit-rollback", "Audit Rollback", "pooled", "")
	if err != nil {
		t.Fatal(err)
	}
	consentedAt := now.Add(-time.Minute)
	grant, err := store.CreateGrant(ctx, Grant{
		OperatorID:  op.ID,
		TenantID:    tenant.ID,
		Reason:      "incident response",
		Scope:       "read",
		GrantedBy:   op.Email,
		GrantedAt:   now.Add(-2 * time.Minute),
		ExpiresAt:   now.Add(time.Hour),
		ConsentedBy: "tenant-admin@example.test",
		ConsentedAt: &consentedAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.BreakGlassResults(ctx, op, grant.ID); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("BreakGlassResults error = %v, want %v", err, errAuditUnavailable)
	}
	got, err := store.GetGrant(ctx, grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UseCount != 0 {
		t.Fatalf("use_count after failed audit = %d, want 0", got.UseCount)
	}
	if telemetry.calls != 0 {
		t.Fatalf("telemetry reads after failed audit = %d, want 0", telemetry.calls)
	}
}

func newReq(method, path string, body any) *http.Request {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	return httptest.NewRequest(method, path, rd)
}

func doReq(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) doAuthed(t *testing.T, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	req := newReq(method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	return doReq(f.h, req)
}

// bootstrapAndLogin runs the full first-admin flow and returns a live session
// token — itself a test of bootstrap → enroll(start+complete) → MFA login.
func (f *fixture) bootstrapAndLogin(t *testing.T) string {
	t.Helper()
	// Bootstrap the first admin.
	rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": bootToken, "email": "root@msp.example", "name": "Root"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("bootstrap: %d %s", rec.Code, rec.Body.String())
	}
	var boot struct {
		EnrollToken string `json:"enroll_token"`
	}
	mustDecode(t, rec, &boot)
	return f.enrollAndLogin(t, boot.EnrollToken, "root@msp.example", "a-long-operator-pw")
}

func (f *fixture) enrollAndLogin(t *testing.T, enrollToken, email, password string) string {
	t.Helper()
	// Enroll: bind the authenticator.
	rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/enroll/start", map[string]string{"token": enrollToken}))
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll start: %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		TOTPSecret string `json:"totp_secret"`
	}
	mustDecode(t, rec, &start)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(start.TOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	code := crypto.TOTPNow(secret, *f.now)
	rec = doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/enroll/complete",
		map[string]string{"token": enrollToken, "password": password, "totp": code}))
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll complete: %d %s", rec.Code, rec.Body.String())
	}
	// MFA login.
	rec = doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
		map[string]string{"email": email, "password": password, "totp": crypto.TOTPNow(secret, *f.now)}))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	mustDecode(t, rec, &login)
	return login.Token
}

func (f *fixture) bootstrapAndLoginFast(t *testing.T) string {
	t.Helper()
	op, err := f.store.CreateOperator(context.Background(),
		Operator{Email: "root@msp.example", Name: "Root", Role: RoleAdmin, Status: "disabled"},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	return f.activateAndIssue(t, op)
}

func (f *fixture) activateAndIssue(t *testing.T, op Operator) string {
	t.Helper()
	if err := f.store.ActivateOperator(context.Background(), op.ID, "test-session-only"); err != nil {
		t.Fatal(err)
	}
	op.Enrolled = true
	op.Status = "active"
	token, err := f.h.sessions.Issue(op)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func mustDecode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

// --- the sprint's named tests ---

// TestProviderLifecycle is the provision→configure→suspend→resume→offboard
// end-to-end, including licensed-band enforcement and the audit trail.
func TestProviderLifecycle(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 2, 90*24*time.Hour)) // band of 2
	token := f.bootstrapAndLogin(t)

	// Provision two tenants — the licensed band.
	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "acme", "name": "Acme"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision: %d %s", rec.Code, rec.Body.String())
	}
	var acme Tenant
	mustDecode(t, rec, &acme)
	if rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "globex", "name": "Globex"}); rec.Code != http.StatusCreated {
		t.Fatalf("provision 2: %d", rec.Code)
	}
	// The third exceeds the band: loud, specific failure.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "initech", "name": "Initech"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "tenant_band_exhausted") {
		t.Fatalf("band: %d %s", rec.Code, rec.Body.String())
	}
	// A bad slug is rejected.
	if rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "Bad Slug!", "name": "x"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad slug: %d", rec.Code)
	}

	// Configure.
	rec = f.doAuthed(t, token, http.MethodPatch, "/provider/v1/tenants/"+acme.ID, map[string]string{"name": "Acme Industries"})
	var renamed Tenant
	mustDecode(t, rec, &renamed)
	if rec.Code != http.StatusOK || renamed.Name != "Acme Industries" {
		t.Fatalf("configure: %d %+v", rec.Code, renamed)
	}

	// Suspend → resume → offboard, asserting status transitions.
	for _, step := range []struct{ action, want string }{
		{"suspend", "suspended"}, {"resume", "active"}, {"offboard", "offboarding"},
	} {
		rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants/"+acme.ID+"/"+step.action, nil)
		var tn Tenant
		mustDecode(t, rec, &tn)
		if rec.Code != http.StatusOK || tn.Status != step.want {
			t.Fatalf("%s: %d status=%s", step.action, rec.Code, tn.Status)
		}
	}

	// Offboarding freed a band slot: provisioning works again.
	if rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "initech", "name": "Initech"}); rec.Code != http.StatusCreated {
		t.Fatalf("post-offboard provision: %d %s", rec.Code, rec.Body.String())
	}

	// Every lifecycle action is on the provider audit stream.
	for _, action := range []string{
		"provider.bootstrap", "provider.operator_enrolled", "provider.login",
		"provider.tenant_provision", "provider.tenant_configure",
		"provider.tenant_suspend", "provider.tenant_resume", "provider.tenant_offboard",
	} {
		if f.audit.count(action) == 0 {
			t.Errorf("audit stream missing %s", action)
		}
	}
}

// TestNoImplicitTelemetryAccess is THE S-T1 test: an operator cannot read
// tenant telemetry without an ACTIVE break-glass grant — not before consent,
// not after expiry, not after revocation, not via another operator's grant —
// and every successful access is audited on the provider stream.
func TestNoImplicitTelemetryAccess(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	f.svc.telemetry = fakeTelemetry{byTenant: map[string][]string{
		"tnA": {"result-A1", "result-A2"},
		"tnB": {"result-B1"},
	}}
	token := f.bootstrapAndLoginFast(t)

	// Request break-glass into tenant A.
	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": "tnA", "reason": "incident #42: cross-plane RCA", "ttl_minutes": 60})
	if rec.Code != http.StatusCreated {
		t.Fatalf("request grant: %d %s", rec.Code, rec.Body.String())
	}
	var g Grant
	mustDecode(t, rec, &g)

	// PENDING grant: telemetry access is refused.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "breakglass_not_active") {
		t.Fatalf("pending grant must not grant access: %d %s", rec.Code, rec.Body.String())
	}

	// A non-admin tenant user CANNOT consent (no directory.write).
	req := newReq(http.MethodPost, "/provider/v1/consent/"+g.ID, map[string]string{"decision": "approve"})
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "tenant-user-A"})
	if rec = doReq(f.h, req); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin consent: %d", rec.Code)
	}
	// Tenant B's admin CANNOT consent tenant A's grant (tenant boundary).
	req = newReq(http.MethodPost, "/provider/v1/consent/"+g.ID, map[string]string{"decision": "approve"})
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "tenant-admin-B"})
	if rec = doReq(f.h, req); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant consent must be refused: %d %s", rec.Code, rec.Body.String())
	}
	// Tenant A's admin consents.
	req = newReq(http.MethodPost, "/provider/v1/consent/"+g.ID, map[string]string{"decision": "approve"})
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "tenant-admin-A"})
	if rec = doReq(f.h, req); rec.Code != http.StatusOK {
		t.Fatalf("consent: %d %s", rec.Code, rec.Body.String())
	}

	// ACTIVE grant: access works, returns ONLY tenant A's data, and is audited.
	before := f.audit.count("provider.breakglass_access")
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("active grant access: %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "result-A1") || strings.Contains(body, "result-B1") {
		t.Fatalf("grant-scoped read leaked or missed: %s", body)
	}
	if f.audit.count("provider.breakglass_access") != before+1 {
		t.Fatal("break-glass access was not audited")
	}
	// A second read = a second audit record (every access, not every grant).
	_ = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil)
	if f.audit.count("provider.breakglass_access") != before+2 {
		t.Fatal("every access must be audited")
	}

	// ANOTHER operator cannot ride this grant (operator-bound).
	rec2 := f.doAuthed(t, token, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op2@msp.example", "name": "Op Two", "role": "operator"})
	var created struct {
		Operator    Operator `json:"operator"`
		EnrollToken string   `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op2 := f.activateAndIssue(t, created.Operator)
	if rec = f.doAuthed(t, op2, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign operator on a grant: %d", rec.Code)
	}

	// EXPIRY: move the clock past the TTL — access stops.
	*f.now = f.now.Add(2 * time.Hour)
	if rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("expired grant must not grant access: %d", rec.Code)
	}
	*f.now = f.now.Add(-2 * time.Hour)

	// REVOCATION ends access immediately.
	if rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass/"+g.ID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g.ID+"/results", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked grant must not grant access: %d", rec.Code)
	}

	// DENIAL: a denied grant never activates.
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": "tnA", "reason": "second look", "ttl_minutes": 30})
	var g2 Grant
	mustDecode(t, rec, &g2)
	req = newReq(http.MethodPost, "/provider/v1/consent/"+g2.ID, map[string]string{"decision": "deny"})
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "tenant-admin-A"})
	if rec = doReq(f.h, req); rec.Code != http.StatusOK {
		t.Fatalf("deny: %d", rec.Code)
	}
	if rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/breakglass/"+g2.ID+"/results", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("denied grant must not grant access: %d", rec.Code)
	}
}

// TestBreakGlassConsentEnforcesTenantABAC proves the tenant consent leg applies
// the same tenant-first, RBAC-then-ABAC decision as the core API. A deny policy
// must beat directory.write for both approval and denial, policy-store faults
// must fail closed, and tenant A's policy must never affect tenant B.
func TestBreakGlassConsentEnforcesTenantABAC(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	operatorToken := f.bootstrapAndLoginFast(t)
	f.tenantAuth.attributes["uA"] = map[string]string{"department": "contractor", "mfa": "true"}
	f.tenantAuth.attributes["uB"] = map[string]string{"department": "contractor", "mfa": "true"}
	f.tenantAuth.policies["tnA"] = []auth.Policy{{
		Name:       "contractors cannot decide break-glass",
		Effect:     auth.PolicyDeny,
		Permission: consentPermission,
		Subject:    map[string]string{"department": "contractor"},
		Priority:   100,
		Enabled:    true,
	}}

	requestGrant := func(t *testing.T, tenantID string) Grant {
		t.Helper()
		rec := f.doAuthed(t, operatorToken, http.MethodPost, "/provider/v1/breakglass",
			map[string]any{"tenant_id": tenantID, "reason": "tenant ABAC regression", "ttl_minutes": 30})
		if rec.Code != http.StatusCreated {
			t.Fatalf("request %s grant: %d %s", tenantID, rec.Code, rec.Body.String())
		}
		var g Grant
		mustDecode(t, rec, &g)
		return g
	}
	decide := func(t *testing.T, token, grantID, decision string) *httptest.ResponseRecorder {
		t.Helper()
		req := newReq(http.MethodPost, "/provider/v1/consent/"+grantID, map[string]string{"decision": decision})
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
		return doReq(f.h, req)
	}

	for _, decision := range []string{"approve", "deny"} {
		g := requestGrant(t, "tnA")
		rec := decide(t, "tenant-admin-A", g.ID, decision)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("ABAC-denied tenant A %s = %d %s, want 403", decision, rec.Code, rec.Body.String())
		}
		stored, err := f.store.GetGrant(t.Context(), g.ID)
		if err != nil {
			t.Fatal(err)
		}
		if state := stored.State(*f.now); state != GrantPending {
			t.Fatalf("ABAC-denied %s mutated grant to %q, want pending", decision, state)
		}
	}

	delete(f.tenantAuth.policies, "tnA")
	f.tenantAuth.policyErr["tnA"] = errors.New("simulated tenant policy store outage")
	gFault := requestGrant(t, "tnA")
	rec := decide(t, "tenant-admin-A", gFault.ID, "approve")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("policy-load failure = %d %s, want 503", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"authorization_unavailable"`) ||
		strings.Contains(body, "simulated tenant policy store outage") {
		t.Fatalf("policy-load response must be actionable but non-revealing: %s", body)
	}
	if stored, err := f.store.GetGrant(t.Context(), gFault.ID); err != nil || stored.State(*f.now) != GrantPending {
		t.Fatalf("policy-load failure mutated grant: grant=%+v err=%v", stored, err)
	}

	delete(f.tenantAuth.policyErr, "tnA")
	gB := requestGrant(t, "tnB")
	rec = decide(t, "tenant-admin-B", gB.ID, "approve")
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant A policy crossed into tenant B: %d %s", rec.Code, rec.Body.String())
	}
	storedB, err := f.store.GetGrant(t.Context(), gB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state := storedB.State(*f.now); state != GrantActive {
		t.Fatalf("tenant B grant state = %q, want active", state)
	}
}

// TestFleetAggregation: fleet health spans tenants (counts/versions only) and
// never bleeds one tenant's rows into another.
func TestFleetAggregation(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)

	var ids []string
	for _, slug := range []string{"acme", "globex"} {
		rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": slug, "name": slug})
		var tn Tenant
		mustDecode(t, rec, &tn)
		ids = append(ids, tn.ID)
	}
	f.store.SetFleet(
		TenantFleet{TenantID: ids[0], AgentsTotal: 3, AgentsOnline: 2, AgentsStale: 1, Versions: map[string]int{"0.3.0": 3}},
		TenantFleet{TenantID: ids[1], AgentsTotal: 1, AgentsOnline: 1, Versions: map[string]int{"0.2.9": 1}},
	)

	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/fleet", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet: %d", rec.Code)
	}
	var out struct {
		Items []TenantFleet `json:"items"`
	}
	mustDecode(t, rec, &out)
	if len(out.Items) != 2 {
		t.Fatalf("fleet rows: %d", len(out.Items))
	}
	byID := map[string]TenantFleet{}
	for _, r := range out.Items {
		byID[r.TenantID] = r
	}
	a, b := byID[ids[0]], byID[ids[1]]
	if a.AgentsTotal != 3 || a.AgentsOnline != 2 || a.AgentsStale != 1 || a.Versions["0.3.0"] != 3 {
		t.Fatalf("acme fleet wrong: %+v", a)
	}
	if b.AgentsTotal != 1 || b.Versions["0.2.9"] != 1 || b.Versions["0.3.0"] != 0 {
		t.Fatalf("globex fleet wrong (cross-bleed?): %+v", b)
	}
	// The fleet payload carries NO telemetry-shaped fields.
	if s := rec.Body.String(); strings.Contains(s, "latency") || strings.Contains(s, "result") {
		t.Fatalf("fleet view must carry operational metadata only: %s", s)
	}
}

func TestFairnessProviderRoundTripDeviceAndOTLPOverrides(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)
	store := &memFairnessStore{policies: map[string]fairness.Policy{}}
	now := time.Now()
	gate := fairness.NewGate(fairness.Policy{
		DeviceMetricsPerSec: 1000,
		OTLPSeriesPerSec:    1000,
		BurstSeconds:        1,
	}, store).WithPolicyTTL(time.Hour).WithNow(func() time.Time { return now })
	f.h.WithFairness(&Fairness{Gate: gate, Store: store})

	const tenantID = "tn-device-otlp"
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/"+tenantID+"/fairness", map[string]any{
		"device_metrics_per_sec": 2,
		"otlp_series_per_sec":    3,
		"burst_seconds":          1,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("fairness PUT: %d %s", rec.Code, rec.Body.String())
	}
	var body fairness.Policy
	mustDecode(t, rec, &body)
	if body.DeviceMetricsPerSec != 2 || body.OTLPSeriesPerSec != 3 || body.BurstSeconds != 1 {
		t.Fatalf("fairness response omitted device/OTLP overrides: %+v", body)
	}
	if f.audit.count("provider.fairness_set") != 1 {
		t.Fatal("provider fairness update must be audited")
	}
	f.audit.mu.Lock()
	auditData := f.audit.events[len(f.audit.events)-1].Data
	f.audit.mu.Unlock()
	if auditData["device_metrics_per_sec"] != float64(2) || auditData["otlp_series_per_sec"] != float64(3) {
		t.Fatalf("audit data omitted device/OTLP overrides: %+v", auditData)
	}

	gate.EffectivePolicy(t.Context(), tenantID)
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := gate.EffectivePolicy(t.Context(), tenantID)
		if p.DeviceMetricsPerSec == 2 && p.OTLPSeriesPerSec == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate did not refresh provider override: %+v", p)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for range 2 {
		if !gate.AdmitN(t.Context(), tenantID, fairness.MeterDeviceMetrics, 1) {
			t.Fatal("device override must admit within capacity")
		}
	}
	if gate.AdmitN(t.Context(), tenantID, fairness.MeterDeviceMetrics, 1) {
		t.Fatal("device override must shed above capacity")
	}
	for range 3 {
		if !gate.AdmitN(t.Context(), tenantID, fairness.MeterOTLPSeries, 1) {
			t.Fatal("OTLP override must admit within capacity")
		}
	}
	if gate.AdmitN(t.Context(), tenantID, fairness.MeterOTLPSeries, 1) {
		t.Fatal("OTLP override must shed above capacity")
	}

	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/fairness", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fairness GET: %d %s", rec.Code, rec.Body.String())
	}
	if s := rec.Body.String(); !strings.Contains(s, `"device_metrics_per_sec":2`) ||
		!strings.Contains(s, `"otlp_series_per_sec":3`) {
		t.Fatalf("provider fairness view omitted device/OTLP fields: %s", s)
	}
}

// TestSeparationOfDuties: operator-role accounts cannot manage operators.
func TestSeparationOfDuties(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	admin := f.bootstrapAndLoginFast(t)

	rec := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Operator    Operator `json:"operator"`
		EnrollToken string   `json:"enroll_token"`
	}
	mustDecode(t, rec, &created)
	op := f.activateAndIssue(t, created.Operator)

	// The operator can run lifecycle…
	if rec = f.doAuthed(t, op, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "acme", "name": "Acme"}); rec.Code != http.StatusCreated {
		t.Fatalf("operator lifecycle: %d", rec.Code)
	}
	// …but not manage operators (admin SoD).
	if rec = f.doAuthed(t, op, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "x@msp.example", "name": "X", "role": "operator"}); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator created an operator: %d", rec.Code)
	}
	if rec = f.doAuthed(t, op, http.MethodGet, "/provider/v1/operators", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator listed operators: %d", rec.Code)
	}
}

// TestReadOnlyDegrade: an expired-past-grace provider license keeps GETs alive
// and blocks every mutation with license_read_only (the S-T0 ladder).
func TestReadOnlyDegrade(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, -31*24*time.Hour)) // read_only state
	token := f.bootstrapAndLoginReadOnly(t)

	// Reads still work.
	if rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/tenants", nil); rec.Code != http.StatusOK {
		t.Fatalf("read in read-only: %d", rec.Code)
	}
	if rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/fleet", nil); rec.Code != http.StatusOK {
		t.Fatalf("fleet in read-only: %d", rec.Code)
	}
	// Mutations are refused, loudly and specifically.
	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/tenants", map[string]string{"slug": "acme", "name": "Acme"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("provision in read-only: %d %s", rec.Code, rec.Body.String())
	}
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": "tnA", "reason": "x", "ttl_minutes": 10})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("grant in read-only: %d %s", rec.Code, rec.Body.String())
	}
}

// bootstrapAndLoginReadOnly seeds an operator directly in the store (the
// read-only ladder blocks CreateOperator — which is itself part of the
// contract), then issues a live session so read-only route behavior is tested
// without spending the race-test budget on PBKDF2.
func (f *fixture) bootstrapAndLoginReadOnly(t *testing.T) string {
	t.Helper()
	op, err := f.store.CreateOperator(context.Background(),
		Operator{Email: "root@msp.example", Name: "Root", Role: RoleAdmin, Status: "disabled"},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	return f.activateAndIssue(t, op)
}

// TestAuthHardening: bad bootstrap tokens, uniform login failures, dead
// sessions after disablement, and bootstrap single-use.
func TestAuthHardening(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))

	// A wrong bootstrap token is refused with no detail.
	rec := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": "wrong", "email": "x@y.example", "name": "X"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong bootstrap token: %d", rec.Code)
	}
	admin := f.bootstrapAndLogin(t)

	// Bootstrap is single-use: inert once operators exist, even with the right token.
	rec = doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/bootstrap",
		map[string]string{"token": bootToken, "email": "again@msp.example", "name": "Again"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bootstrap reuse: %d %s", rec.Code, rec.Body.String())
	}

	// Login failures are uniform 403s: wrong password and wrong TOTP look identical.
	rec = doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
		map[string]string{"email": "root@msp.example", "password": "wrong", "totp": "000000"}))
	body1 := rec.Body.String()
	rec2 := doReq(f.h, newReq(http.MethodPost, "/provider/v1/auth/login",
		map[string]string{"email": "nobody@msp.example", "password": "x", "totp": "000000"}))
	if rec.Code != http.StatusForbidden || rec2.Code != http.StatusForbidden || body1 != rec2.Body.String() {
		t.Fatalf("login failures must be uniform: %d/%d %q vs %q", rec.Code, rec2.Code, body1, rec2.Body.String())
	}

	// No session = 401 on every operator route.
	if rec = doReq(f.h, newReq(http.MethodGet, "/provider/v1/tenants", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}

	// Disabling an operator kills its live session immediately.
	rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	var created struct {
		Operator    Operator `json:"operator"`
		EnrollToken string   `json:"enroll_token"`
	}
	mustDecode(t, rec, &created)
	op := f.activateAndIssue(t, created.Operator)
	if rec = f.doAuthed(t, op, http.MethodGet, "/provider/v1/me", nil); rec.Code != http.StatusOK {
		t.Fatalf("live session: %d", rec.Code)
	}
	if rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators/"+created.Operator.ID+"/status",
		map[string]string{"status": "disabled"}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec = f.doAuthed(t, op, http.MethodGet, "/provider/v1/me", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled operator session must die: %d", rec.Code)
	}
}

// TestGrantStateDerivation pins the Grant state machine.
func TestGrantStateDerivation(t *testing.T) {
	now := time.Now()
	hour := now.Add(time.Hour)
	consented := now.Add(-time.Minute)
	cases := []struct {
		name string
		g    Grant
		want string
	}{
		{"pending", Grant{ExpiresAt: hour}, GrantPending},
		{"active", Grant{ExpiresAt: hour, ConsentedAt: &consented}, GrantActive},
		{"expired-pending", Grant{ExpiresAt: now.Add(-time.Second)}, GrantExpired},
		{"expired-after-consent", Grant{ExpiresAt: now.Add(-time.Second), ConsentedAt: &consented}, GrantExpired},
		{"denied", Grant{ExpiresAt: hour, DeniedAt: &consented}, GrantDenied},
		{"revoked-beats-all", Grant{ExpiresAt: hour, ConsentedAt: &consented, RevokedAt: &consented}, GrantRevoked},
	}
	for _, tc := range cases {
		if got := tc.g.State(now); got != tc.want {
			t.Errorf("%s: state = %s, want %s", tc.name, got, tc.want)
		}
		if usable := tc.g.Usable(now); usable != (tc.want == GrantActive) {
			t.Errorf("%s: usable = %v", tc.name, usable)
		}
	}
}

// TestConsentListIsTenantScoped: each tenant sees only its own pending grants.
func TestConsentListIsTenantScoped(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)
	for _, tn := range []string{"tnA", "tnB"} {
		rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
			map[string]any{"tenant_id": tn, "reason": "audit " + tn, "ttl_minutes": 30})
		if rec.Code != http.StatusCreated {
			t.Fatalf("grant %s: %d", tn, rec.Code)
		}
	}
	req := newReq(http.MethodGet, "/provider/v1/consent", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "tenant-admin-A"})
	rec := doReq(f.h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("consent list: %d", rec.Code)
	}
	if s := rec.Body.String(); !strings.Contains(s, "tnA") || strings.Contains(s, "tnB") {
		t.Fatalf("consent list leaked across tenants: %s", s)
	}
}

// TestBreakGlassTTLCap: TTLs beyond the configured cap are refused.
func TestBreakGlassTTLCap(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	token := f.bootstrapAndLoginFast(t)
	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": "tnA", "reason": "way too long", "ttl_minutes": 60 * 24 * 7})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ttl cap: %d %s", rec.Code, rec.Body.String())
	}
	// And a missing reason is refused (break-glass is always justified).
	rec = f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": "tnA", "reason": "  ", "ttl_minutes": 30})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing reason: %d", rec.Code)
	}
}
