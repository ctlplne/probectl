// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
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
	"github.com/imfeelingtheagi/probectl/internal/license"
)

// --- shared fixtures ---

// memAudit captures provider-stream audit events for assertions.
type memAudit struct {
	mu     sync.Mutex
	events []auditEvent
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

// fakeTelemetry stands in for the latest-results read model, tenant-keyed so
// the tests can prove grant-scoped access returns ONLY the grant's tenant.
type fakeTelemetry struct{ byTenant map[string][]string }

func (f fakeTelemetry) LatestResults(tenantID string) any { return f.byTenant[tenantID] }

// fakeTenantAuth resolves fixed tenant sessions: token -> (tenant, user, perms).
type fakeTenantAuth struct {
	sessions map[string]*auth.Session
	perms    map[string][]string // userID -> permission keys
}

func (f fakeTenantAuth) ResolveSession(_ context.Context, token string) (*auth.Session, error) {
	return f.sessions[token], nil
}

func (f fakeTenantAuth) Permissions(_ context.Context, _, userID string) ([]string, error) {
	return f.perms[userID], nil
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
	h     *Handler
	store *MemStore
	svc   *Service
	audit *memAudit
	now   *time.Time // movable clock
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
	ta := fakeTenantAuth{
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
	}
	f.h = NewHandler(svc, NewSessions(nil), ta, slog.New(slog.NewTextHandler(io.Discard, nil)), bootToken, false)
	return f
}

func newTestHandler(t *testing.T) *Handler {
	return newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour)).h
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
	f := newFixture(t, licenseManager(t, license.TierProvider, 2, 90*24*time.Hour)) // band of 2
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
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	f.svc.telemetry = fakeTelemetry{byTenant: map[string][]string{
		"tnA": {"result-A1", "result-A2"},
		"tnB": {"result-B1"},
	}}
	token := f.bootstrapAndLogin(t)

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
		EnrollToken string `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op2 := f.enrollAndLogin(t, created.EnrollToken, "op2@msp.example", "another-long-pw-12")
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

// TestFleetAggregation: fleet health spans tenants (counts/versions only) and
// never bleeds one tenant's rows into another.
func TestFleetAggregation(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	token := f.bootstrapAndLogin(t)

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

// TestSeparationOfDuties: operator-role accounts cannot manage operators.
func TestSeparationOfDuties(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	admin := f.bootstrapAndLogin(t)

	rec := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		EnrollToken string `json:"enroll_token"`
	}
	mustDecode(t, rec, &created)
	op := f.enrollAndLogin(t, created.EnrollToken, "op@msp.example", "operator-pw-123456")

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
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, -31*24*time.Hour)) // read_only state
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
// contract), then logs in normally: authentication still works read-only.
func (f *fixture) bootstrapAndLoginReadOnly(t *testing.T) string {
	t.Helper()
	enroll := "seed-enroll-token"
	if _, err := f.store.CreateOperator(context.Background(),
		Operator{Email: "root@msp.example", Name: "Root", Role: RoleAdmin, Status: "disabled"},
		crypto.Hash([]byte(enroll))); err != nil {
		t.Fatal(err)
	}
	return f.enrollAndLogin(t, enroll, "root@msp.example", "a-long-operator-pw")
}

// TestAuthHardening: bad bootstrap tokens, uniform login failures, dead
// sessions after disablement, and bootstrap single-use.
func TestAuthHardening(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))

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
	op := f.enrollAndLogin(t, created.EnrollToken, "op@msp.example", "operator-pw-123456")
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
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	token := f.bootstrapAndLogin(t)
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
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	token := f.bootstrapAndLogin(t)
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
