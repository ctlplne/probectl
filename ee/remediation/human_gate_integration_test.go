// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package remediation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	eeremediation "github.com/ctlplne/probectl/ee/remediation"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/migrations"
)

// TestRemediationIsHumanGatedRealStack is the real-stack receipt for F44
// (guarded remediation) and CLM-HUMAN-GATED ("Remediation is human-gated:
// explicit approval, dry-run, blast-radius limits; never autonomous").
//
// The control plane is the production constructor over real PostgreSQL; the
// remediation service is the production assembly from ee_attach.go (PG store,
// topology what-if estimator, tenant audit, license write gate); users are
// provisioned with the tenant's system roles exactly as tenant provisioning
// does, and sessions are issued by the production session manager, so every
// request runs through the production auth, RBAC and CSRF middleware. Two
// tenants, public /v1 API only:
//
//  1. proposals are created "proposed" with a dry-run blast radius computed by
//     the real topology what-if — never auto-approved;
//  2. default OFF: with the master switch off, a valid approval is refused;
//  3. four-eyes: the proposer cannot approve their own proposal;
//  4. human-only: an API bearer token holding remediation.approve is refused
//     (an automated or AI client cannot stand in for the approver);
//  5. a second human's interactive session approves a within-limit proposal,
//     and approval only RECORDS a decision;
//  6. an over-limit blast radius and an unknown blast radius are refused;
//  7. the other tenant cannot see or decide these proposals;
//  8. every decision and every blocked attempt is in the tenant's audit chain,
//     which still verifies; the other tenant's chain records none of it.
func TestRemediationIsHumanGatedRealStack(t *testing.T) {
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
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: hmacKey}
	srv := control.New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil)
	h := srv.Handler()

	// The production remediation assembly (cmd/probectl-control/ee_attach.go).
	topo := topology.NewIndexedStore()
	writes := license.WriteCapability(func() bool { return true })
	const maxBlastRadius = 3
	attach := func(approvalsEnabled bool) {
		svc := eeremediation.New(eeremediation.NewPGStore(db.Pool()), eeremediation.NewTopologyEstimator(topo, nil),
			eeremediation.NewTenantAudit(db.Pool()),
			eeremediation.Config{ApprovalsEnabled: approvalsEnabled, MaxBlastRadius: maxBlastRadius})
		srv.WithRemediation(remediation.GateServiceWrites(svc, writes))
	}

	sessions := auth.NewManager(store.NewSessions(db.Pool()), time.Hour, cfg.CookieSecure(), cfg.SessionHMACKey)
	tenantA := provisionTenant(t, db, "remed-a")
	tenantB := provisionTenant(t, db, "remed-b")
	alice := newAdmin(t, db, sessions, h, tenantA, "alice") // proposer
	bob := newAdmin(t, db, sessions, h, tenantA, "bob")     // second human approver
	carol := newAdmin(t, db, sessions, h, tenantB, "carol") // another tenant

	// Tenant A topology: web calls three APIs, all of which call one database.
	ta, err := topo.ForTenant(tenantA)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, e := range [][2]string{{"web", "api-1"}, {"web", "api-2"}, {"web", "api-3"}, {"api-1", "db"}, {"api-2", "db"}, {"api-3", "db"}} {
		ta.ObserveServiceEdge(topology.ServiceEdgeInput{Source: e[0], Destination: e[1], DestPort: 443, Transport: "tcp"}, now)
	}
	leaf, hub := nodeID(t, ta, "web"), nodeID(t, ta, "db")
	leafRadius, hubRadius := whatIfRadius(t, topo, tenantA, leaf), whatIfRadius(t, topo, tenantA, hub)
	// Failing a service impacts itself and every transitive caller: web has no
	// callers (1); db is called by api-1..3, which web calls (1 + 4).
	if leafRadius != 1 || hubRadius != 5 {
		t.Fatalf("topology fixture radii = %d/%d, want 1/5", leafRadius, hubRadius)
	}

	// 1 + 2. Default OFF: a dry-run proposal is created, but nobody can approve it.
	attach(false)
	p1 := alice.propose(t, "reroute_suggestion", "Reroute around web", leaf)
	if p1.State != "proposed" || p1.DryRun.BlastRadius != leafRadius {
		t.Fatalf("new proposal = state %q radius %d, want proposed / what-if radius %d", p1.State, p1.DryRun.BlastRadius, leafRadius)
	}
	if code, body := bob.do(t, http.MethodPost, "/v1/remediation/proposals/"+p1.ID+"/approve", map[string]any{"note": "ok"}); code != http.StatusConflict {
		t.Fatalf("approval with the master switch OFF = %d, want 409 (approvals disabled): %s", code, body)
	}

	attach(true)

	// 3. Four-eyes: the proposer cannot approve their own proposal.
	if code, body := alice.do(t, http.MethodPost, "/v1/remediation/proposals/"+p1.ID+"/approve", map[string]any{"note": "mine"}); code != http.StatusForbidden {
		t.Fatalf("self-approval = %d, want 403 (four-eyes): %s", code, body)
	}

	// 4. Human-only: a bearer token that HOLDS remediation.approve is still refused.
	token := bob.mintToken(t, "remediation.approve", "remediation.propose")
	if code, body := bearerDo(t, h, http.MethodPost, "/v1/remediation/proposals/"+p1.ID+"/approve", token, map[string]any{"note": "bot"}); code != http.StatusForbidden ||
		!strings.Contains(string(body), "interactive session") {
		t.Fatalf("bearer-token approval = %d %s, want 403 requiring an interactive session", code, body)
	}

	// 5. A second human's interactive session approves within the limit; approval records only.
	code, body := bob.do(t, http.MethodPost, "/v1/remediation/proposals/"+p1.ID+"/approve", map[string]any{"note": "within limits"})
	if code != http.StatusOK {
		t.Fatalf("second-human approval = %d, want 200: %s", code, body)
	}
	var approved proposalView
	mustJSON(t, body, &approved)
	if approved.State != "approved" || approved.DecidedBy == approved.ProposedBy || !strings.Contains(approved.DecidedBy, bob.email) {
		t.Fatalf("approved proposal = %+v, want approved by %s (not the proposer)", approved, bob.email)
	}

	// 6. Over-limit and unknown blast radii are refused.
	p2 := alice.propose(t, "reroute_suggestion", "Reroute around the database", hub)
	if p2.DryRun.BlastRadius != hubRadius {
		t.Fatalf("hub proposal radius = %d, want what-if radius %d", p2.DryRun.BlastRadius, hubRadius)
	}
	if code, body := bob.do(t, http.MethodPost, "/v1/remediation/proposals/"+p2.ID+"/approve", map[string]any{"note": "too wide"}); code != http.StatusConflict {
		t.Fatalf("over-limit approval (radius %d > %d) = %d, want 409: %s", hubRadius, maxBlastRadius, code, body)
	}
	p3 := alice.propose(t, "reroute_suggestion", "Reroute with no target", "")
	if p3.DryRun.BlastRadius >= 0 {
		t.Fatalf("target-less network change radius = %d, want unknown (<0)", p3.DryRun.BlastRadius)
	}
	if code, body := bob.do(t, http.MethodPost, "/v1/remediation/proposals/"+p3.ID+"/approve", map[string]any{"note": "unknown"}); code != http.StatusConflict {
		t.Fatalf("unknown-radius approval = %d, want 409: %s", code, body)
	}

	// 7. Tenant isolation: tenant B cannot see or decide tenant A's proposals.
	if code, _ := carol.do(t, http.MethodGet, "/v1/remediation/proposals/"+p2.ID, nil); code != http.StatusNotFound {
		t.Fatalf("tenant B reading tenant A's proposal = %d, want 404", code)
	}
	if code, _ := carol.do(t, http.MethodPost, "/v1/remediation/proposals/"+p2.ID+"/approve", map[string]any{"note": "x"}); code != http.StatusNotFound {
		t.Fatalf("tenant B approving tenant A's proposal = %d, want 404", code)
	}
	if code, body := carol.do(t, http.MethodGet, "/v1/remediation/proposals", nil); code != http.StatusOK || strings.Contains(string(body), p1.ID) {
		t.Fatalf("tenant B list = %d, must not include tenant A's proposals: %s", code, body)
	}

	// 8. The full trail is in tenant A's chain (and verifies); none of it is in B's.
	trail := alice.auditActions(t)
	for _, want := range []string{"remediation.propose", "remediation.approve", "remediation.approve_blocked"} {
		if trail[want] == 0 {
			t.Errorf("tenant A audit is missing %s (have %v)", want, trail)
		}
	}
	if trail["remediation.approve_blocked"] < 3 {
		t.Errorf("want ≥3 blocked approvals audited (self-approval, over-limit, unknown radius), got %d", trail["remediation.approve_blocked"])
	}
	if !alice.auditVerifies(t) {
		t.Error("tenant A's audit chain does not verify")
	}
	for action := range carol.auditActions(t) {
		if strings.HasPrefix(action, "remediation.") {
			t.Errorf("tenant B's audit chain records %s from tenant A", action)
		}
	}
}

type proposalView struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	ProposedBy string `json:"proposed_by"`
	DecidedBy  string `json:"decided_by"`
	DryRun     struct {
		BlastRadius int `json:"blast_radius"`
	} `json:"dry_run"`
}

// sessionUser is one human driving the public API with a real session cookie,
// following token rotation exactly as a browser does.
type sessionUser struct {
	h      http.Handler
	email  string
	cookie *http.Cookie
}

func (u *sessionUser) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	req := newJSONRequest(t, method, path, body)
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

func (u *sessionUser) propose(t *testing.T, kind, title, target string) proposalView {
	t.Helper()
	code, body := u.do(t, http.MethodPost, "/v1/remediation/proposals",
		map[string]any{"kind": kind, "title": title, "rationale": "real-stack receipt", "target": target})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("propose %q = %d: %s", title, code, body)
	}
	var p proposalView
	mustJSON(t, body, &p)
	if p.ID == "" {
		t.Fatalf("propose returned no id: %s", body)
	}
	return p
}

func (u *sessionUser) mintToken(t *testing.T, scopes ...string) string {
	t.Helper()
	code, body := u.do(t, http.MethodPost, "/v1/api-tokens", map[string]any{"name": "automation", "scopes": scopes})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("mint API token = %d: %s", code, body)
	}
	var out struct {
		Token string `json:"token"`
	}
	mustJSON(t, body, &out)
	if out.Token == "" {
		t.Fatalf("API token response carried no token: %s", body)
	}
	return out.Token
}

func (u *sessionUser) auditActions(t *testing.T) map[string]int {
	t.Helper()
	code, body := u.do(t, http.MethodGet, "/v1/audit?limit=500", nil)
	if code != http.StatusOK {
		t.Fatalf("list audit = %d: %s", code, body)
	}
	var out struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	mustJSON(t, body, &out)
	actions := map[string]int{}
	for _, ev := range out.Items {
		actions[ev.Action]++
	}
	return actions
}

func (u *sessionUser) auditVerifies(t *testing.T) bool {
	t.Helper()
	code, body := u.do(t, http.MethodGet, "/v1/audit/verify", nil)
	if code != http.StatusOK {
		t.Fatalf("verify audit = %d: %s", code, body)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	mustJSON(t, body, &out)
	return out.OK
}

func bearerDo(t *testing.T, h http.Handler, method, path, token string, body any) (int, []byte) {
	t.Helper()
	req := newJSONRequest(t, method, path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func newJSONRequest(t *testing.T, method, path string, body any) *http.Request {
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

func mustJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

// provisionTenant creates a tenant and seeds its system roles, as tenant
// provisioning does (ee/provider, bootstrap-admin).
func provisionTenant(t *testing.T, db *store.DB, prefix string) string {
	t.Helper()
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		prefix+"-"+time.Now().Format("150405.000000000"), prefix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	inTenant(t, db, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return store.Roles{}.EnsureSystemRoles(ctx, sc)
	})
	return tn.ID
}

// newAdmin provisions a user holding the tenant's system admin role and issues
// them a session through the production session manager.
func newAdmin(t *testing.T, db *store.DB, sessions *auth.Manager, h http.Handler, tenant, name string) *sessionUser {
	t.Helper()
	email := name + "-" + tenant[:8] + "@example.com"
	var userID string
	inTenant(t, db, tenant, func(ctx context.Context, sc tenancy.Scope) error {
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
	})
	token, err := sessions.Issue(context.Background(), auth.Session{TenantID: tenant, UserID: userID, Email: email, DisplayName: name})
	if err != nil {
		t.Fatalf("issue session for %s: %v", email, err)
	}
	return &sessionUser{h: h, email: email, cookie: &http.Cookie{Name: auth.SessionCookie, Value: token}}
}

func inTenant(t *testing.T, db *store.DB, tenant string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), fn); err != nil {
		t.Fatalf("tenant %s: %v", tenant, err)
	}
}

// nodeID resolves a service's topology node ID by label (the ID format is the
// topology package's own concern).
func nodeID(t *testing.T, ts topology.TenantStore, label string) string {
	t.Helper()
	for _, n := range ts.Latest().Nodes {
		if n.Label == label && n.Kind == topology.NodeService {
			return n.ID
		}
	}
	t.Fatalf("no service node labeled %q", label)
	return ""
}

// whatIfRadius is the blast radius the production what-if reports for target.
func whatIfRadius(t *testing.T, s topology.Store, tenant, target string) int {
	t.Helper()
	imp, err := topology.Simulate(s, tenant, target, time.Time{}, nil)
	if err != nil {
		t.Fatalf("what-if %s: %v", target, err)
	}
	return len(imp.ImpactedServices) + len(imp.ImpactedPrefixes) + len(imp.Disconnected)
}
