// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AUTHZ-15: ABAC deny policies must be enforced — and every denial audited — on
// the routes where enforcement was silently skipped (handlers reading
// principal.Permissions directly, incident data returned under a weaker
// permission), and policy-create must reject resource keys no route supplies so
// a deny can never look enforced while failing open (docs/guardrails.md G7-5).

// createUserWithPerms is createUserWithPerm for a user needing more than one
// grant (e.g. the coverage matrix needs both test.read and agent.read).
func createUserWithPerms(t *testing.T, db *store.DB, tenant, email string, attrs map[string]string, perms ...string) string {
	t.Helper()
	var uid string
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, e := store.Users{}.CreateSCIM(ctx, sc, store.User{Email: email, UserName: email, Attributes: attrs})
		if e != nil {
			return e
		}
		uid = u.ID
		role, e := store.Roles{}.Create(ctx, sc, "svc-"+email[:6], "svc", "")
		if e != nil {
			return e
		}
		for _, perm := range perms {
			if e := (store.Roles{}).AddPermission(ctx, sc, role.ID, perm); e != nil {
				return e
			}
		}
		return store.RoleBindings{}.Bind(ctx, sc, "user", uid, role.ID)
	})
	if err != nil {
		t.Fatalf("create user with perms: %v", err)
	}
	return uid
}

func authz15Session(t *testing.T, srv *Server, tenant, uid, email string) *http.Cookie {
	t.Helper()
	sess, err := srv.sessions.Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: uid, Email: email, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return &http.Cookie{Name: auth.SessionCookie, Value: sess}
}

// TestAUTHZ15PolicyResourceKeyValidation: a deny whose resource keys no route
// supplies for its permission is REJECTED at create time (422), so it can never
// be stored as an unenforceable (silently failing-open) policy. Hierarchy-scoped
// policies (org/team/project on org.read or "*") and the tenant-boundary key
// remain accepted.
func TestAUTHZ15PolicyResourceKeyValidation(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "az15val")
	uid := createUserWithPerms(t, db, tenant, "admin15@x.com", nil, permDirectoryWrite)

	cases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "deny org-scoped on non-hierarchy permission is rejected",
			body: `{"name":"dead","effect":"deny","permission":"test.write","resource":{"org":"org-1"},"priority":100,"enabled":true}`,
			want: http.StatusUnprocessableEntity,
		},
		{
			name: "deny with unknown resource key is rejected",
			body: `{"name":"dead2","effect":"deny","permission":"agent.read","resource":{"widget":"w-1"},"priority":50,"enabled":true}`,
			want: http.StatusUnprocessableEntity,
		},
		{
			name: "deny org-scoped on org.read is accepted (hierarchy route supplies it)",
			body: `{"name":"live","effect":"deny","permission":"org.read","resource":{"org":"org-1"},"priority":10,"enabled":true}`,
			want: http.StatusCreated,
		},
		{
			name: "deny team-scoped on wildcard is accepted",
			body: `{"name":"wild","effect":"deny","permission":"*","resource":{"team":"team-1"},"priority":10,"enabled":true}`,
			want: http.StatusCreated,
		},
		{
			name: "deny on tenant-boundary key is accepted",
			body: `{"name":"tenantkey","effect":"deny","permission":"ai.query","resource":{"tenant":"` + tenant + `"},"priority":10,"enabled":true}`,
			want: http.StatusCreated,
		},
		{
			name: "subject-only deny (no resource) is accepted",
			body: `{"name":"subjonly","effect":"deny","permission":"test.write","subject":{"department":"contractor"},"priority":10,"enabled":true}`,
			want: http.StatusCreated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh session per request: the control plane rotates (and
			// invalidates) the session cookie on each call.
			cookie := authz15Session(t, srv, tenant, uid, "admin15@x.com")
			rec := sessionReq(t, h, http.MethodPost, "/v1/abac/policies", cookie, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("create policy = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// TestAUTHZ15DeniesAreEnforcedAndAudited: for every affected route, a DENY on
// the permission the route actually consumes (the secondary agent.read on the
// coverage endpoints, incident.read on the incident-data paths) returns 403 AND
// writes exactly one abac.denied audit row naming that permission — proving the
// decision routes through the ABAC chokepoint and the single audit emission.
func TestAUTHZ15DeniesAreEnforcedAndAudited(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()

	contractor := map[string]string{"department": "contractor"}
	cases := []struct {
		name      string
		perms     []string // grants the user holds (RBAC passes)
		denyPerm  string   // the permission a deny policy targets
		method    string
		path      string
		body      string
		auditPerm string // the permission expected on the single abac.denied row
	}{
		{
			name:      "coverage vantages denies secondary agent.read",
			perms:     []string{permTestRead, permAgentRead},
			denyPerm:  permAgentRead,
			method:    http.MethodGet,
			path:      "/v1/coverage/vantages",
			auditPerm: permAgentRead,
		},
		{
			name:      "coverage debt denies secondary agent.read",
			perms:     []string{permTestRead, permAgentRead, ai.PermTopologyRead},
			denyPerm:  permAgentRead,
			method:    http.MethodGet,
			path:      "/v1/coverage/debt",
			auditPerm: permAgentRead,
		},
		{
			name:      "coverage debt denies secondary topology.read",
			perms:     []string{permTestRead, permAgentRead, ai.PermTopologyRead},
			denyPerm:  ai.PermTopologyRead,
			method:    http.MethodGet,
			path:      "/v1/coverage/debt",
			auditPerm: ai.PermTopologyRead,
		},
		{
			name:      "alert workflow incident data denies incident.read",
			perms:     []string{permAlertRead, permIncidentRead},
			denyPerm:  permIncidentRead,
			method:    http.MethodGet,
			path:      "/v1/alerts/active/fp-az15/workflow?incident_id=inc-az15",
			auditPerm: permIncidentRead,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := freshTenant(t, db, fmt.Sprintf("az15d%d", i))
			email := fmt.Sprintf("deny%d@x.com", i)
			uid := createUserWithPerms(t, db, tenant, email, contractor, tc.perms...)
			createDenyPolicy(t, db, tenant, tc.denyPerm, contractor)
			cookie := authz15Session(t, srv, tenant, uid, email)

			rec := sessionReq(t, h, tc.method, tc.path, cookie, tc.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s with %s denied = %d, want 403: %s", tc.method, tc.path, tc.denyPerm, rec.Code, rec.Body)
			}
			rows := abacDenialRows(t, db, tenant)
			if len(rows) != 1 {
				t.Fatalf("a deny must write exactly one abac.denied row, got %d", len(rows))
			}
			if rows[0].Target != tc.auditPerm || rows[0].Data["permission"] != tc.auditPerm {
				t.Fatalf("abac.denied row must name %q, got target=%q data=%v", tc.auditPerm, rows[0].Target, rows[0].Data)
			}
		})
	}
}

// TestAUTHZ15AlertWorkflowIncidentReadRequired: the alert-workflow incident join
// returns ONLY incident-plane data, so an incident_id query with no incident.read
// is 403 even with no policy at all — an RBAC miss, NOT recorded as a policy
// denial — while a caller who holds incident.read is not blocked by authorization.
func TestAUTHZ15AlertWorkflowIncidentReadRequired(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	const path = "/v1/alerts/active/fp-az15b/workflow?incident_id=inc-az15b"

	// Missing incident.read: 403, and no abac.denied row (RBAC miss, not a policy
	// denial).
	tMiss := freshTenant(t, db, "az15awm")
	uMiss := createUserWithPerms(t, db, tMiss, "awmiss@x.com", nil, permAlertRead)
	cMiss := authz15Session(t, srv, tMiss, uMiss, "awmiss@x.com")
	if rec := sessionReq(t, h, http.MethodGet, path, cMiss, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("alert workflow incident_id without incident.read = %d, want 403: %s", rec.Code, rec.Body)
	}
	if rows := abacDenialRows(t, db, tMiss); len(rows) != 0 {
		t.Fatalf("an RBAC miss must not be recorded as a policy denial, got %d rows", len(rows))
	}

	// Holding incident.read: authorization does not block it (the 404 that
	// follows for a non-existent incident is not an authorization refusal).
	tOK := freshTenant(t, db, "az15awo")
	uOK := createUserWithPerms(t, db, tOK, "awok@x.com", nil, permAlertRead, permIncidentRead)
	cOK := authz15Session(t, srv, tOK, uOK, "awok@x.com")
	if rec := sessionReq(t, h, http.MethodGet, path, cOK, ""); rec.Code == http.StatusForbidden {
		t.Fatalf("alert workflow incident_id with incident.read must not be 403: %s", rec.Body)
	}
}

// seedIncident creates one open incident with the given synthetic target so a
// discovery read has incident-plane data to expose.
func seedIncident(t *testing.T, db *store.DB, tenant, target string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		now := time.Now().UTC()
		_, e := store.Incidents{}.Create(ctx, sc, incident.Incident{
			Severity: incident.SeverityWarning, Title: "seed " + target, Target: target,
			StartedAt: now, LastSeenAt: now,
		})
		return e
	})
	if err != nil {
		t.Fatalf("seed incident: %v", err)
	}
}

// TestAUTHZ15DiscoverIncidentDataGatedByIncidentRead: /v1/ai/discover must not
// expose incident-derived targets without incident.read. Unlike the workflow
// route, discover also serves a flow-only caller, so a missing/denied
// incident.read WITHHOLDS the incident data (and audits a deny) rather than
// 403-ing the whole route.
func TestAUTHZ15DiscoverIncidentDataGatedByIncidentRead(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	const target = "10.9.9.9"
	contractor := map[string]string{"department": "contractor"}

	hasIncidentProposal := func(t *testing.T, body string) bool {
		t.Helper()
		var out struct {
			Proposals []struct {
				Source string `json:"source"`
				Spec   struct {
					Target string `json:"target"`
				} `json:"spec"`
			} `json:"proposals"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode discover response: %v (%s)", err, body)
		}
		for _, p := range out.Proposals {
			if p.Source == "incident" && p.Spec.Target == target {
				return true
			}
		}
		return false
	}

	// Caller WITH incident.read and no policy: the incident target is proposed.
	tAllow := freshTenant(t, db, "az15dia")
	seedIncident(t, db, tAllow, target)
	uAllow := createUserWithPerms(t, db, tAllow, "diallow@x.com", nil, permTestWrite, permIncidentRead)
	cAllow := authz15Session(t, srv, tAllow, uAllow, "diallow@x.com")
	rec := sessionReq(t, h, http.MethodPost, "/v1/ai/discover", cAllow, "")
	if rec.Code != http.StatusOK || !hasIncidentProposal(t, rec.Body.String()) {
		t.Fatalf("incident.read caller must see the incident proposal: %d %s", rec.Code, rec.Body)
	}

	// Caller WITH incident.read but a DENY policy: incident data withheld AND the
	// deny is audited exactly once.
	tDeny := freshTenant(t, db, "az15did")
	seedIncident(t, db, tDeny, target)
	uDeny := createUserWithPerms(t, db, tDeny, "dideny@x.com", contractor, permTestWrite, permIncidentRead)
	createDenyPolicy(t, db, tDeny, permIncidentRead, contractor)
	cDeny := authz15Session(t, srv, tDeny, uDeny, "dideny@x.com")
	rec = sessionReq(t, h, http.MethodPost, "/v1/ai/discover", cDeny, "")
	if rec.Code != http.StatusOK || hasIncidentProposal(t, rec.Body.String()) {
		t.Fatalf("incident.read-denied caller must NOT see incident data: %d %s", rec.Code, rec.Body)
	}
	rows := abacDenialRows(t, db, tDeny)
	if len(rows) != 1 || rows[0].Target != permIncidentRead {
		t.Fatalf("a withheld incident read must write exactly one abac.denied row for %q, got %+v", permIncidentRead, rows)
	}

	// Caller WITHOUT incident.read (RBAC miss): incident data withheld, and NOT
	// recorded as a policy denial.
	tMiss := freshTenant(t, db, "az15dim")
	seedIncident(t, db, tMiss, target)
	uMiss := createUserWithPerms(t, db, tMiss, "dimiss@x.com", nil, permTestWrite)
	cMiss := authz15Session(t, srv, tMiss, uMiss, "dimiss@x.com")
	rec = sessionReq(t, h, http.MethodPost, "/v1/ai/discover", cMiss, "")
	if rec.Code != http.StatusOK || hasIncidentProposal(t, rec.Body.String()) {
		t.Fatalf("caller without incident.read must NOT see incident data: %d %s", rec.Code, rec.Body)
	}
	if rows := abacDenialRows(t, db, tMiss); len(rows) != 0 {
		t.Fatalf("an RBAC miss must not be recorded as a policy denial, got %d rows", len(rows))
	}
}
