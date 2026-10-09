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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestSCIMABACAndDelegatedAdminRealStack is the real-stack receipt for F25
// (SCIM, ABAC, and delegated admin) through the complete operator workflow,
// across two tenants.
//
// It runs on the SSO receipt's stack: the production control plane behind TLS,
// Dex as the deployment IdP, people signing in for real in Chromium, the
// shipped `probectl-control bootstrap-admin` and the shipped CLI. The IdP's
// provisioning side is a SCIM 2.0 client over HTTPS with the tenant's bearer
// token, speaking both dialects the server accepts (Okta's group PATCH, Entra's
// quoted-string deactivate).
//
//  1. Each tenant admin mints a SCIM token through the CLI; tenant A's IdP
//     provisions two people with their department and adds both to the Editor
//     group; they sign in through Dex and hold the editor role.
//  2. ABAC, set through the CLI, narrows that role by attribute: the
//     contractor's test write is refused (and audited as abac.denied) while
//     the engineer's succeeds.
//  3. Delegated administration: the admin delegates org Alpha to both people
//     through the CLI. The engineer administers Alpha and nothing else (no
//     team in Beta, no tenant directory writes) and the contractor is still
//     held back by an ABAC policy on hierarchy writes; neither delegation shows
//     as an IdP group membership. In the rendered admin console the people and policies show,
//     and the admin removes the engineer's delegation with its control, which
//     ends it on his next request.
//  4. The IdP deprovisions the contractor: her live session is refused at once
//     and her next sign-in is turned away.
//  5. Two tenants: tenant B's SCIM token sees none of A's people and cannot
//     touch them, and B's own ABAC policy does not reach A.
func TestSCIMABACAndDelegatedAdminRealStack(t *testing.T) {
	st := newSSOStack(t, "scim-acme", "scim-globex")
	A, B := st.tenantA, st.tenantB
	const ada, bob, carla, dan = "ada@acme.example", "bob@globex.example", "carla@acme.example", "dan@acme.example"
	operatorScopes := []string{"tenant.read", "directory.read", "directory.write", "org.read", "org.write", "audit.read"}

	st.bootstrapAdmin(t, A, ada)
	st.bootstrapAdmin(t, B, bob)
	adaS, bobS := st.signIn(t, A, ada, "scim-acme"), st.signIn(t, B, bob, "scim-globex")
	adaTok, bobTok := adaS.apiToken(t, st, operatorScopes...), bobS.apiToken(t, st, operatorScopes...)

	// 1. SCIM tokens through the CLI; tenant A's IdP pushes people and a group.
	var scimA, scimB struct{ Token string }
	st.mustCLI(t, adaTok, &scimA, "scim", "create-token", "--body", `{"name":"okta"}`)
	st.mustCLI(t, bobTok, &scimB, "scim", "create-token", "--body", `{"name":"entra"}`)
	carlaID := st.scimProvision(t, scimA.Token, carla, "contractor")
	danID := st.scimProvision(t, scimA.Token, dan, "engineering")
	editors := st.scimGroup(t, scimA.Token, "Editor")
	if code, body := st.scimPush(t, scimA.Token, http.MethodPatch, "/Groups/"+editors.ID, map[string]any{
		"schemas": []string{scimPatchOp},
		"Operations": []map[string]any{{"op": "add", "path": "members",
			"value": []map[string]string{{"value": carlaID}, {"value": danID}}}},
	}); code/100 != 2 {
		t.Fatalf("IdP adds the Editor members = %d: %s", code, body)
	}
	carlaS, danS := st.signIn(t, A, carla, "scim-acme"), st.signIn(t, A, dan, "scim-acme")
	for who, s := range map[string]*ssoUser{carla: carlaS, dan: danS} {
		if me := s.me(t, st); me.TenantID != A || !slices.Contains(me.Permissions, "test.write") {
			t.Fatalf("%s signed in as %+v, want tenant A with the SCIM-synced editor role", who, me)
		}
	}

	// 2. ABAC narrows the editor role by the SCIM-provisioned department.
	st.mustCLI(t, adaTok, nil, "abac", "create", "--body",
		`{"name":"contractor write guard","effect":"deny","permission":"test.write","subject":{"department":"contractor"},"priority":10,"enabled":true}`)
	newTest := func(name string) map[string]any {
		return map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1", "interval_seconds": 30}
	}
	if code, body := carlaS.do(t, st, http.MethodPost, "/v1/tests", newTest("carla-check")); code != http.StatusForbidden {
		t.Fatalf("the contractor writing a test = %d, want 403 (ABAC): %s", code, body)
	}
	if code, body := danS.do(t, st, http.MethodPost, "/v1/tests", newTest("dan-check")); code != http.StatusCreated {
		t.Fatalf("the engineer writing a test = %d, want 201: %s", code, body)
	}
	if denied := st.auditCount(t, A, "abac.denied"); denied < 1 {
		t.Fatalf("tenant A's audit chain holds %d abac.denied events, want the contractor's", denied)
	}

	// 3. Delegated administration of org Alpha, through the CLI.
	var alpha, beta struct{ ID string }
	st.mustCLI(t, adaTok, &alpha, "hierarchy", "create-org", "--body", `{"slug":"alpha","name":"Alpha"}`)
	st.mustCLI(t, adaTok, &beta, "hierarchy", "create-org", "--body", `{"slug":"beta","name":"Beta"}`)
	delegate := fmt.Sprintf(`{"role":"admin","scope_type":"org","scope_id":%q}`, alpha.ID)
	st.mustCLI(t, adaTok, nil, "directory", "grant", danID, "--body", delegate)
	st.mustCLI(t, adaTok, nil, "directory", "grant", carlaID, "--body", delegate)
	st.mustCLI(t, adaTok, nil, "abac", "create", "--body",
		`{"name":"contractor hierarchy guard","effect":"deny","permission":"org.write","subject":{"department":"contractor"},"priority":10,"enabled":true}`)

	team := func(s *ssoUser, org, slug string) int {
		t.Helper()
		code, _ := s.do(t, st, http.MethodPost, "/v1/hierarchy/orgs/"+org+"/teams", map[string]string{"slug": slug, "name": slug})
		return code
	}
	// He is a tenant-wide editor (reads everything); the delegation adds the
	// administration of Alpha and nothing else.
	if code := team(danS, alpha.ID, "platform"); code != http.StatusCreated {
		t.Fatalf("the delegated engineer creating a team in Alpha = %d, want 201", code)
	}
	if code := team(danS, beta.ID, "sneak"); code != http.StatusForbidden {
		t.Fatalf("the delegated engineer creating a team in Beta = %d, want 403", code)
	}
	if code, body := danS.do(t, st, http.MethodPost, "/v1/directory/users", map[string]string{"email": "eve@acme.example"}); code != http.StatusForbidden {
		t.Fatalf("the delegated engineer adding a person to the tenant = %d, want 403: %s", code, body)
	}
	if code := team(carlaS, alpha.ID, "contractor-team"); code != http.StatusForbidden {
		t.Fatalf("the delegated contractor creating a team in Alpha = %d, want 403 (ABAC)", code)
	}
	if admins := st.scimGroup(t, scimA.Token, "Administrator").members(); slices.Contains(admins, danID) || slices.Contains(admins, carlaID) {
		t.Fatalf("the IdP sees a delegation as Administrator group membership: %v", admins)
	}

	// The admin console shows the people, their delegations and the policies,
	// and the admin ends the engineer's delegation with its control.
	removeDan := "Remove admin on org Alpha from " + dan
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.baseURL + "/ui/admin",
		Cookies:        []testsupport.RenderCookie{{Name: "probectl_session", Value: adaS.cookie}},
		TrustCertFiles: st.trustCerts, CAFile: st.caFile,
		Expect: []string{"People & roles", carla, dan, "admin · Org Alpha", "contractor write guard", "contractor hierarchy guard"},
		Steps: []testsupport.RenderStep{
			{Click: removeDan},
			{Click: "Remove role", Vanish: removeDan},
		},
	})
	if code := team(danS, alpha.ID, "after-revoke"); code != http.StatusForbidden {
		t.Fatalf("the engineer creating a team after the console revoked his delegation = %d, want 403", code)
	}

	// 4. The IdP deprovisions the contractor (Entra's quoted-string dialect).
	if code, body := st.scimPush(t, scimA.Token, http.MethodPatch, "/Users/"+carlaID, map[string]any{
		"schemas":    []string{scimPatchOp},
		"Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}},
	}); code/100 != 2 {
		t.Fatalf("IdP deactivates the contractor = %d: %s", code, body)
	}
	if code, body := carlaS.do(t, st, http.MethodGet, "/v1/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("the deprovisioned contractor's live session = %d, want 401 at once: %s", code, body)
	}
	st.signInRefusedWith(t, A, carla, "account is not active")

	// 5. Tenant B's IdP and policies never reach tenant A.
	if code, body := st.scimPush(t, scimB.Token, http.MethodGet, "/Users?filter="+url.QueryEscape(`userName eq "`+dan+`"`), nil); code != http.StatusOK ||
		strings.Contains(string(body), danID) {
		t.Fatalf("tenant B's SCIM listing of tenant A's engineer = %d: %s", code, body)
	}
	if code, body := st.scimPush(t, scimB.Token, http.MethodPatch, "/Users/"+danID, map[string]any{
		"schemas":    []string{scimPatchOp},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}); code != http.StatusNotFound {
		t.Fatalf("tenant B's IdP deactivating tenant A's engineer = %d, want 404: %s", code, body)
	}
	st.mustCLI(t, bobTok, nil, "abac", "create", "--body",
		`{"name":"globex engineering freeze","effect":"deny","permission":"test.write","subject":{"department":"engineering"},"priority":10,"enabled":true}`)
	if code, body := danS.do(t, st, http.MethodPost, "/v1/tests", newTest("dan-after-b-policy")); code != http.StatusCreated {
		t.Fatalf("tenant A's engineer after tenant B's policy = %d, want 201: %s", code, body)
	}
	if me := danS.me(t, st); me.TenantID != A {
		t.Fatalf("tenant A's engineer = %+v, still want tenant A", me)
	}
}

const scimPatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// scimPush is the IdP's provisioning side: SCIM 2.0 over HTTPS with the
// tenant's bearer token.
func (st *ssoStack) scimPush(t *testing.T, token, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, st.baseURL+"/scim/v2"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := st.client.Do(req)
	if err != nil {
		t.Fatalf("SCIM %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out
}

// scimProvision is the IdP creating a person with their department.
func (st *ssoStack) scimProvision(t *testing.T, token, email, department string) string {
	t.Helper()
	code, body := st.scimPush(t, token, http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"userName": email,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   true,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]string{"department": department},
	})
	if code != http.StatusCreated {
		t.Fatalf("IdP provisions %s = %d: %s", email, code, body)
	}
	var out struct{ ID string }
	fcJSON(t, body, &out)
	return out.ID
}

type scimGroupView struct {
	ID      string `json:"id"`
	Members []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (g scimGroupView) members() []string {
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, m.Value)
	}
	return out
}

// scimGroup is the IdP's lookup of a group by display name before it binds
// members.
func (st *ssoStack) scimGroup(t *testing.T, token, name string) scimGroupView {
	t.Helper()
	code, body := st.scimPush(t, token, http.MethodGet, "/Groups?filter="+url.QueryEscape(`displayName eq "`+name+`"`), nil)
	if code != http.StatusOK {
		t.Fatalf("IdP looks up group %q = %d: %s", name, code, body)
	}
	var list struct {
		Resources []scimGroupView `json:"Resources"`
	}
	fcJSON(t, body, &list)
	if len(list.Resources) != 1 {
		t.Fatalf("IdP lookup of group %q found %d groups: %s", name, len(list.Resources), body)
	}
	return list.Resources[0]
}

// auditCount counts a tenant's audit events of one action.
func (st *ssoStack) auditCount(t *testing.T, tenant, action string) int {
	t.Helper()
	var n int
	if err := st.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, tenant, action).Scan(&n); err != nil {
		t.Fatalf("count %s in tenant %s: %v", action, tenant, err)
	}
	return n
}
