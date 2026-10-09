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
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestSSOWithARealIdPRealStack is the real-stack receipt for F22 (SSO and role
// model): a real OIDC identity provider, the complete session and role flow,
// the CLI and rendered-UI paths, and the two-tenant outcome.
//
// The IdP is Dex — the self-hosted reference IdP of
// docs/auth/self-hosted-idp.md, started by scripts/ci_dex.sh under a throwaway
// CA — as the deployment IdP, configured through config.Load with its private
// CA in PROBECTL_OIDC_CA_FILE. The control plane is the production constructor
// over PostgreSQL behind a TLS listener at the redirect URL registered with
// Dex. People sign in for real: Chromium runs the authorization-code flow
// (PKCE S256, nonce) through Dex's own login form, and the session the browser
// holds afterwards is the one the API legs use. Each tenant's first
// administrator is granted by the shipped `probectl-control bootstrap-admin`;
// everything else goes through /v1 and the shipped CLI.
//
//  1. Each bootstrap admin signs in through Dex and lands in their own tenant's
//     UI with an admin session, which mints the API token the CLI uses.
//  2. Roles: the admin pre-provisions a viewer through the CLI; the viewer signs
//     in holding exactly the viewer permissions; a grant and a revoke through
//     the CLI change the LIVE session's permissions on its next request.
//  3. Two tenants: an identity provisioned in one tenant is refused by the
//     other (no just-in-time join through the shared deployment IdP), an
//     unprovisioned identity is refused everywhere, each directory holds only
//     its own people, and a session never reads the other tenant.
//  4. A tenant-configured IdP is tenant input: tenant B pointing its own IdP at
//     the private-address Dex makes B's login fail closed (SSRF guard) while A
//     keeps signing in; disabling it restores the deployment IdP for B.
func TestSSOWithARealIdPRealStack(t *testing.T) {
	st := newSSOStack(t)
	A, B := st.tenantA, st.tenantB
	const adaEmail, aliceEmail, bobEmail, malloryEmail = "ada@acme.example", "alice@acme.example", "bob@globex.example", "mallory@outside.example"

	// 1. The first administrators, through the shipped binary and the real IdP.
	st.bootstrapAdmin(t, A, adaEmail)
	st.bootstrapAdmin(t, B, bobEmail)
	ada := st.signIn(t, A, adaEmail, "sso-acme")
	bob := st.signIn(t, B, bobEmail, "sso-globex")
	if me := ada.me(t, st); me.TenantID != A || me.Email != adaEmail || !slices.Contains(me.Permissions, "directory.write") {
		t.Fatalf("ada's session = %+v, want tenant A with the admin role", me)
	}
	if me := bob.me(t, st); me.TenantID != B || me.Email != bobEmail || !slices.Contains(me.Permissions, "directory.write") {
		t.Fatalf("bob's session = %+v, want tenant B with the admin role", me)
	}
	adaToken, bobToken := ada.apiToken(t, st), bob.apiToken(t, st)

	var cliMe ssoMe
	st.mustCLI(t, adaToken, &cliMe, "me", "show")
	if cliMe.TenantID != A || cliMe.Email != adaEmail {
		t.Fatalf("probectl me show = %+v, want ada in tenant A", cliMe)
	}
	var settings tenantIDPResponse
	st.mustCLI(t, adaToken, &settings, "identity", "settings")
	if settings.Source != "environment" || settings.Issuer != st.dex.issuer || !settings.Valid {
		t.Fatalf("probectl identity settings = %+v, want the valid deployment IdP %s", settings, st.dex.issuer)
	}

	// 2. Roles: a viewer provisioned through the CLI, then live grant and revoke.
	var alicePerson struct {
		ID string `json:"id"`
	}
	st.mustCLI(t, adaToken, &alicePerson, "directory", "create-user", "--body", fmt.Sprintf(`{"email":%q,"role":"viewer"}`, aliceEmail))
	alice := st.signIn(t, A, aliceEmail, "sso-acme")
	viewer := alice.me(t, st)
	if viewer.TenantID != A || !slices.Contains(viewer.Permissions, "test.read") ||
		slices.Contains(viewer.Permissions, "test.write") || slices.Contains(viewer.Permissions, "directory.write") {
		t.Fatalf("alice's session = %+v, want tenant A with exactly the viewer role", viewer)
	}
	if code, body := alice.do(t, st, http.MethodPost, "/v1/directory/users", map[string]string{"email": "eve@acme.example"}); code != http.StatusForbidden {
		t.Fatalf("a viewer creating a person = %d, want 403: %s", code, body)
	}
	st.mustCLI(t, adaToken, nil, "directory", "grant", alicePerson.ID, "--body", `{"role":"editor"}`)
	if me := alice.me(t, st); !slices.Contains(me.Permissions, "test.write") {
		t.Fatalf("after the editor grant alice's live session still lacks test.write: %v", me.Permissions)
	}
	st.mustCLI(t, adaToken, nil, "directory", "revoke", alicePerson.ID, "editor")
	if me := alice.me(t, st); !slices.Equal(me.Permissions, viewer.Permissions) {
		t.Fatalf("after the revoke alice's live session holds %v, want the viewer set %v", me.Permissions, viewer.Permissions)
	}

	// 3. Two tenants.
	st.signInRefused(t, B, aliceEmail)
	st.signInRefused(t, A, malloryEmail)
	st.signInRefused(t, B, malloryEmail)
	if people := st.directory(t, adaToken); !people[adaEmail] || !people[aliceEmail] || people[bobEmail] {
		t.Fatalf("tenant A's directory = %v, want ada and alice and nobody from tenant B", people)
	}
	if people := st.directory(t, bobToken); !people[bobEmail] || people[adaEmail] || people[aliceEmail] {
		t.Fatalf("tenant B's directory = %v, want bob and nobody from tenant A", people)
	}
	if code, body := ada.doHeader(t, st, http.MethodGet, "/v1/me", map[string]string{"X-Probectl-Tenant": B}); code == http.StatusOK &&
		strings.Contains(string(body), B) {
		t.Fatalf("ada's session naming tenant B in a header read tenant B: %s", body)
	}

	// 4. Tenant B points its own IdP at the private-address Dex.
	tenantIDP := func(enabled bool) string {
		raw, err := json.Marshal(map[string]any{
			"issuer": st.dex.issuer, "client_id": st.dex.clientID, "client_secret": st.dex.secret,
			"redirect_url": st.dex.redirect, "scopes": []string{"openid", "email", "profile"}, "enabled": enabled,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	st.mustCLI(t, bobToken, nil, "identity", "set-settings", "--body", tenantIDP(true))
	if code, body := st.loginStart(t, B); code != http.StatusServiceUnavailable || !strings.Contains(body, "tenant SSO provider is unavailable") {
		t.Fatalf("tenant B login with its own private-address IdP = %d, want 503 (SSRF guard): %s", code, body)
	}
	if code, body := st.loginStart(t, A); code != http.StatusFound {
		t.Fatalf("tenant A login on the deployment IdP = %d, want 302 to Dex: %s", code, body)
	}
	st.mustCLI(t, bobToken, nil, "identity", "set-settings", "--body", tenantIDP(false))
	if me := st.signIn(t, B, bobEmail, "sso-globex").me(t, st); me.TenantID != B {
		t.Fatalf("bob after B's own IdP was disabled = %+v, want a tenant B session", me)
	}

	// Each tenant's tamper-evident chain records its own sign-ins.
	for tenant, people := range map[string][]string{A: {adaEmail, aliceEmail}, B: {bobEmail}} {
		logins := st.loginActors(t, tenant)
		for _, person := range people {
			if !logins[person] {
				t.Errorf("tenant %s's audit chain has no auth.login for %s (has %v)", tenant, person, logins)
			}
		}
	}
}

// ssoDex is the IdP scripts/ci_dex.sh started.
type ssoDex struct{ issuer, caFile, certFile, clientID, secret, redirect, password string }

// ssoStack is the production control plane behind TLS at Dex's registered
// redirect URL, with the deployment IdP configured through config.Load.
type ssoStack struct {
	dex              ssoDex
	db               *store.DB
	baseURL          string
	caFile           string
	trustCerts       []string // the control plane's and Dex's leaf certificates, for the browser
	client           *http.Client
	binary           string
	binEnv           []string
	tenantA, tenantB string
}

func newSSOStack(t *testing.T) *ssoStack {
	t.Helper()
	dex := ssoDex{
		issuer: os.Getenv("PROBECTL_TEST_DEX_ISSUER"), caFile: os.Getenv("PROBECTL_TEST_DEX_CA_FILE"),
		certFile: os.Getenv("PROBECTL_TEST_DEX_CERT_FILE"),
		clientID: os.Getenv("PROBECTL_TEST_DEX_CLIENT_ID"), secret: os.Getenv("PROBECTL_TEST_DEX_CLIENT_SECRET"),
		redirect: os.Getenv("PROBECTL_TEST_DEX_REDIRECT_URL"), password: os.Getenv("PROBECTL_TEST_DEX_PASSWORD"),
	}
	if dex.issuer == "" || dex.caFile == "" || dex.certFile == "" || dex.secret == "" || dex.redirect == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_DEX_* not set — start the real IdP with scripts/ci_dex.sh (CI does) and export its env")
	}
	redirect, err := url.Parse(dex.redirect)
	if err != nil || redirect.Port() == "" {
		t.Fatalf("PROBECTL_TEST_DEX_REDIRECT_URL %q must name the listener's port", dex.redirect)
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "probectl-control")
	if out, err := exec.Command("go", "build", "-o", binary, filepath.Join(repoRoot, "cmd", "probectl-control")).CombinedOutput(); err != nil {
		t.Fatalf("build the shipped control binary: %v\n%s", err, out)
	}

	db := changeDB(t)
	st := &ssoStack{dex: dex, db: db, binary: binary}
	st.tenantA, st.tenantB = freshTenant(t, db, "sso-acme"), freshTenant(t, db, "sso-globex")

	// The deployment IdP and the session key go through the production loader.
	env := map[string]string{
		"PROBECTL_DATABASE_URL":       integrationDSN(),
		"PROBECTL_AUTH_MODE":          "session",
		"PROBECTL_SESSION_HMAC_KEY":   hex.EncodeToString(fcRandom(t)),
		"PROBECTL_OIDC_ISSUER":        dex.issuer,
		"PROBECTL_OIDC_CLIENT_ID":     dex.clientID,
		"PROBECTL_OIDC_CLIENT_SECRET": dex.secret,
		"PROBECTL_OIDC_REDIRECT_URL":  dex.redirect,
		"PROBECTL_OIDC_CA_FILE":       dex.caFile,
		"PROBECTL_ENVELOPE_KEY":       base64.StdEncoding.EncodeToString(fcRandom(t)),
		"PROBECTL_ENVELOPE_KEY_ID":    "sso-it",
	}
	loaded, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("load the SSO configuration: %v", err)
	}
	for k, v := range env {
		st.binEnv = append(st.binEnv, k+"="+v)
	}
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: loaded.SessionHMACKey,
		DeploymentProfile: "multi-tenant",
		EnvelopeKey:       loaded.EnvelopeKey, EnvelopeKeyID: loaded.EnvelopeKeyID,
		OIDCIssuer: loaded.OIDCIssuer, OIDCClientID: loaded.OIDCClientID, OIDCClientSecret: loaded.OIDCClientSecret,
		OIDCRedirectURL: loaded.OIDCRedirectURL, OIDCCAFile: loaded.OIDCCAFile,
	}
	// At-rest sealing of tenant secrets (a tenant IdP's client secret), installed
	// from the envelope key exactly as builders.go does.
	sealer, err := tenantcrypto.NewEnvelopeKeyringSealer(loaded.EnvelopeKeyID, loaded.EnvelopeKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	srv := New(cfg, quietLog(), db, db.Pool(), nil, nil).WithTenantStatus(NewTenantStatusCache(db.Pool(), 0))

	dir := t.TempDir()
	ca, err := crypto.GenerateCA("sso-it-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st.caFile = fcWrite(t, dir, "ca.crt", ca.CertPEM())
	certPEM, keyPEM, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := fcWrite(t, dir, "server.crt", certPEM)
	st.trustCerts = []string{serverCert, dex.certFile}
	tlsCfg, err := crypto.ServerTLSConfig(serverCert, fcWrite(t, dir, "server.key", keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+redirect.Port())
	if err != nil {
		t.Fatalf("listen at the redirect URL's port: %v", err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = hs.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = hs.Close() })
	st.baseURL = "https://localhost:" + redirect.Port()
	if st.client, err = crypto.HardenedHTTPClientWithCAFile(30*time.Second, st.caFile); err != nil {
		t.Fatal(err)
	}
	st.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return st
}

// bootstrapAdmin grants a tenant's first administrator with the shipped binary.
func (st *ssoStack) bootstrapAdmin(t *testing.T, tenant, email string) {
	t.Helper()
	cmd := exec.Command(st.binary, "bootstrap-admin", "-tenant", tenant, "-email", email)
	cmd.Env = st.binEnv
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), fmt.Sprintf("bound role %q to %s", "admin", email)) {
		t.Fatalf("probectl-control bootstrap-admin -tenant %s -email %s: %v\n%s", tenant, email, err, out)
	}
}

// signIn is a real browser login: Dex's own form, the authorization-code flow
// back to the control plane, and the tenant's UI with the person signed in. It
// returns the session the browser holds afterwards.
func (st *ssoStack) signIn(t *testing.T, tenant, email, tenantName string) *ssoUser {
	t.Helper()
	res := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.baseURL + "/auth/login?tenant=" + tenant,
		TrustCertFiles: st.trustCerts, CAFile: st.caFile,
		Expect: []string{"Password"},
		Steps: []testsupport.RenderStep{
			{Fill: "#login", Value: email},
			{Fill: "#password", Value: st.dex.password},
			{Click: "Login", Expect: []string{tenantName}},
		},
		Controls: []testsupport.RenderControl{{Role: "button", Name: "Open account menu for " + email}},
	})
	cookie := res.Cookie(auth.SessionCookie)
	if cookie == "" {
		t.Fatalf("%s's browser holds no %s cookie after signing in", email, auth.SessionCookie)
	}
	return &ssoUser{email: email, cookie: cookie}
}

// signInRefused is a real browser login the control plane must refuse:
// the identity is not provisioned in that tenant, and the shared deployment
// IdP never joins it just in time.
func (st *ssoStack) signInRefused(t *testing.T, tenant, email string) {
	t.Helper()
	res := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.baseURL + "/auth/login?tenant=" + tenant,
		TrustCertFiles: st.trustCerts, CAFile: st.caFile,
		Expect: []string{"Password"},
		Steps: []testsupport.RenderStep{
			{Fill: "#login", Value: email},
			{Fill: "#password", Value: st.dex.password},
			{Click: "Login", Expect: []string{"identity is not provisioned in this tenant"}},
		},
	})
	if res.Cookie(auth.SessionCookie) != "" {
		t.Fatalf("%s was refused by tenant %s but the browser holds a session", email, tenant)
	}
}

// loginStart begins a login without following the redirect to the IdP.
func (st *ssoStack) loginStart(t *testing.T, tenant string) (int, string) {
	t.Helper()
	resp, err := st.client.Get(st.baseURL + "/auth/login?tenant=" + tenant)
	if err != nil {
		t.Fatalf("start login for tenant %s: %v", tenant, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(body)
}

// mustCLI runs the shipped CLI against the TLS listener with an API token.
func (st *ssoStack) mustCLI(t *testing.T, token string, out any, args ...string) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_URL": st.baseURL, "PROBECTL_CA_FILE": st.caFile, "PROBECTL_API_TOKEN": token}
	var stdout, stderr bytes.Buffer
	if code := cli.RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return env[k] },
		strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("probectl %s: exit %d: %s%s", strings.Join(args, " "), code, stderr.String(), stdout.String())
	}
	if out != nil {
		fcJSON(t, stdout.Bytes(), out)
	}
}

// directory is the people a tenant admin's `probectl directory users` lists.
func (st *ssoStack) directory(t *testing.T, token string) map[string]bool {
	t.Helper()
	var out struct {
		Items []struct {
			Email string `json:"email"`
		} `json:"items"`
	}
	st.mustCLI(t, token, &out, "directory", "users")
	people := map[string]bool{}
	for _, p := range out.Items {
		people[p.Email] = true
	}
	return people
}

// loginActors is who signed in, per the tenant's own audit chain.
func (st *ssoStack) loginActors(t *testing.T, tenant string) map[string]bool {
	t.Helper()
	rows, err := st.db.Pool().Query(context.Background(),
		`SELECT actor FROM audit_events WHERE tenant_id = $1 AND action = 'auth.login'`, tenant)
	if err != nil {
		t.Fatalf("read tenant %s's audit chain: %v", tenant, err)
	}
	defer rows.Close()
	actors := map[string]bool{}
	for rows.Next() {
		var actor string
		if err := rows.Scan(&actor); err != nil {
			t.Fatal(err)
		}
		actors[actor] = true
	}
	return actors
}

// ssoUser holds the session a real browser login minted, following rotation
// the way a browser does.
type ssoUser struct {
	email  string
	cookie string
}

type ssoMe struct {
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	Permissions []string `json:"permissions"`
}

func (u *ssoUser) doHeader(t *testing.T, st *ssoStack, method, path string, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, st.baseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return u.send(t, st, req)
}

func (u *ssoUser) do(t *testing.T, st *ssoStack, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, st.baseURL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return u.send(t, st, req)
}

func (u *ssoUser) send(t *testing.T, st *ssoStack, req *http.Request) (int, []byte) {
	t.Helper()
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: u.cookie})
	resp, err := st.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" && c.MaxAge >= 0 {
			u.cookie = c.Value
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body
}

func (u *ssoUser) me(t *testing.T, st *ssoStack) ssoMe {
	t.Helper()
	code, body := u.do(t, st, http.MethodGet, "/v1/me", nil)
	if code != http.StatusOK {
		t.Fatalf("%s GET /v1/me = %d: %s", u.email, code, body)
	}
	var me ssoMe
	fcJSON(t, body, &me)
	return me
}

// apiToken mints, from the browser-minted session, the API token the CLI uses.
func (u *ssoUser) apiToken(t *testing.T, st *ssoStack) string {
	t.Helper()
	code, body := u.do(t, st, http.MethodPost, "/v1/api-tokens", map[string]any{"name": "sso-cli",
		"scopes": []string{"tenant.read", "directory.read", "directory.write"}})
	if code != http.StatusCreated {
		t.Fatalf("%s mints an API token = %d: %s", u.email, code, body)
	}
	var out struct{ Token string }
	fcJSON(t, body, &out)
	return out.Token
}
