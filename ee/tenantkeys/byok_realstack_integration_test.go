// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package tenantkeys_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/ee/tenantkeys"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestBYOKExternalKeyLifecycleRealStack is the real-stack receipt for F56
// (per-tenant keys / BYOK): a BYOK provider and the external-key lifecycle
// through the public keys API, CLI and rendered UI, across two tenants.
//
// The stack is the production assembly: control.New over PostgreSQL with the
// per-tenant keyring ee_attach.go installs (tenantkeys.NewDeploymentKeyring over
// the deployment master, the S41 secrets resolver from secrets.FromEnv and the
// operator's per-tenant reference fence PROBECTL_BYOK_REF_PREFIX, its key
// manager behind the license write gate), on an Enterprise license. The
// customer's secret manager is a local stand-in speaking Vault's real KV v2 and
// AppRole wire protocol over loopback, reached as through a path-normalizing
// front (a service-mesh ingress): dot segments are resolved before the lookup.
// The sealed values are alert-channel secrets: written through POST
// /v1/alerts, opened on every read.
//
//  1. Tenant A's first seal provisions a managed key; the value is stored tk1:.
//  2. BYOK through the CLI: a reference in B's namespace, one that walks into
//     it from A's (a dot segment), and one that does not resolve are refused
//     (fence, lockout guard); a resolvable one becomes the active version and
//     the managed one retires.
//  3. Continuity: values sealed before and after the switch both open.
//  4. The customer revokes (deletes the key in Vault): the BYOK-sealed value no
//     longer opens and nothing new can be sealed, while the managed-sealed one
//     still opens; restoring the key restores access at once (no cache).
//  5. Re-keying through the rendered Encryption keys card: a foreign reference
//     is refused there too; a new one of A's activates, and the old
//     reference's values still open.
//  6. Tenant B stays managed and unaffected; its admin rotates through the
//     same card; each tenant's chain and audit are its own.
//  7. Tenant A's ciphertext planted in tenant B's row does not open there.
func TestBYOKExternalKeyLifecycleRealStack(t *testing.T) {
	vault := newVaultStandIn(t)
	st := newKeysStack(t, vault)
	A, B := st.tenant(t, "byok-acme"), st.tenant(t, "byok-globex")
	ada, bob := st.admin(t, A, "ada@byok-acme.example"), st.admin(t, B, "bob@byok-globex.example")
	adaTok, bobTok := ada.apiToken(t, st), bob.apiToken(t, st)

	// 1. The first seal provisions tenant A's managed key.
	r1 := ada.createRule(t, st, "r1-managed", "secret-one")
	if got := st.storedSecret(t, A, r1); !strings.HasPrefix(got, "tk1:") {
		t.Fatalf("tenant A's channel secret is stored as %q, want a per-tenant tk1: seal", got[:min(8, len(got))])
	}
	if chain := st.chain(t, adaTok); len(chain) != 1 || chain[0].Mode != "managed" || chain[0].State != "active" {
		t.Fatalf("tenant A's chain after its first seal = %+v, want one active managed key", chain)
	}

	// 2. BYOK through the CLI, fenced to A's namespace and lockout-guarded.
	keyPath := func(tenant, name string) string { return "probectl/byok/" + tenant + "/" + name }
	ref := func(tenant, name string) string { return "vault:secret/" + keyPath(tenant, name) + "#key" }
	vault.put(keyPath(A, "kek"), randomKey(t))
	vault.put(keyPath(B, "kek"), randomKey(t))
	const refused = "byok_ref is not an allowed secret reference for this tenant"
	for _, foreign := range []string{ref(B, "kek"), ref(A, "../"+B+"/kek"), ref(A, "missing")} {
		st.refusedCLI(t, adaTok, refused, "key", "rotate", "--body", byokBody(foreign))
	}
	var v2 struct{ Version int }
	st.mustCLI(t, adaTok, &v2, "key", "rotate", "--body", byokBody(ref(A, "kek")))
	chain := st.chain(t, adaTok)
	if v2.Version != 2 || len(chain) != 2 || modeState(chain, 1) != "managed/retired" || modeState(chain, 2) != "byok/active" {
		t.Fatalf("tenant A's chain after BYOK activation = %+v (version %d), want v1 managed retired and v2 byok active", chain, v2.Version)
	}

	// 3. Values sealed under either version open.
	r2 := ada.createRule(t, st, "r2-byok", "secret-two")
	for _, id := range []string{r1, r2} {
		if code := ada.getRule(t, st, id); code != http.StatusOK {
			t.Fatalf("tenant A reading rule %s = %d, want 200 (decrypt continuity)", id, code)
		}
	}

	// 4. The customer revokes: the key is deleted in their secret manager.
	material := vault.get(keyPath(A, "kek"))
	vault.remove(keyPath(A, "kek"))
	if code := ada.getRule(t, st, r2); code == http.StatusOK {
		t.Fatal("the BYOK-sealed value still opened after the customer deleted the key")
	}
	if code := ada.getRule(t, st, r1); code != http.StatusOK {
		t.Fatalf("the managed-sealed value = %d after the BYOK revocation, want 200 (retired versions stay decrypt-only)", code)
	}
	if code, _ := ada.postRule(t, st, "r3-while-revoked", "secret-three"); code == http.StatusCreated {
		t.Fatal("a new value was sealed while the active BYOK key was revoked")
	}
	if code := bob.getRule(t, st, bob.createRule(t, st, "b1-managed", "secret-b")); code != http.StatusOK {
		t.Fatalf("tenant B's managed value = %d during tenant A's revocation, want 200", code)
	}
	vault.putRaw(keyPath(A, "kek"), material)
	if code := ada.getRule(t, st, r2); code != http.StatusOK {
		t.Fatalf("the BYOK-sealed value = %d once the customer restored the key, want 200 at once", code)
	}

	// 5. Re-key through the rendered card: the old reference's values keep
	// opening.
	vault.put(keyPath(A, "kek-2"), randomKey(t))
	const refField = `input[placeholder="vault:kv/tenants/acme#kek"]`
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:     st.baseURL + "/ui/admin",
		Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: ada.cookie}},
		Expect:  []string{"Encryption keys", "Tenant key chain", "byok", "Retired (decrypt-only)", "Active"},
		Steps: []testsupport.RenderStep{
			{Fill: refField, Value: ref(B, "kek")},
			{Click: "Activate BYOK", Expect: []string{refused}},
			{Fill: refField, Value: ref(A, "kek-2")},
			{Click: "Activate BYOK", Expect: []string{"Rotated — new data seals under v3.", "v3"}},
		},
	})
	r4 := ada.createRule(t, st, "r4-byok-2", "secret-four")
	for _, id := range []string{r1, r2, r4} {
		if code := ada.getRule(t, st, id); code != http.StatusOK {
			t.Fatalf("tenant A reading rule %s after re-keying = %d, want 200", id, code)
		}
	}
	if chain := st.chain(t, adaTok); len(chain) != 3 || modeState(chain, 2) != "byok/retired" || modeState(chain, 3) != "byok/active" {
		t.Fatalf("tenant A's chain after the console re-key = %+v, want v2 retired and v3 active (both byok)", chain)
	}

	// 6. Tenant B: its own managed chain, rotated through the same card.
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:     st.baseURL + "/ui/admin",
		Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: bob.cookie}},
		Expect:  []string{"Encryption keys", "Tenant key chain"},
		Steps:   []testsupport.RenderStep{{Click: "Rotate managed key", Expect: []string{"Rotated — new data seals under v2."}}},
	})
	if chain := st.chain(t, bobTok); len(chain) != 2 || modeState(chain, 1) != "managed/retired" || modeState(chain, 2) != "managed/active" {
		t.Fatalf("tenant B's chain after the console rotation = %+v, want v1 retired and v2 active (managed)", chain)
	}
	for tenant, want := range map[string]int{A: 2, B: 1} {
		if got := st.auditCount(t, tenant, "security.key_rotate"); got != want {
			t.Errorf("tenant %s's chain holds %d security.key_rotate events, want %d", tenant, got, want)
		}
	}

	// 7. A ciphertext lifted from tenant A and planted in tenant B's row (a
	// direct database write inside B's scope) does not open as B's — neither
	// one sealed under a version number B also holds (v1) nor one B lacks (v3).
	for _, lifted := range []string{r1, r4} {
		b := bob.createRule(t, st, "b-target-"+lifted[:8], "secret-b")
		st.plantSecret(t, B, b, st.storedSecret(t, A, lifted))
		if code := bob.getRule(t, st, b); code == http.StatusOK {
			t.Fatalf("tenant A's sealed secret %s opened as tenant B's", st.storedSecret(t, A, lifted)[:6])
		}
	}
}

// vaultStandIn speaks the real Vault wire protocol the production client uses:
// AppRole login (POST /v1/auth/approle/login) and KV v2 reads
// (GET /v1/<mount>/data/<path>, X-Vault-Token, data under .data.data). It is
// reached as through a normalizing front, which resolves dot segments before
// routing (Vault's own listener answers them with a 301 to the clean path, a
// redirect the resolver follows for a named host).
type vaultStandIn struct {
	srv      *httptest.Server
	roleID   string
	secretID string
	token    string
	mu       sync.Mutex
	kv       map[string]map[string]string
}

func newVaultStandIn(t *testing.T) *vaultStandIn {
	t.Helper()
	v := &vaultStandIn{roleID: "probectl-role", secretID: "probectl-secret-id", token: "s.issued-" + fmt.Sprint(time.Now().UnixNano()), kv: map[string]map[string]string{}}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = path.Clean(r.URL.Path)
		v.serve(w, r)
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *vaultStandIn) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
		var in struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.RoleID != v.roleID || in.SecretID != v.secretID {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":["invalid role or secret ID"]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": v.token, "lease_duration": 3600, "renewable": true}})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
		if r.Header.Get("X-Vault-Token") != v.token {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		v.mu.Lock()
		data, ok := v.kv[strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")]
		v.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errors":[]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"data":     data,
			"metadata": map[string]any{"created_time": time.Now().UTC().Format(time.RFC3339Nano), "deletion_time": "", "destroyed": false, "version": 1},
		}})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errors":[]}`)
	}
}

func (v *vaultStandIn) put(path, key string) { v.putRaw(path, map[string]string{"key": key}) }

func (v *vaultStandIn) putRaw(path string, data map[string]string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.kv[path] = data
}

func (v *vaultStandIn) get(path string) map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.kv[path]
}

func (v *vaultStandIn) remove(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.kv, path)
}

// keysStack is the production control plane with the per-tenant keyring
// installed as ee_attach.go installs it.
type keysStack struct {
	db      *store.DB
	srv     *control.Server
	baseURL string
	suffix  string
}

func newKeysStack(t *testing.T, vault *vaultStandIn) *keysStack {
	t.Helper()
	ctx := context.Background()
	dsn := testsupport.PostgresDSN()
	db, err := store.Open(ctx, dsn, 10, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// The customer's secret manager, reached through the production resolver.
	t.Setenv("PROBECTL_SECRETS_VAULT_ADDR", vault.srv.URL)
	t.Setenv("PROBECTL_SECRETS_VAULT_ROLE_ID", vault.roleID)
	t.Setenv("PROBECTL_SECRETS_VAULT_SECRET_ID", vault.secretID)
	resolver, err := secrets.FromEnv(0)
	if err != nil {
		t.Fatalf("secrets resolver: %v", err)
	}

	masterKey := base64.StdEncoding.EncodeToString(randomBytes(t))
	cfg := &config.Config{
		HSTSEnabled: true, HSTSMaxAge: time.Hour,
		AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: randomBytes(t),
		DeploymentProfile: "multi-tenant",
		EnvelopeKey:       masterKey, EnvelopeKeyID: "byok-it",
		BYOKRefPrefix: "vault:secret/probectl/byok/" + tenantkeys.TenantToken + "/",
	}
	lic := enterpriseLicense(t)

	// main installs the deployment sealer; ee_attach.go then makes the keyring
	// the primary sealer (the deployment one stays an opener).
	dv1, err := tenantcrypto.NewEnvelopeKeyringSealer(cfg.EnvelopeKeyID, cfg.EnvelopeKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(dv1)
	t.Cleanup(tenantcrypto.Reset)
	kp, err := crypto.NewStaticKeyProviderFromBase64Keyring(cfg.EnvelopeKeyID, cfg.EnvelopeKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := logging.New(io.Discard, "error", "json")
	ring, err := tenantkeys.NewDeploymentKeyring(tenantkeys.NewPGStore(db.Pool()), crypto.NewEnvelope(kp), resolver, cfg.BYOKRefPrefix, log)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(ring)

	srv := control.New(cfg, log, db, db.Pool(), nil, nil).WithLicense(lic)
	srv.WithKeyManager(tenantcrypto.GateKeyManagerWrites(tenantkeys.NewManager(ring), lic.WriteCapability()))
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &keysStack{db: db, srv: srv, baseURL: httpSrv.URL, suffix: fmt.Sprint(time.Now().UnixNano())}
}

func (st *keysStack) tenant(t *testing.T, prefix string) string {
	t.Helper()
	tn, err := store.NewTenants(st.db.Pool()).Create(context.Background(), prefix+"-"+st.suffix, prefix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

// keysUser is a tenant administrator holding a production session.
type keysUser struct {
	email  string
	cookie string
}

func (st *keysStack) admin(t *testing.T, tenant, email string) *keysUser {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	var userID string
	if err := tenancy.InTenant(ctx, st.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.Roles{}).EnsureSystemRoles(ctx, sc); err != nil {
			return err
		}
		u, err := store.Users{}.Create(ctx, sc, email, email)
		if err != nil {
			return err
		}
		userID = u.ID
		role, err := store.Roles{}.GetBySlug(ctx, sc, "admin")
		if err != nil {
			return err
		}
		return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID)
	}); err != nil {
		t.Fatalf("tenant admin %s: %v", email, err)
	}
	grants, err := st.srv.PermissionLoader().ForUser(context.Background(), tenant, userID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := st.srv.SessionManager().Issue(context.Background(), auth.Session{
		TenantID: tenant, UserID: userID, Email: email, DisplayName: email,
		AuthorizationHash: auth.PermissionGrantFingerprint(grants),
	})
	if err != nil {
		t.Fatalf("issue session for %s: %v", email, err)
	}
	return &keysUser{email: email, cookie: token}
}

func (u *keysUser) do(t *testing.T, st *keysStack, method, path string, body any) (int, []byte) {
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: u.cookie})
	resp, err := crypto.HardenedHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, out
}

func (u *keysUser) apiToken(t *testing.T, st *keysStack) string {
	t.Helper()
	code, body := u.do(t, st, http.MethodPost, "/v1/api-tokens", map[string]any{"name": "keys-cli", "scopes": []string{"security.keys", "tenant.read"}})
	if code != http.StatusCreated {
		t.Fatalf("%s mints an API token = %d: %s", u.email, code, body)
	}
	var out struct{ Token string }
	decode(t, body, &out)
	return out.Token
}

func (u *keysUser) postRule(t *testing.T, st *keysStack, name, secret string) (int, []byte) {
	t.Helper()
	return u.do(t, st, http.MethodPost, "/v1/alerts", map[string]any{
		"name": name + "-" + st.suffix, "metric": "probectl_probe_loss_ratio", "type": "threshold",
		"comparison": "gt", "threshold": 0.5, "severity": "critical",
		"channels": []map[string]any{{"type": "webhook", "url": "https://hooks/x", "secret": secret}},
	})
}

func (u *keysUser) createRule(t *testing.T, st *keysStack, name, secret string) string {
	t.Helper()
	code, body := u.postRule(t, st, name, secret)
	if code != http.StatusCreated {
		t.Fatalf("%s creates alert rule %s = %d: %s", u.email, name, code, body)
	}
	var out struct {
		ID       string `json:"id"`
		Channels []struct {
			Secret string `json:"secret"`
		} `json:"channels"`
	}
	decode(t, body, &out)
	if len(out.Channels) != 1 || out.Channels[0].Secret != "***" {
		t.Fatalf("the channel secret is not redacted in the API response: %s", body)
	}
	return out.ID
}

func (u *keysUser) getRule(t *testing.T, st *keysStack, id string) int {
	t.Helper()
	code, _ := u.do(t, st, http.MethodGet, "/v1/alerts/"+id, nil)
	return code
}

type keyVersion struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	State   string `json:"state"`
}

// chain is the tenant's key chain through `probectl key list`.
func (st *keysStack) chain(t *testing.T, token string) []keyVersion {
	t.Helper()
	var out struct{ Items []keyVersion }
	st.mustCLI(t, token, &out, "key", "list")
	return out.Items
}

func modeState(chain []keyVersion, version int) string {
	for _, k := range chain {
		if k.Version == version {
			return k.Mode + "/" + k.State
		}
	}
	return "missing"
}

func (st *keysStack) cli(t *testing.T, token string, args ...string) (string, string, int) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_URL": st.baseURL, "PROBECTL_API_TOKEN": token}
	var stdout, stderr bytes.Buffer
	code := cli.RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return env[k] },
		strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func (st *keysStack) mustCLI(t *testing.T, token string, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := st.cli(t, token, args...)
	if code != 0 {
		t.Fatalf("probectl %s: exit %d: %s%s", strings.Join(args, " "), code, stderr, stdout)
	}
	if out != nil {
		decode(t, []byte(stdout), out)
	}
}

func (st *keysStack) refusedCLI(t *testing.T, token, want string, args ...string) {
	t.Helper()
	stdout, stderr, code := st.cli(t, token, args...)
	if code == 0 || !strings.Contains(stderr, want) {
		t.Fatalf("probectl %s: exit %d, want a refusal saying %q: %s%s", strings.Join(args, " "), code, want, stderr, stdout)
	}
}

// storedSecret reads a rule's sealed channel secret as stored at rest.
func (st *keysStack) storedSecret(t *testing.T, tenant, ruleID string) string {
	t.Helper()
	var channels []struct {
		Secret string `json:"secret"`
	}
	var raw []byte
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, st.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT channels FROM alert_rules WHERE id = $1`, ruleID).Scan(&raw)
	}); err != nil {
		t.Fatalf("read rule %s: %v", ruleID, err)
	}
	decode(t, raw, &channels)
	if len(channels) != 1 {
		t.Fatalf("rule %s has %d channels", ruleID, len(channels))
	}
	return channels[0].Secret
}

// plantSecret overwrites a rule's sealed secret with a direct write inside the
// rule's own tenant scope — the attack the per-tenant binding exists for.
func (st *keysStack) plantSecret(t *testing.T, tenant, ruleID, sealed string) {
	t.Helper()
	channels, err := json.Marshal([]map[string]any{{"type": "webhook", "url": "https://hooks/x", "secret": sealed}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, st.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE alert_rules SET channels = $2 WHERE id = $1`, ruleID, channels)
		return err
	}); err != nil {
		t.Fatalf("plant a secret in rule %s: %v", ruleID, err)
	}
}

func (st *keysStack) auditCount(t *testing.T, tenant, action string) int {
	t.Helper()
	var n int
	if err := st.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`, tenant, action).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", action, err)
	}
	return n
}

func byokBody(ref string) string { return fmt.Sprintf(`{"mode":"byok","byok_ref":%q}`, ref) }

func randomBytes(t *testing.T) []byte {
	t.Helper()
	b, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randomKey(t *testing.T) string { return base64.StdEncoding.EncodeToString(randomBytes(t)) }

// enterpriseLicense is a signed Enterprise license (byok granted) trusted by
// the manager it loads into.
func enterpriseLicense(t *testing.T) *license.Manager {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_byok_it", Customer: "BYOK Receipt GmbH", Tier: license.TierEnterprise,
		IssuedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(90 * 24 * time.Hour),
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

func decode(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}
