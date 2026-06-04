package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRefParsingAndLiterals(t *testing.T) {
	cases := map[string]Ref{
		"vault:kv/netops/snmp#community": {Scheme: "vault", Path: "kv/netops/snmp", Field: "community"},
		"env:SNMP_COMMUNITY":             {Scheme: "env", Path: "SNMP_COMMUNITY"},
		"cyberark:Safe=NetOps;Object=o1": {Scheme: "cyberark", Path: "Safe=NetOps;Object=o1"},
		"aws:prod/cmdb#password":         {Scheme: "aws", Path: "prod/cmdb", Field: "password"},
		"azure:ops-kv/cmdb-secret":       {Scheme: "azure", Path: "ops-kv/cmdb-secret"},
		"gcp:acme-prod/snmp/3":           {Scheme: "gcp", Path: "acme-prod/snmp/3"},
	}
	for raw, want := range cases {
		if !IsRef(raw) {
			t.Fatalf("IsRef(%q) = false", raw)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("Parse(%q) = %+v, want %+v", raw, got, want)
		}
	}
	for _, lit := range []string{"hunter2", "user:password", "literal:vault:not-a-ref", "https://x", ""} {
		if IsRef(lit) {
			t.Fatalf("IsRef(%q) = true for a literal", lit)
		}
	}
	// Redaction hides the fragment.
	r, _ := Parse("vault:kv/x#password")
	if got := r.Redacted(); strings.Contains(got, "password") {
		t.Fatalf("Redacted leaked the field: %s", got)
	}
}

func TestResolverLiteralEnvAndFailClosed(t *testing.T) {
	res, err := NewResolver(time.Minute, NewEnvSource(func(k string) string {
		if k == "SNMP" {
			return "c0mmun1ty"
		}
		return ""
	}))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := res.Resolve(ctxT(t), "plain-value"); v != "plain-value" {
		t.Fatalf("literal = %q", v)
	}
	if v, _ := res.Resolve(ctxT(t), "literal:vault:looks-like-ref"); v != "vault:looks-like-ref" {
		t.Fatalf("escaped literal = %q", v)
	}
	if v, err := res.Resolve(ctxT(t), "env:SNMP"); err != nil || v != "c0mmun1ty" {
		t.Fatalf("env = %q err=%v", v, err)
	}
	// Fail closed: unset env, unconfigured backend.
	if _, err := res.Resolve(ctxT(t), "env:MISSING"); err == nil {
		t.Fatal("missing env resolved")
	}
	if _, err := res.Resolve(ctxT(t), "vault:kv/x#f"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unconfigured backend: %v", err)
	}
}

// countingSource counts fetches and can be told to fail.
type countingSource struct {
	calls int
	fail  bool
	value string
}

func (c *countingSource) Scheme() string { return "vault" }
func (c *countingSource) Fetch(context.Context, Ref) (string, error) {
	c.calls++
	if c.fail {
		return "", fmt.Errorf("%w: dial tcp: refused", ErrUnavailable)
	}
	return c.value, nil
}

func TestLeaseCacheSealedAndFailClosedOnRotation(t *testing.T) {
	src := &countingSource{value: "s3cr3t-A"}
	res, err := NewResolver(time.Minute, src)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	res.clock = func() time.Time { return now }

	ref := "vault:kv/netops#community"
	for i := 0; i < 3; i++ {
		if v, err := res.Resolve(ctxT(t), ref); err != nil || v != "s3cr3t-A" {
			t.Fatalf("resolve %d: %q %v", i, v, err)
		}
	}
	if src.calls != 1 {
		t.Fatalf("calls = %d, want 1 (lease cache)", src.calls)
	}

	// NO PLAINTEXT AT REST: the cached bytes never contain the secret.
	res.mu.Lock()
	for _, e := range res.cache {
		if bytes.Contains(e.sealed, []byte("s3cr3t-A")) {
			res.mu.Unlock()
			t.Fatal("plaintext secret found in the resolver cache")
		}
	}
	res.mu.Unlock()

	// Lease expiry -> re-resolve (rotation picked up).
	src.value = "s3cr3t-B"
	now = now.Add(2 * time.Minute)
	if v, _ := res.Resolve(ctxT(t), ref); v != "s3cr3t-B" {
		t.Fatalf("post-lease value = %q", v)
	}
	if src.calls != 2 {
		t.Fatalf("calls = %d, want 2", src.calls)
	}

	// Backend down after expiry: FAIL CLOSED — no stale credential reuse.
	src.fail = true
	now = now.Add(2 * time.Minute)
	if _, err := res.Resolve(ctxT(t), ref); err == nil {
		t.Fatal("stale credential served while backend down")
	}

	// Health: counters present, secret material absent, error redacted-safe.
	var health string
	for _, h := range res.Health() {
		b, _ := json.Marshal(h)
		health += string(b)
	}
	if strings.Contains(health, "s3cr3t") {
		t.Fatalf("health leaked secret material: %s", health)
	}
	if !strings.Contains(health, `"failures":1`) || !strings.Contains(health, `"resolves":2`) {
		t.Fatalf("health counters wrong: %s", health)
	}
}

func TestVaultKV2AndAppRole(t *testing.T) {
	var loginCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPost:
			loginCalls++
			fmt.Fprint(w, `{"auth":{"client_token":"approle-tok","lease_duration":600}}`)
		case r.URL.Path == "/v1/kv/data/netops/snmp":
			if r.Header.Get("X-Vault-Token") != "approle-tok" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if r.Header.Get("X-Vault-Namespace") != "team-a" {
				http.Error(w, "wrong ns", 400)
				return
			}
			fmt.Fprint(w, `{"data":{"data":{"community":"v4ult-c0mm","username":"ro"}}}`)
		default:
			http.Error(w, "nope", 404)
		}
	}))
	defer ts.Close()

	env := map[string]string{
		"PROBECTL_SECRETS_VAULT_ADDR":      ts.URL,
		"PROBECTL_SECRETS_VAULT_ROLE_ID":   "rid",
		"PROBECTL_SECRETS_VAULT_SECRET_ID": "sid",
		"PROBECTL_SECRETS_VAULT_NAMESPACE": "team-a",
	}
	v := NewVaultSource(func(k string) string { return env[k] })
	if v == nil {
		t.Fatal("vault source not built")
	}
	got, err := v.Fetch(ctxT(t), Ref{Scheme: "vault", Path: "kv/netops/snmp", Field: "community"})
	if err != nil || got != "v4ult-c0mm" {
		t.Fatalf("fetch = %q err=%v", got, err)
	}
	// Token reused inside its lease.
	if _, err := v.Fetch(ctxT(t), Ref{Scheme: "vault", Path: "kv/netops/snmp", Field: "username"}); err != nil {
		t.Fatal(err)
	}
	if loginCalls != 1 {
		t.Fatalf("approle logins = %d, want 1", loginCalls)
	}
	// Missing field fails closed.
	if _, err := v.Fetch(ctxT(t), Ref{Scheme: "vault", Path: "kv/netops/snmp", Field: "absent"}); err == nil {
		t.Fatal("absent field resolved")
	}
}

func TestCyberArkCCP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/AIMWebService/api/Accounts") {
			http.Error(w, "nope", 404)
			return
		}
		q := r.URL.Query()
		if q.Get("AppID") != "probectl" || q.Get("Query") != "Safe=NetOps;Object=snmp-core" {
			http.Error(w, "bad query", 400)
			return
		}
		fmt.Fprint(w, `{"Content":"ccp-s3cret","UserName":"svc-snmp"}`)
	}))
	defer ts.Close()

	env := map[string]string{
		"PROBECTL_SECRETS_CYBERARK_URL":    ts.URL,
		"PROBECTL_SECRETS_CYBERARK_APP_ID": "probectl",
	}
	ca, err := NewCyberArkSource(func(k string) string { return env[k] })
	if err != nil || ca == nil {
		t.Fatalf("source: %v", err)
	}
	got, err := ca.Fetch(ctxT(t), Ref{Scheme: "cyberark", Path: "Safe=NetOps;Object=snmp-core"})
	if err != nil || got != "ccp-s3cret" {
		t.Fatalf("content = %q err=%v", got, err)
	}
	user, err := ca.Fetch(ctxT(t), Ref{Scheme: "cyberark", Path: "Safe=NetOps;Object=snmp-core", Field: "username"})
	if err != nil || user != "svc-snmp" {
		t.Fatalf("username = %q err=%v", user, err)
	}
}

func TestAWSSecretsManagerSigV4(t *testing.T) {
	var gotAuth, gotTarget, gotDate string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTarget = r.Header.Get("X-Amz-Target")
		gotDate = r.Header.Get("X-Amz-Date")
		var req struct {
			SecretID string `json:"SecretId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.SecretID != "prod/cmdb" {
			http.Error(w, "wrong id", 400)
			return
		}
		fmt.Fprint(w, `{"SecretString":"{\"username\":\"svc\",\"password\":\"aws-s3cret\"}"}`)
	}))
	defer ts.Close()

	env := map[string]string{
		"AWS_REGION": "eu-central-1", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "sk", "AWS_SESSION_TOKEN": "sess",
	}
	a := NewAWSSource(func(k string) string { return env[k] })
	if a == nil {
		t.Fatal("aws source not built")
	}
	a.endpoint = ts.URL
	a.now = func() time.Time { return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC) }

	got, err := a.Fetch(ctxT(t), Ref{Scheme: "aws", Path: "prod/cmdb", Field: "password"})
	if err != nil || got != "aws-s3cret" {
		t.Fatalf("fetch = %q err=%v", got, err)
	}
	if gotTarget != "secretsmanager.GetSecretValue" || gotDate != "20260604T120000Z" {
		t.Fatalf("headers: target=%q date=%q", gotTarget, gotDate)
	}
	// The SigV4 envelope is well-formed: algorithm, scoped credential, the
	// session token in the signed-header list, and a 64-hex signature.
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260604/eu-central-1/secretsmanager/aws4_request, ") {
		t.Fatalf("auth = %q", gotAuth)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, ") {
		t.Fatalf("signed headers: %q", gotAuth)
	}
	sig := gotAuth[strings.LastIndex(gotAuth, "Signature=")+len("Signature="):]
	if len(sig) != 64 || strings.Trim(sig, "0123456789abcdef") != "" {
		t.Fatalf("signature not 64-hex: %q", sig)
	}
	// Whole-string fetch (no field).
	whole, err := a.Fetch(ctxT(t), Ref{Scheme: "aws", Path: "prod/cmdb"})
	if err != nil || !strings.Contains(whole, "aws-s3cret") {
		t.Fatalf("whole = %q err=%v", whole, err)
	}
}

func TestAzureKeyVault(t *testing.T) {
	var tokenCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "cid" {
			http.Error(w, "bad grant", 400)
			return
		}
		fmt.Fprint(w, `{"access_token":"az-tok","expires_in":3600}`)
	})
	mux.HandleFunc("/secrets/cmdb-secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer az-tok" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"value":"azure-s3cret"}`)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	env := map[string]string{"AZURE_TENANT_ID": "tid", "AZURE_CLIENT_ID": "cid", "AZURE_CLIENT_SECRET": "cs"}
	az := NewAzureSource(func(k string) string { return env[k] })
	if az == nil {
		t.Fatal("azure source not built")
	}
	az.tokenURL = ts.URL + "/token"
	az.vaultBase = ts.URL

	got, err := az.Fetch(ctxT(t), Ref{Scheme: "azure", Path: "ops-kv/cmdb-secret"})
	if err != nil || got != "azure-s3cret" {
		t.Fatalf("fetch = %q err=%v", got, err)
	}
	if _, err := az.Fetch(ctxT(t), Ref{Scheme: "azure", Path: "ops-kv/cmdb-secret"}); err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 {
		t.Fatalf("token calls = %d, want 1 (cached bearer)", tokenCalls)
	}
}

func TestGCPSecretManager(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY",
		Bytes: mustPKCS8(t, key)})
	saJSON, _ := json.Marshal(map[string]string{
		"client_email": "svc@acme-prod.iam.gserviceaccount.com",
		"private_key":  string(keyPEM),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		assertion := r.Form.Get("assertion")
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
			strings.Count(assertion, ".") != 2 {
			http.Error(w, "bad grant", 400)
			return
		}
		fmt.Fprint(w, `{"access_token":"gcp-tok","expires_in":3600}`)
	})
	mux.HandleFunc("/v1/projects/acme-prod/secrets/snmp/versions/latest:access", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-tok" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"payload":{"data":"Z2NwLXMzY3JldA=="}}`) // "gcp-s3cret"
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	g, err := NewGCPSource(
		func(k string) string {
			if k == "GOOGLE_APPLICATION_CREDENTIALS" {
				return "/sa.json"
			}
			return ""
		},
		func(string) ([]byte, error) { return saJSON, nil },
	)
	if err != nil || g == nil {
		t.Fatalf("source: %v", err)
	}
	g.tokenURL = ts.URL + "/token"
	g.apiBase = ts.URL

	got, err := g.Fetch(ctxT(t), Ref{Scheme: "gcp", Path: "acme-prod/snmp"})
	if err != nil || got != "gcp-s3cret" {
		t.Fatalf("fetch = %q err=%v", got, err)
	}
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
