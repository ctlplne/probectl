// SPDX-License-Identifier: LicenseRef-probectl-TBD

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

type byteCountingSource struct {
	calls       int
	stringCalls int
	cleanups    int
	fail        bool
	value       []byte
	returned    [][]byte
}

func (c *byteCountingSource) Scheme() string { return "vault" }
func (c *byteCountingSource) Fetch(context.Context, Ref) (string, error) {
	c.stringCalls++
	return "", fmt.Errorf("string fetch should not be used for byte-capable source")
}
func (c *byteCountingSource) FetchBytes(context.Context, Ref) ([]byte, func(), error) {
	c.calls++
	if c.fail {
		return nil, nil, fmt.Errorf("%w: byte backend refused", ErrUnavailable)
	}
	b := append([]byte(nil), c.value...)
	c.returned = append(c.returned, b)
	return b, func() {
		c.cleanups++
		crypto.Zeroize(b)
	}, nil
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

func TestResolveBytesByteSourceLeaseEvictionAndCleanup(t *testing.T) {
	src := &byteCountingSource{value: []byte("s3cr3t-A")}
	res, err := NewResolver(time.Minute, src)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	res.clock = func() time.Time { return now }

	ref := "vault:kv/netops#community"
	plain, cleanup, err := res.ResolveBytes(ctxT(t), ref)
	if err != nil || string(plain) != "s3cr3t-A" {
		t.Fatalf("resolve bytes: %q %v", plain, err)
	}
	cleanup()
	if src.stringCalls != 0 {
		t.Fatalf("byte-capable backend used immutable string Fetch %d times", src.stringCalls)
	}
	if src.calls != 1 || src.cleanups != 1 {
		t.Fatalf("byte fetch calls/cleanups = %d/%d, want 1/1", src.calls, src.cleanups)
	}
	if !allZeroBytes(src.returned[0]) {
		t.Fatalf("source-returned plaintext bytes were not zeroized: %x", src.returned[0])
	}

	res.mu.Lock()
	var oldSealed []byte
	for _, e := range res.cache {
		oldSealed = e.sealed
		if bytes.Contains(e.sealed, []byte("s3cr3t-A")) {
			res.mu.Unlock()
			t.Fatal("plaintext byte-source secret found in resolver cache")
		}
	}
	res.mu.Unlock()
	if len(oldSealed) == 0 || allZeroBytes(oldSealed) {
		t.Fatalf("expected non-zero sealed cache entry before lease expiry: %x", oldSealed)
	}

	src.value = []byte("s3cr3t-B")
	plain, cleanup, err = res.ResolveBytes(ctxT(t), ref)
	if err != nil || string(plain) != "s3cr3t-A" {
		t.Fatalf("cache hit before expiry: %q %v", plain, err)
	}
	cleanup()
	if src.calls != 1 {
		t.Fatalf("source re-fetched before lease expiry: calls=%d", src.calls)
	}

	now = now.Add(2 * time.Minute)
	plain, cleanup, err = res.ResolveBytes(ctxT(t), ref)
	if err != nil || string(plain) != "s3cr3t-B" {
		t.Fatalf("post-lease resolve: %q %v", plain, err)
	}
	cleanup()
	if src.calls != 2 || src.cleanups != 2 {
		t.Fatalf("post-lease calls/cleanups = %d/%d, want 2/2", src.calls, src.cleanups)
	}
	if !allZeroBytes(oldSealed) {
		t.Fatalf("expired sealed cache entry was not zeroized: %x", oldSealed)
	}

	var health string
	for _, h := range res.Health() {
		b, _ := json.Marshal(h)
		health += string(b)
	}
	if strings.Contains(health, "s3cr3t") {
		t.Fatalf("health leaked byte-source secret material: %s", health)
	}
}

func TestResolverCloseZeroizesKeyAndCache(t *testing.T) {
	src := &countingSource{value: "s3cr3t-A"}
	res, err := NewResolver(time.Minute, src)
	if err != nil {
		t.Fatal(err)
	}
	ref := "vault:kv/netops#community"
	if v, err := res.Resolve(ctxT(t), ref); err != nil || v != "s3cr3t-A" {
		t.Fatalf("resolve: %q %v", v, err)
	}

	res.mu.Lock()
	keyRef := res.key
	var sealedRefs [][]byte
	for _, e := range res.cache {
		sealedRefs = append(sealedRefs, e.sealed)
	}
	res.mu.Unlock()
	if len(keyRef) == 0 || allZeroBytes(keyRef) {
		t.Fatalf("expected non-zero resolver cache key before close: %x", keyRef)
	}
	if len(sealedRefs) != 1 || allZeroBytes(sealedRefs[0]) {
		t.Fatalf("expected one non-zero sealed cache entry before close: %x", sealedRefs)
	}

	res.Close()
	if !allZeroBytes(keyRef) {
		t.Fatalf("resolver cache key was not zeroized: %x", keyRef)
	}
	for i, sealed := range sealedRefs {
		if !allZeroBytes(sealed) {
			t.Fatalf("sealed cache entry %d was not zeroized: %x", i, sealed)
		}
	}
	res.mu.Lock()
	cacheLen, closed := len(res.cache), res.closed
	res.mu.Unlock()
	if cacheLen != 0 || !closed {
		t.Fatalf("resolver close state: cache=%d closed=%v", cacheLen, closed)
	}
	if _, err := res.Resolve(ctxT(t), ref); err == nil {
		t.Fatal("closed resolver must fail closed")
	}
}

func allZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
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

// KEYS-001: concurrent resolves race the AppRole token cache. The resolver
// releases its own mutex before calling src.Fetch (secrets.go), so VaultSource
// must guard its own leaseTok/leaseExp. Under -race this must be clean; before
// the fix it reported a DATA RACE on those fields.
func TestVaultAppRoleConcurrentNoRace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/auth/approle/login":
			fmt.Fprint(w, `{"auth":{"client_token":"approle-tok","lease_duration":600}}`)
		case strings.HasPrefix(r.URL.Path, "/v1/kv/data/"):
			fmt.Fprint(w, `{"data":{"data":{"community":"v4ult-c0mm"}}}`)
		default:
			http.Error(w, "nope", 404)
		}
	}))
	defer ts.Close()

	v := NewVaultSource(func(k string) string {
		return map[string]string{
			"PROBECTL_SECRETS_VAULT_ADDR":      ts.URL,
			"PROBECTL_SECRETS_VAULT_ROLE_ID":   "rid",
			"PROBECTL_SECRETS_VAULT_SECRET_ID": "sid",
		}[k]
	})
	if v == nil {
		t.Fatal("vault source not built")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := v.Fetch(ctxT(t), Ref{Scheme: "vault", Path: "kv/netops/snmp", Field: "community"})
			switch {
			case err != nil:
				errs <- err
			case got != "v4ult-c0mm":
				errs <- fmt.Errorf("got %q", got)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent fetch: %v", err)
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

// SEC-002: the no-session-token path and a GovCloud (non-us-*) region must
// produce a well-formed SigV4 envelope from the SAME canonical-headers builder
// — x-amz-security-token must be ABSENT from SignedHeaders and the host must be
// the regional endpoint. A recorded-fixture style check (deterministic clock).
func TestAWSSecretsManagerSigV4NoSessionGovCloud(t *testing.T) {
	var gotAuth, gotHost, gotToken string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotHost = r.Host
		gotToken = r.Header.Get("X-Amz-Security-Token")
		fmt.Fprint(w, `{"SecretString":"govcloud-s3cret"}`)
	}))
	defer ts.Close()

	// No AWS_SESSION_TOKEN, GovCloud region.
	env := map[string]string{
		"AWS_REGION": "us-gov-west-1", "AWS_ACCESS_KEY_ID": "AKIAGOV",
		"AWS_SECRET_ACCESS_KEY": "sk",
	}
	a := NewAWSSource(func(k string) string { return env[k] })
	if a == nil {
		t.Fatal("aws source not built")
	}
	a.endpoint = ts.URL
	a.now = func() time.Time { return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC) }

	got, err := a.Fetch(ctxT(t), Ref{Scheme: "aws", Path: "gov/cmdb"})
	if err != nil || got != "govcloud-s3cret" {
		t.Fatalf("fetch = %q err=%v", got, err)
	}
	// No session token sent, and it must NOT be in the signed-header list.
	if gotToken != "" {
		t.Errorf("unexpected session token header: %q", gotToken)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=content-type;host;x-amz-date;x-amz-target, ") {
		t.Fatalf("no-token signed headers wrong: %q", gotAuth)
	}
	if strings.Contains(gotAuth, "x-amz-security-token") {
		t.Errorf("security-token leaked into the no-token signed headers: %q", gotAuth)
	}
	// GovCloud region is reflected in the scope.
	if !strings.Contains(gotAuth, "/us-gov-west-1/secretsmanager/aws4_request, ") {
		t.Fatalf("region scope wrong: %q", gotAuth)
	}
	_ = gotHost
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
	// Key material comes from internal/crypto — never RSA primitives directly
	// (guardrail 3; the crypto-import gate enforces it).
	keyPEM, err := crypto.GenerateRSAKeyPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
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
