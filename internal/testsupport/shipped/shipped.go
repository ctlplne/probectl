// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package shipped boots the shipped control plane and agents — the binaries
// built from this tree — on the dev stack the way a production deployment
// runs them, for real-stack receipts that must exercise the production wiring
// end to end: the bus lane supervisor, the silo router and provisioner, the
// OTLP receivers, the provider plane, the least-privilege serve login. It is a
// test harness: nothing in it is linked into a product binary.
package shipped

import (
	"bytes"
	"context"
	"encoding/base32"
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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// ReaderUser is the ClickHouse user every telemetry plane's setting-scoped
// row policy is installed on (PROBECTL_*_READER_USER): with tenant scoping on,
// the control plane refuses to start without one.
const ReaderUser = "probectl_it_reader"

// Dex is the real OIDC IdP scripts/ci_dex.sh starts (PROBECTL_TEST_DEX_*).
type Dex struct {
	Issuer, CAFile, CertFile, ClientID, Secret, Redirect, Password string
}

// Options configures one stack.
type Options struct {
	// Name labels the stack's database, login role and logs.
	Name string
	// TenantBand is the MSP license's tenant band, the seeded default tenant
	// included.
	TenantBand int
	// Env adds to or overrides the serve environment.
	Env map[string]string
}

// Stack is one running shipped control plane.
type Stack struct {
	Root, Dir      string
	Control, Agent string // the built binaries
	BaseURL        string // https://localhost:<the IdP's registered callback port>
	CAFile         string // the CA behind every control-plane listener
	ServerCert     string // the listeners' leaf certificate
	AgentAddr      string // the agent gRPC/mTLS listener
	OTLPURL        string // the OTLP/HTTP listener
	ObjectDir      string // the filesystem object store
	AdminDSN       string // the privileged DSN of this stack's database
	BootstrapToken string // PROBECTL_PROVIDER_BOOTSTRAP_TOKEN
	Dex            Dex
	Log            string // the control plane's log file
	serveRole      string // the least-privilege serve login
	env            []string
	client         *http.Client
}

// Start builds the binaries, provisions a fresh database with a
// least-privilege serve login (TEN-01: probectl_app, and probectl_provider
// assume-only), migrates it with the privileged login, signs an MSP license
// the binary trusts, and serves on the dev stack's Kafka, ClickHouse (every
// plane, DB-level tenant scoping on) and Prometheus, behind TLS, with the real
// IdP as the deployment IdP.
func Start(t *testing.T, o Options) *Stack {
	t.Helper()
	dex := Dex{
		Issuer: os.Getenv("PROBECTL_TEST_DEX_ISSUER"), CAFile: os.Getenv("PROBECTL_TEST_DEX_CA_FILE"),
		CertFile: os.Getenv("PROBECTL_TEST_DEX_CERT_FILE"), ClientID: os.Getenv("PROBECTL_TEST_DEX_CLIENT_ID"),
		Secret: os.Getenv("PROBECTL_TEST_DEX_CLIENT_SECRET"), Redirect: os.Getenv("PROBECTL_TEST_DEX_REDIRECT_URL"),
		Password: os.Getenv("PROBECTL_TEST_DEX_PASSWORD"),
	}
	if dex.Issuer == "" || dex.Secret == "" || dex.Redirect == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_DEX_* not set — start the real IdP with scripts/ci_dex.sh (CI does) and export its env")
	}
	brokers := testsupport.KafkaBrokers()
	chURL := firstEnv("PROBECTL_TEST_CLICKHOUSE_URL", "PROBECTL_FLOWSTORE_URL")
	promURL := os.Getenv("PROBECTL_PROM_URL")
	if len(brokers) == 0 || chURL == "" || promURL == "" {
		testsupport.SkipOrFatal(t, "the shipped stack needs Kafka, ClickHouse and Prometheus (PROBECTL_TEST_KAFKA, PROBECTL_TEST_CLICKHOUSE_URL, PROBECTL_PROM_URL)")
	}
	redirect, err := url.Parse(dex.Redirect)
	if err != nil || redirect.Port() == "" {
		t.Fatalf("PROBECTL_TEST_DEX_REDIRECT_URL %q must name the listener's port", dex.Redirect)
	}

	s := &Stack{Root: repoRoot(t), Dir: t.TempDir(), Dex: dex}
	name := strings.ToLower(o.Name) + "_" + fmt.Sprint(time.Now().UnixNano())

	// The license and the binary that trusts its key, as a release bakes it.
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	s.Control = filepath.Join(s.Dir, "probectl-control")
	s.Agent = filepath.Join(s.Dir, "probectl-agent")
	s.build(t, s.Control, "./cmd/probectl-control",
		"-X github.com/ctlplne/probectl/internal/license.builtinPubKeysB64="+base64.StdEncoding.EncodeToString(pub))
	s.build(t, s.Agent, "./cmd/probectl-agent", "")
	now := time.Now()
	raw, err := license.Sign(license.Claims{
		V: 1, ID: "lic_" + name, Customer: "probectl " + o.Name + " receipt", Tier: license.TierMSP,
		TenantBand: o.TenantBand, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(90 * 24 * time.Hour),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	licenseFile := s.write(t, "license.json", raw, 0o600)

	// A fresh database, migrated by the privileged login, served by a
	// least-privilege one.
	var runtimeDSN string
	s.AdminDSN, runtimeDSN, s.serveRole = freshDatabase(t, "probectl_"+name)

	tlsDir := filepath.Join(s.Dir, "tls")
	s.run(t, nil, s.Control, "gen-cert", tlsDir)
	s.CAFile, s.ServerCert = filepath.Join(tlsDir, "ca.crt"), filepath.Join(tlsDir, "tls.crt")
	if s.client, err = crypto.HardenedHTTPClientWithCAFile(30*time.Second, s.CAFile); err != nil {
		t.Fatal(err)
	}
	s.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ensureCHReader(t, chURL)

	irDir, wormDir := s.mkdir(t, "ir"), s.mkdir(t, "worm")
	s.ObjectDir = s.mkdir(t, "objects")
	s.AgentAddr, s.OTLPURL = freeAddr(t), "https://"+freeAddr(t)
	s.BootstrapToken = hex.EncodeToString(random(t))
	env := map[string]string{
		"PROBECTL_DATABASE_URL":               runtimeDSN,
		"PROBECTL_MIGRATE_DATABASE_URL":       s.AdminDSN,
		"PROBECTL_HTTP_ADDR":                  "127.0.0.1:" + redirect.Port(),
		"PROBECTL_TLS_CERT_FILE":              s.ServerCert,
		"PROBECTL_TLS_KEY_FILE":               filepath.Join(tlsDir, "tls.key"),
		"PROBECTL_AUTH_MODE":                  "session",
		"PROBECTL_SESSION_HMAC_KEY":           hex.EncodeToString(random(t)),
		"PROBECTL_OIDC_ISSUER":                dex.Issuer,
		"PROBECTL_OIDC_CLIENT_ID":             dex.ClientID,
		"PROBECTL_OIDC_CLIENT_SECRET":         dex.Secret,
		"PROBECTL_OIDC_REDIRECT_URL":          dex.Redirect,
		"PROBECTL_OIDC_CA_FILE":               dex.CAFile,
		"PROBECTL_ENVELOPE_KEY":               base64.StdEncoding.EncodeToString(random(t)),
		"PROBECTL_ENVELOPE_KEY_ID":            "shipped-" + o.Name,
		"PROBECTL_LICENSE_FILE":               licenseFile,
		"PROBECTL_PROVIDER_BOOTSTRAP_TOKEN":   s.BootstrapToken,
		"PROBECTL_IR_PUBLIC_KEY_DIR":          irDir,
		"PROBECTL_AUDIT_WORM_DIR":             wormDir,
		"PROBECTL_WORM_SIGNING_KEY_FILE":      filepath.Join(wormDir, "signing-key.pem"),
		"PROBECTL_OBJECTSTORE_MODE":           "filesystem",
		"PROBECTL_OBJECTSTORE_DIR":            s.ObjectDir,
		"PROBECTL_BUS_MODE":                   "kafka",
		"PROBECTL_BUS_BROKERS":                strings.Join(brokers, ","),
		"PROBECTL_BUS_ALLOW_PLAINTEXT":        "true", // the dev stack's Kafka is plaintext
		"PROBECTL_INGEST_STRICT_TENANT_LANES": "true",
		"PROBECTL_TSDB_MODE":                  "prometheus",
		"PROBECTL_TSDB_URL":                   promURL,
		"PROBECTL_OTLP_HTTP_ADDR":             strings.TrimPrefix(s.OTLPURL, "https://"),
		"PROBECTL_OTLP_TLS_CERT_FILE":         s.ServerCert,
		"PROBECTL_OTLP_TLS_KEY_FILE":          filepath.Join(tlsDir, "tls.key"),
	}
	for _, plane := range []string{"FLOWSTORE", "PATHSTORE", "OTELSTORE", "EBPFSTORE", "ENDPOINTSTORE"} {
		env["PROBECTL_"+plane+"_MODE"] = "clickhouse"
		env["PROBECTL_"+plane+"_URL"] = chURL
		env["PROBECTL_"+plane+"_TENANT_SCOPING"] = "true"
		env["PROBECTL_"+plane+"_READER_USER"] = ReaderUser
	}
	for k, v := range o.Env {
		env[k] = v
	}
	for k, v := range env {
		s.env = append(s.env, k+"="+v)
	}

	// One-shot subcommands run without the agent listener, whose mTLS CA
	// only exists once agent-ca has exported it; serve adds it.
	s.Subcommand(t, "migrate")
	s.grantServeLogin(t)
	agentCA := filepath.Join(s.Dir, "agent-ca.crt")
	s.Subcommand(t, "agent-ca", "init", "-key-out", filepath.Join(s.Dir, "agent-ca-root.key"))
	s.Subcommand(t, "agent-ca", "export", agentCA)
	serveEnv := append(append([]string(nil), s.env...),
		"PROBECTL_AGENT_GRPC_ADDR="+s.AgentAddr,
		"PROBECTL_AGENT_TLS_CERT_FILE="+s.ServerCert,
		"PROBECTL_AGENT_TLS_KEY_FILE="+filepath.Join(tlsDir, "tls.key"),
		"PROBECTL_AGENT_TLS_CA_FILE="+agentCA)

	s.BaseURL = "https://localhost:" + redirect.Port()
	s.Log = s.start(t, "control", s.Control, []string{"serve"}, serveEnv)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		logs, _ := filepath.Glob(filepath.Join(s.Dir, "*.log"))
		for _, l := range logs {
			t.Logf("log tail (%s):\n%s", filepath.Base(l), tail(l, 40))
		}
	})
	s.await(t, "the control plane's /readyz", 90*time.Second, func() bool {
		resp, err := s.client.Get(s.BaseURL + "/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return s
}

// Subcommand runs `probectl-control <args>` in the stack's environment.
func (s *Stack) Subcommand(t *testing.T, args ...string) string {
	t.Helper()
	return s.run(t, s.env, s.Control, args...)
}

// Client trusts the control plane's CA and does not follow redirects.
func (s *Stack) Client() *http.Client { return s.client }

// TrustCerts are the leaf certificates a rendered page must trust: the
// control plane's and the IdP's.
func (s *Stack) TrustCerts() []string { return []string{s.ServerCert, s.Dex.CertFile} }

// CLI runs the shipped CLI (cmd/probectl is cli.RunWithStdin over argv and the
// environment) against the stack with env added.
func (s *Stack) CLI(env map[string]string, args ...string) (stdout, stderr string, code int) {
	full := map[string]string{"PROBECTL_API_URL": s.BaseURL, "PROBECTL_CA_FILE": s.CAFile}
	for k, v := range env {
		full[k] = v
	}
	var out, errb bytes.Buffer
	code = cli.RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return full[k] },
		strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

// MustCLI runs the CLI and decodes its JSON output into out (when non-nil).
func (s *Stack) MustCLI(t *testing.T, env map[string]string, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := s.CLI(env, args...)
	if code != 0 {
		t.Fatalf("probectl %s: exit %d: %s%s", strings.Join(args, " "), code, stderr, stdout)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(stdout), out); err != nil {
			t.Fatalf("probectl %s: decode %q: %v", strings.Join(args, " "), stdout, err)
		}
	}
}

// SecretFile writes v as JSON to an owner-only file (the CLI's --body-file),
// keeping credentials out of argv.
func (s *Stack) SecretFile(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(s.Dir, "body-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// OnboardOperator redeems the one-time provider bootstrap token, enrolls the
// operator's TOTP and logs in through the CLI, returning the provider session
// token.
func (s *Stack) OnboardOperator(t *testing.T, email string) string {
	t.Helper()
	var boot struct {
		EnrollToken string `json:"enroll_token"`
	}
	s.MustCLI(t, nil, &boot, "provider", "bootstrap", "--body-file",
		s.SecretFile(t, map[string]string{"token": s.BootstrapToken, "email": email, "name": "Operator"}))
	var start struct {
		TOTPSecret string `json:"totp_secret"`
	}
	s.MustCLI(t, nil, &start, "provider", "enroll-start", "--body-file", s.SecretFile(t, map[string]string{"token": boot.EnrollToken}))
	secret, err := base32Decode(start.TOTPSecret)
	if err != nil {
		t.Fatalf("decode the TOTP secret: %v", err)
	}
	password := "a-long-operator-password-" + hex.EncodeToString(random(t)[:8])
	s.MustCLI(t, nil, nil, "provider", "enroll-complete", "--body-file", s.SecretFile(t,
		map[string]string{"token": boot.EnrollToken, "password": password, "totp": crypto.TOTPNow(secret, time.Now())}))
	var login struct {
		Token string `json:"token"`
	}
	s.MustCLI(t, nil, &login, "provider", "login", "--body-file", s.SecretFile(t,
		map[string]string{"email": email, "password": password, "totp": crypto.TOTPNow(secret, time.Now())}))
	if login.Token == "" {
		t.Fatal("provider login returned no session token")
	}
	return login.Token
}

// SignIn grants email the admin role in tenant with the shipped
// bootstrap-admin, then signs in for real: the IdP's own form in Chromium, the
// authorization-code flow back to the control plane, and the tenant's UI with
// expect rendered. It returns the session the browser holds afterwards.
func (s *Stack) SignIn(t *testing.T, tenant, email string, expect ...string) string {
	t.Helper()
	out := s.Subcommand(t, "bootstrap-admin", "-tenant", tenant, "-email", email)
	if !strings.Contains(out, fmt.Sprintf("bound role %q to %s", "admin", email)) {
		t.Fatalf("bootstrap-admin -tenant %s -email %s:\n%s", tenant, email, out)
	}
	res := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            s.BaseURL + "/auth/login?tenant=" + tenant,
		TrustCertFiles: s.TrustCerts(), CAFile: s.CAFile,
		Expect: []string{"Password"},
		Steps: []testsupport.RenderStep{
			{Fill: "#login", Value: email},
			{Fill: "#password", Value: s.Dex.Password},
			{Click: "Login", Expect: expect},
		},
	})
	cookie := res.Cookie(auth.SessionCookie)
	if cookie == "" {
		t.Fatalf("%s's browser holds no %s cookie after signing in", email, auth.SessionCookie)
	}
	return cookie
}

// Do sends a request with the session cookie and returns the status and body.
func (s *Stack) Do(t *testing.T, cookie, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, s.BaseURL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: cookie})
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, out
}

// APIToken mints, from a browser session, the API token the CLI uses.
func (s *Stack) APIToken(t *testing.T, cookie string, scopes ...string) string {
	t.Helper()
	code, body := s.Do(t, cookie, http.MethodPost, "/v1/api-tokens", map[string]any{"name": "receipt-cli", "scopes": scopes})
	if code != http.StatusCreated {
		t.Fatalf("mint an API token = %d: %s", code, body)
	}
	var out struct{ Token string }
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		t.Fatalf("API token response %s: %v", body, err)
	}
	return out.Token
}

// EnrollAgent mints a one-time join token for a new agent of tenant with the
// shipped enroll-token and redeems it with the shipped agent, returning the
// agent id and the directory holding its tenant-bound identity.
func (s *Stack) EnrollAgent(t *testing.T, tenant, agentID, name string) string {
	t.Helper()
	out := s.Subcommand(t, "enroll-token", "-tenant", tenant, "-agent", agentID, "-name", name, "-ttl", "10m")
	token := ""
	for _, line := range strings.Split(out, "\n") {
		if candidate := strings.TrimSpace(line); strings.HasPrefix(candidate, "pjt_") {
			token = candidate
		}
	}
	if token == "" {
		t.Fatalf("enroll-token printed no pjt_ token:\n%s", out)
	}
	dir := filepath.Join(s.Dir, "agent-"+name)
	enrolled := s.run(t, nil, s.Agent, "enroll", "--server", s.BaseURL, "--token", token,
		"--dir", dir, "--ca-file", s.CAFile, "--hostname", name)
	if want := crypto.AgentSPIFFEID(tenant, agentID); !strings.Contains(enrolled, want) {
		t.Fatalf("agent enrollment did not return the tenant-bound identity %s:\n%s", want, enrolled)
	}
	return dir
}

// StartAgent runs the shipped agent, with its compiled-in capabilities and
// config (YAML appended to the control-plane, mTLS, identity and buffer
// stanzas for the enrolled identity).
func (s *Stack) StartAgent(t *testing.T, identityDir, name string, capabilities []string, config string) string {
	t.Helper()
	full := fmt.Sprintf(`apiVersion: probectl.io/agent/v1
control_plane:
  grpc_addr: %q
tls:
  cert_file: %q
  key_file: %q
  ca_file: %q
  server_name: "localhost"
agent:
  hostname: %q
  capabilities: [%s]
  heartbeat_interval: 1s
buffer:
  dir: %q
  max_records: 100
  drain_pace: 100ms
%s`, s.AgentAddr, filepath.Join(identityDir, "cert.pem"), filepath.Join(identityDir, "key.pem"), s.CAFile,
		name, strings.Join(capabilities, ", "), filepath.Join(s.Dir, "buffer-"+name), config)
	cfg := s.write(t, "agent-"+name+".yaml", []byte(full), 0o600)
	// Each agent's metrics listener gets its own port (the default is shared).
	return s.start(t, "agent-"+name, s.Agent, []string{"-config", cfg},
		[]string{"PROBECTL_AGENT_METRICS_ADDR=" + freeAddr(t)})
}

func (s *Stack) await(t *testing.T, what string, within time.Duration, fn func() bool) {
	t.Helper()
	Await(t, what, within, fn)
}

// Await polls fn until it holds or the deadline passes.
func Await(t *testing.T, what string, within time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", within, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (s *Stack) build(t *testing.T, out, pkg, ldflags string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, "-ldflags", ldflags, pkg)
	cmd.Dir = s.Root
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, raw)
	}
}

func (s *Stack) run(t *testing.T, env []string, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = s.Dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), redact(args), err, out)
	}
	return string(out)
}

func (s *Stack) start(t *testing.T, label, bin string, args, env []string) string {
	t.Helper()
	logPath := filepath.Join(s.Dir, label+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Dir = s.Dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", label, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = logFile.Close()
	})
	return logPath
}

func (s *Stack) write(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(s.Dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *Stack) mkdir(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(s.Dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// freshDatabase creates a database on the dev stack's PostgreSQL and a
// least-privilege login for it, both dropped afterwards. It returns the
// privileged DSN (migrations, silo DDL), the serve login's DSN and its role.
func freshDatabase(t *testing.T, name string) (admin, runtime, role string) {
	t.Helper()
	ctx := context.Background()
	base, err := url.Parse(testsupport.PostgresDSN())
	if err != nil || base.Scheme == "" {
		t.Fatalf("PROBECTL_DATABASE_URL must be a postgres:// URL: %v", err)
	}
	server := *base
	server.Path = "/postgres"
	pool, err := pgxpool.New(ctx, server.String())
	if err != nil {
		testsupport.SkipOrFatal(t, "open postgres: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	db := pgx.Identifier{name}.Sanitize()
	role = name + "_rt"
	quotedRole := pgx.Identifier{role}.Sanitize()
	password := hex.EncodeToString(random(t))
	if _, err := pool.Exec(ctx, `CREATE DATABASE `+db); err != nil {
		pool.Close()
		t.Fatalf("create the receipt's database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`)
		_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+quotedRole)
		pool.Close()
	})
	adminURL := *base
	adminURL.Path = "/" + name
	// The serve login as deploy/compose/provision-app-login.sql makes it; its
	// two roles are granted once the migrations have created them.
	if _, err := pool.Exec(ctx, `CREATE ROLE `+quotedRole+` LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD '`+password+`'`); err != nil {
		t.Fatalf("create the serve login: %v", err)
	}
	runtimeURL := adminURL
	runtimeURL.User = url.UserPassword(role, password)
	return adminURL.String(), runtimeURL.String(), role
}

// grantServeLogin grants the serve login probectl_app and probectl_provider
// assume-only, exactly as provision-app-login.sql does.
func (s *Stack) grantServeLogin(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, s.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	role := pgx.Identifier{s.serveRole}.Sanitize()
	for _, stmt := range []string{
		`GRANT probectl_app TO ` + role,
		`GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func base32Decode(secret string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
}

func ensureCHReader(t *testing.T, chURL string) {
	t.Helper()
	q := `CREATE USER IF NOT EXISTS ` + ReaderUser + ` IDENTIFIED WITH sha256_password BY '` + hex.EncodeToString(random(t)) + `'`
	if _, err := CHQuery(chURL, q); err != nil {
		t.Fatalf("ensure the ClickHouse reader user: %v", err)
	}
}

// CHQuery runs one statement against ClickHouse over HTTP and returns the
// response body.
func CHQuery(chURL, query string) (string, error) {
	u, err := url.Parse(chURL)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, u.Scheme+"://"+u.Host+"/", strings.NewReader(query))
	if err != nil {
		return "", err
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), pw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}
	return string(body), nil
}

// CHURL is the dev stack's ClickHouse the stack's planes use.
func CHURL() string { return firstEnv("PROBECTL_TEST_CLICKHOUSE_URL", "PROBECTL_FLOWSTORE_URL") }

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if raw, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && bytes.Contains(raw, []byte("module github.com/ctlplne/probectl\n")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("the probectl module root is not above the test's directory")
		}
		dir = parent
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func random(t *testing.T) []byte {
	t.Helper()
	b, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func redact(args []string) string {
	out := append([]string(nil), args...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--token" || out[i] == "-token" {
			out[i+1] = "[redacted]"
		}
	}
	return strings.Join(out, " ")
}

func tail(path string, lines int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}
