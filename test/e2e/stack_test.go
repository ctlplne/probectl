// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// containerWorkDir is where the run's work directory is mounted inside every
// control-plane container. Host paths under the work directory map to it.
const containerWorkDir = "/e2e"

// dexHost is the issuer host name: Dex's alias on the run's Docker network, a
// SAN on its certificate, and a name this test resolves to loopback itself.
const dexHost = "dex"

// releaseImage returns the probectl-control image under test. CI builds it in
// the job exactly as build-images and image-scan do and passes the tag in
// PROBECTL_E2E_IMAGE; without it the test builds the same image itself, from
// the same Dockerfile and build arguments, and never pushes it.
func releaseImage(t *testing.T, root, project string) string {
	t.Helper()
	if image := strings.TrimSpace(os.Getenv("PROBECTL_E2E_IMAGE")); image != "" {
		return image
	}
	tag := project + "/probectl-control:e2e"
	runCmd(t, root, nil, "docker", "buildx", "build", "--load",
		"-f", "deploy/docker/Dockerfile",
		"--build-arg", "COMPONENT=probectl-control",
		"--build-arg", "EDITION=core",
		"-t", tag, ".")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", tag).Run() })
	return tag
}

// controlImage runs the release image the way the shipped Compose stack runs
// it: distroless, non-root, read-only root filesystem, no capabilities, no
// privilege escalation, on the stack's own network.
type controlImage struct {
	image, network, work, project string
	seq                           int
}

// path maps a host path under the work directory to its container path.
func (c *controlImage) path(t *testing.T, hostPath string) string {
	t.Helper()
	rel, err := filepath.Rel(c.work, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("%s is outside the mounted work directory %s", hostPath, c.work)
	}
	return containerWorkDir + "/" + filepath.ToSlash(rel)
}

func (c *controlImage) baseArgs(name string, envFiles []string, extra ...string) []string {
	args := []string{"run", "--name", name,
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--read-only", "--tmpfs", "/tmp:size=16m,mode=1777",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"-v", c.work + ":" + containerWorkDir}
	for _, f := range envFiles {
		args = append(args, "--env-file", f)
	}
	return append(args, extra...)
}

// oneShot runs a probectl-control subcommand in a throwaway container and
// returns its combined output.
func (c *controlImage) oneShot(t *testing.T, network string, envFiles []string, env []string, args ...string) string {
	t.Helper()
	c.seq++
	name := fmt.Sprintf("%s-cli-%d", c.project, c.seq)
	extra := []string{"--rm", "--network", network}
	for _, kv := range env {
		extra = append(extra, "-e", kv)
	}
	full := append(c.baseArgs(name, envFiles, extra...), c.image)
	return runCmdOutput(t, c.work, nil, "docker", append(full, args...)...)
}

// serve starts `probectl-control serve` detached with the given loopback
// publishes and returns a probe that fails the test, with the container's log
// tail, once the container has stopped running.
func (c *controlImage) serve(t *testing.T, envFiles []string, publish ...string) func() {
	t.Helper()
	name := c.project + "-control"
	extra := []string{"-d", "--network", c.network}
	for _, p := range publish {
		extra = append(extra, "-p", p)
	}
	full := append(c.baseArgs(name, envFiles, extra...), c.image, "serve")
	runCmd(t, c.work, nil, "docker", full...)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("---- control container log tail ----\n%s", containerLogTail(name))
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	return func() {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", name).Output()
		if status := strings.TrimSpace(string(out)); err != nil || status != "running" {
			t.Fatalf("the control-plane container is %q (%v), not running; its log tail follows", status, err)
		}
	}
}

func containerLogTail(name string) string {
	out, _ := exec.Command("docker", "logs", "--tail", "400", name).CombinedOutput()
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, `"msg":"request"`) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// writeEnvFile writes a docker --env-file (owner-only: it holds the run's
// throwaway credentials) with the keys in a stable order.
func writeEnvFile(t *testing.T, path string, env map[string]string) string {
	t.Helper()
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if strings.ContainsAny(env[k], "\n\r") {
			t.Fatalf("env value for %s spans lines", k)
		}
		b.WriteString(k + "=" + env[k] + "\n")
	}
	writeFile(t, path, b.String())
	return path
}

// randomHex reads n bytes from the kernel's random source. The e2e module is
// stdlib-only and outside internal/crypto, so it reads /dev/urandom directly
// rather than importing a crypto primitive.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	f, err := os.Open("/dev/urandom")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

// readEnvFile parses the KEY=VALUE lines scripts/ci_dex.sh writes.
func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = v
		}
	}
	return out
}

// startDex starts the real OIDC IdP with scripts/ci_dex.sh — the same script,
// image digest and password users the integration lane signs in through — on
// the run's network, so the control-plane container reaches the issuer
// in-network while this test reaches it on 127.0.0.1:5556.
func startDex(t *testing.T, root, dir, network, container, redirect string) map[string]string {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("---- dex log tail ----\n%s", containerLogTail(container))
		}
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})
	runCmd(t, root, []string{
		"PROBECTL_TEST_DEX_CONTAINER=" + container,
		"PROBECTL_TEST_DEX_NETWORK=" + network,
		"PROBECTL_TEST_DEX_HOST=" + dexHost,
		"PROBECTL_TEST_DEX_REDIRECT_URL=" + redirect,
		"GITHUB_ENV=/dev/null", // the script's exports are for CI steps, not for this run
	}, "./scripts/ci_dex.sh", dir)
	return readEnvFile(t, filepath.Join(dir, "env"))
}

// newHTTPS returns an HTTPS client that trusts exactly the given CA files,
// resolves localhost and the Dex alias to loopback, and keeps cookies when
// jar is set.
func newHTTPS(t *testing.T, jar http.CookieJar, caFiles ...string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, f := range caFiles {
		pem, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("CA file %s contains no certificates", f)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 20 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if host == "localhost" || host == dexHost {
					addr = net.JoinHostPort("127.0.0.1", port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

var formAction = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"`)

// ssoSignIn signs email in to tenant for real, headless: the control plane's
// /auth/login, Dex's own password form, the authorization-code + PKCE
// exchange back on /auth/callback, and the session cookie that sets. It then
// mints, from that session, the tenant-bound API token every later request
// presents — the production path an operator's CLI token takes.
func ssoSignIn(t *testing.T, apiBase string, caFiles []string, tenant, email, password string, scopes []string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := newHTTPS(t, jar, caFiles...)
	resp, err := client.Get(apiBase + "/auth/login?tenant=" + url.QueryEscape(tenant))
	if err != nil {
		t.Fatalf("SSO login for %s: %v", email, err)
	}
	page := readBody(t, resp)
	match := formAction.FindSubmatch(page)
	if resp.StatusCode != http.StatusOK || match == nil || resp.Request.URL.Hostname() != dexHost {
		t.Fatalf("SSO login for %s did not reach the IdP's password form (status %d at %s):\n%.2000s",
			email, resp.StatusCode, resp.Request.URL.Redacted(), page)
	}
	action, err := resp.Request.URL.Parse(html.UnescapeString(string(match[1])))
	if err != nil {
		t.Fatalf("IdP form action %q: %v", match[1], err)
	}
	resp, err = client.PostForm(action.String(), url.Values{"login": {email}, "password": {password}})
	if err != nil {
		t.Fatalf("submit the IdP password form for %s: %v", email, err)
	}
	landing := readBody(t, resp)
	base, _ := url.Parse(apiBase)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Host != base.Host {
		t.Fatalf("SSO callback for %s did not land on the control plane (status %d at %s):\n%.2000s",
			email, resp.StatusCode, resp.Request.URL.Redacted(), landing)
	}
	if len(jar.Cookies(base)) == 0 {
		t.Fatalf("%s holds no control-plane session cookie after the SSO callback", email)
	}
	raw, err := json.Marshal(map[string]any{"name": "e2e-" + tenant, "scopes": scopes, "expires_in_hours": 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Post(apiBase+"/v1/api-tokens", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mint %s's API token: %v", email, err)
	}
	body := readBody(t, resp)
	var minted struct {
		Token string `json:"token"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(body, &minted) != nil || minted.Token == "" {
		t.Fatalf("mint %s's API token from the SSO session = %d: %s", email, resp.StatusCode, body)
	}
	return minted.Token
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatalf("read %s response: %v", resp.Request.URL.Redacted(), err)
	}
	return b
}

// api is the public REST API as one tenant's bearer token sees it.
type api struct {
	base, token string
	client      *http.Client
}

// do sends one request and returns its status and body. headers are added
// as-is; a nil body sends none.
func (a api) do(t *testing.T, method, path string, body any, headers ...string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp.StatusCode, readBody(t, resp)
}

// json sends a request that must answer want and decodes the body into out.
func (a api) json(t *testing.T, want int, method, path string, body, out any) []byte {
	t.Helper()
	code, raw := a.do(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, raw)
	}
	if !json.Valid(raw) {
		t.Fatalf("%s %s answered non-JSON: %s", method, path, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("decode %s %s: %v: %s", method, path, err, raw)
		}
	}
	return raw
}

// get is a GET that must answer 200 and returns the raw JSON body.
func (a api) get(t *testing.T, path string) string {
	t.Helper()
	return string(a.json(t, http.StatusOK, http.MethodGet, path, nil, nil))
}

// tenantObjects is what one tenant wrote through the API: the ids and the
// unique marker every one of its objects carries.
type tenantObjects struct {
	tenant, mark, testID, alertID string
}

// writeObjects creates, then updates, one synthetic test and one alert rule
// as the tenant, and reads both back by id.
func writeObjects(t *testing.T, a api, tenant, mark string) tenantObjects {
	t.Helper()
	o := tenantObjects{tenant: tenant, mark: mark}
	var created struct {
		ID string `json:"id"`
	}
	a.json(t, http.StatusCreated, http.MethodPost, "/v1/tests", map[string]any{
		"name": mark + "-test", "type": "noop", "interval_seconds": 60, "timeout_seconds": 3,
		"params": map[string]string{"owner": mark},
	}, &created)
	o.testID = created.ID
	created.ID = ""
	a.json(t, http.StatusCreated, http.MethodPost, "/v1/alerts", map[string]any{
		"name": mark + "-alert", "type": "threshold", "metric": "probectl_probe_loss_ratio",
		"match": map[string]string{"test_id": o.testID}, "comparison": "gt", "threshold": 0.5,
		"for_n": 1, "severity": "warning", "enabled": true,
	}, &created)
	o.alertID = created.ID
	if o.testID == "" || o.alertID == "" {
		t.Fatalf("tenant %s: create returned no id (test %q, alert %q)", tenant, o.testID, o.alertID)
	}
	a.json(t, http.StatusOK, http.MethodPut, "/v1/tests/"+o.testID, map[string]any{
		"name": mark + "-test", "type": "noop", "interval_seconds": 30, "timeout_seconds": 3,
		"params": map[string]string{"owner": mark},
	}, nil)
	for _, path := range []string{"/v1/tests/" + o.testID, "/v1/alerts/" + o.alertID} {
		if body := a.get(t, path); !strings.Contains(body, mark) {
			t.Fatalf("tenant %s: GET %s does not carry its own marker %s: %s", tenant, path, mark, body)
		}
	}
	if body := a.get(t, "/v1/tests/"+o.testID); !strings.Contains(body, `"interval_seconds":30`) {
		t.Fatalf("tenant %s: the update of its own test did not persist: %s", tenant, body)
	}
	return o
}

// assertOwnOnly proves the reader's lists hold its own objects and nothing of
// the other tenant's, and that every by-id operation on the other tenant's
// objects — read, update, delete — is refused as not found, then that the
// owner's objects survived the attempts unchanged.
func assertOwnOnly(t *testing.T, reader api, own, other tenantObjects, owner api) {
	t.Helper()
	for _, path := range []string{"/v1/tests", "/v1/alerts"} {
		body := reader.get(t, path)
		if !strings.Contains(body, own.mark) {
			t.Fatalf("tenant %s: GET %s is missing its own objects (%s): %s", own.tenant, path, own.mark, body)
		}
		for _, foreign := range []string{other.mark, other.testID, other.alertID} {
			if strings.Contains(body, foreign) {
				t.Fatalf("CROSS-TENANT LEAK: tenant %s's GET %s shows tenant %s's %s:\n%s",
					own.tenant, path, other.tenant, foreign, body)
			}
		}
	}
	for _, op := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v1/tests/" + other.testID, nil},
		{http.MethodGet, "/v1/alerts/" + other.alertID, nil},
		{http.MethodPut, "/v1/tests/" + other.testID, map[string]any{"name": own.mark + "-hijack", "type": "noop"}},
		{http.MethodPut, "/v1/alerts/" + other.alertID, map[string]any{"name": own.mark + "-hijack", "type": "threshold",
			"metric": "probectl_probe_loss_ratio", "comparison": "gt", "threshold": 0.9}},
		{http.MethodDelete, "/v1/tests/" + other.testID, nil},
		{http.MethodDelete, "/v1/alerts/" + other.alertID, nil},
	} {
		code, body := reader.do(t, op.method, op.path, op.body)
		if code != http.StatusNotFound && code != http.StatusForbidden {
			t.Fatalf("CROSS-TENANT ACCESS: tenant %s's %s %s (tenant %s's object) = %d, want 404/403: %s",
				own.tenant, op.method, op.path, other.tenant, code, body)
		}
		if strings.Contains(string(body), other.mark) {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s's refused %s %s still carried tenant %s's data: %s",
				own.tenant, op.method, op.path, other.tenant, body)
		}
	}
	for _, path := range []string{"/v1/tests/" + other.testID, "/v1/alerts/" + other.alertID} {
		body := owner.get(t, path)
		if !strings.Contains(body, other.mark) || strings.Contains(body, own.mark+"-hijack") {
			t.Fatalf("tenant %s's %s changed after tenant %s's refused writes: %s", other.tenant, path, own.tenant, body)
		}
	}
}

// assertNoForeign fails if a tenant's read of path carries any of the other
// tenant's markers.
func assertNoForeign(t *testing.T, reader api, tenant, path string, foreign ...string) {
	t.Helper()
	body := reader.get(t, path)
	for _, f := range foreign {
		if f != "" && strings.Contains(body, f) {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s's GET %s shows the other tenant's %s:\n%s", tenant, path, f, body)
		}
	}
}

// assertUnauthenticated proves the production auth mode has no ambient
// identity: no credential, a tenant header without a credential, and one
// tenant's token asserting the other tenant are all 401, never data.
func assertUnauthenticated(t *testing.T, anon, tokenB api, tenantA, markA string) {
	t.Helper()
	for _, c := range []struct {
		name    string
		a       api
		headers []string
	}{
		{"no credential", anon, nil},
		{"tenant header without a credential", anon, []string{"X-Probectl-Tenant", tenantA}},
		{"tenant B's token asserting tenant A", tokenB, []string{"X-Probectl-Tenant", tenantA}},
	} {
		code, body := c.a.do(t, http.MethodGet, "/v1/tests", nil, c.headers...)
		if code != http.StatusUnauthorized || (markA != "" && strings.Contains(string(body), markA)) {
			t.Fatalf("%s: GET /v1/tests = %d, want 401 without tenant A's data: %s", c.name, code, body)
		}
	}
}

// resultsLatest returns, from the tenant's /v1/results/latest, the observed
// time of the successful result for (agentID, type, target).
func resultsLatest(t *testing.T, a api, agentID, canaryType, target string) (time.Time, bool) {
	t.Helper()
	var response struct {
		Items []struct {
			AgentID    string    `json:"agent_id"`
			Type       string    `json:"type"`
			Target     string    `json:"target"`
			Success    bool      `json:"success"`
			ObservedAt time.Time `json:"observed_at"`
		} `json:"items"`
	}
	a.json(t, http.StatusOK, http.MethodGet, "/v1/results/latest", nil, &response)
	for _, item := range response.Items {
		if item.AgentID == agentID && item.Type == canaryType && item.Target == target && item.Success {
			return item.ObservedAt, true
		}
	}
	return time.Time{}, false
}

// doQuiet is a credential-free request that reports a transport error as
// status 0 instead of failing the test, for readiness polling.
func (a api) doQuiet(method, path string) (int, error) {
	req, err := http.NewRequest(method, a.base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
