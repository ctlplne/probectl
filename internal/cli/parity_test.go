// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type openAPIDoc struct {
	Paths map[string]map[string]any `json:"paths"`
}

func TestCLIOpenAPIParity(t *testing.T) {
	covered := map[string]cliCoverage{}
	for _, cov := range cliImplementedCoverage() {
		covered[opKey(cov.Method, cov.Path)] = cov
	}
	for _, cov := range cliCoverageExceptions {
		if cov.Reason == "" {
			t.Fatalf("%s %s: none-by-design exception must explain why", cov.Method, cov.Path)
		}
		covered[opKey(cov.Method, cov.Path)] = cov
	}

	for _, spec := range []struct {
		name   string
		path   string
		prefix string
	}{
		{name: "core", path: "../control/openapi.json", prefix: "/v1/"},
		{name: "provider", path: "../../ee/provider/openapi.json", prefix: "/provider/v1/"},
	} {
		t.Run(spec.name, func(t *testing.T) {
			raw, err := os.ReadFile(spec.path)
			if err != nil {
				t.Fatal(err)
			}
			var doc openAPIDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}

			var missing []string
			for path, methods := range doc.Paths {
				if !strings.HasPrefix(path, spec.prefix) {
					continue
				}
				for method := range methods {
					if method == "parameters" {
						continue
					}
					key := opKey(method, path)
					if _, ok := covered[key]; !ok {
						missing = append(missing, key)
					}
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Fatalf("OpenAPI operations without CLI command or explicit exception:\n%s", strings.Join(missing, "\n"))
			}
		})
	}
}

func TestProviderAuthAndProvisioningSurfacesExecute(t *testing.T) {
	const (
		provisionID = "00000000-0000-4000-8000-000000000201"
		session     = "test-only-provider-session"
	)
	type observedRequest struct {
		method        string
		path          string
		query         string
		authorization string
		body          []byte
	}
	seen := make(chan observedRequest, 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- observedRequest{
			method:        r.Method,
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"),
			body:          body,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name        string
		command     string
		method      string
		template    string
		path        string
		query       string
		withSession bool
		body        string
		args        []string
	}{
		{
			name: "bootstrap", command: "bootstrap", method: http.MethodPost,
			template: "/provider/v1/auth/bootstrap", path: "/provider/v1/auth/bootstrap",
			body: `{"token":"test-only-bootstrap-token","email":"operator@example.test","name":"Test Operator"}`,
		},
		{
			name: "enroll start", command: "enroll-start", method: http.MethodPost,
			template: "/provider/v1/auth/enroll/start", path: "/provider/v1/auth/enroll/start",
			body: `{"token":"test-only-enroll-token"}`,
		},
		{
			name: "enroll complete", command: "enroll-complete", method: http.MethodPost,
			template: "/provider/v1/auth/enroll/complete", path: "/provider/v1/auth/enroll/complete",
			body: `{"token":"test-only-enroll-token","password":"test-only-not-a-secret","totp":"654321"}`,
		},
		{
			name: "login", command: "login", method: http.MethodPost,
			template: "/provider/v1/auth/login", path: "/provider/v1/auth/login",
			body: `{"email":"operator@example.test","password":"test-only-not-a-secret","totp":"654321"}`,
		},
		{
			name: "logout", command: "logout", method: http.MethodPost,
			template: "/provider/v1/auth/logout", path: "/provider/v1/auth/logout", withSession: true,
		},
		{
			name: "list stranded provisioning", command: "provisioning", method: http.MethodGet,
			template: "/provider/v1/tenants/provisioning", path: "/provider/v1/tenants/provisioning",
			query: "older_than=24h", withSession: true, args: []string{"--query", "older_than=24h"},
		},
		{
			name: "abandon stranded provisioning", command: "abandon-provision", method: http.MethodPost,
			template:    "/provider/v1/tenants/provisioning/{id}/abandon",
			path:        "/provider/v1/tenants/provisioning/" + provisionID + "/abandon",
			withSession: true, args: []string{provisionID},
		},
	}

	provider := surfaceCommands["provider"]
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, ok := provider.Ops[tc.command]
			if !ok {
				t.Fatalf("provider CLI surface %q is not registered", tc.command)
			}
			if op.Method != tc.method || op.Path != tc.template {
				t.Fatalf("provider %s operation = %s %s, want %s %s", tc.command, op.Method, op.Path, tc.method, tc.template)
			}
			if op.SensitiveBody != (tc.body != "") {
				t.Fatalf("provider %s SensitiveBody = %t, want %t", tc.command, op.SensitiveBody, tc.body != "")
			}

			args := make([]string, 0, 8)
			args = append(args, "provider", tc.command)
			if tc.body != "" {
				args = append(args, "--body-file", "-")
			}
			args = append(args, tc.args...)
			joinedArgs := strings.Join(args, "\x00")
			for _, secret := range []string{"test-only-bootstrap-token", "test-only-enroll-token", "test-only-not-a-secret", "654321"} {
				if strings.Contains(joinedArgs, secret) {
					t.Fatalf("credential %q leaked into argv: %q", secret, args)
				}
			}

			var stdout, stderr bytes.Buffer
			code := RunWithStdin(args, func(key string) string {
				if key == "PROBECTL_API_URL" {
					return srv.URL
				}
				if key == "PROBECTL_API_TOKEN" && tc.withSession {
					return session
				}
				return ""
			}, strings.NewReader(tc.body), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			got := <-seen
			if got.method != tc.method || got.path != tc.path || got.query != tc.query {
				t.Fatalf("request = %s %s?%s, want %s %s?%s", got.method, got.path, got.query, tc.method, tc.path, tc.query)
			}
			wantAuthorization := ""
			if tc.withSession {
				wantAuthorization = "Bearer " + session
			}
			if got.authorization != wantAuthorization {
				t.Fatalf("Authorization = %q, want %q", got.authorization, wantAuthorization)
			}
			if tc.body != "" {
				var gotJSON, wantJSON any
				if err := json.Unmarshal(got.body, &gotJSON); err != nil {
					t.Fatalf("request body is invalid JSON: %q: %v", got.body, err)
				}
				if err := json.Unmarshal([]byte(tc.body), &wantJSON); err != nil {
					t.Fatal(err)
				}
				gotCanonical, _ := json.Marshal(gotJSON)
				wantCanonical, _ := json.Marshal(wantJSON)
				if !bytes.Equal(gotCanonical, wantCanonical) {
					t.Fatalf("request body = %s, want %s", gotCanonical, wantCanonical)
				}
			}
		})
	}
}

func TestProviderCLIHelpAdvertisesOnlyTheSecureCredentialBodyPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := RunWithStdin(
		[]string{"provider", "help"},
		func(string) string { return "" },
		strings.NewReader("unused"),
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("exit = %d, want usage exit 2", code)
	}
	usage := stderr.String()
	for _, want := range []string{
		"Flags: --query k=v (repeatable), --body JSON, global --json",
		"Credential-bearing operations require --body-file <0600-file|->; inline --body is refused. Stdin is preserved on this secure path.",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("provider help missing %q:\n%s", want, usage)
		}
	}
}

func TestSensitiveProviderAuthBodyFileSafety(t *testing.T) {
	const body = `{"email":"operator@example.test","password":"owner-only-password","totp":"654321"}`
	requests := 0
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	env := func(key string) string {
		if key == "PROBECTL_API_URL" {
			return srv.URL
		}
		return ""
	}
	run := func(stdin io.Reader, args ...string) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := RunWithStdin(args, env, stdin, &stdout, &stderr)
		return code, stderr.String()
	}

	t.Run("owner-only file succeeds", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "login.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		before := requests
		if code, stderr := run(strings.NewReader("unused"), "provider", "login", "--body-file", path); code != 0 {
			t.Fatalf("exit = %d, stderr=%s", code, stderr)
		}
		if requests != before+1 || !json.Valid(received) {
			t.Fatalf("requests=%d, body=%q", requests, received)
		}
	})

	reject := func(t *testing.T, stdin io.Reader, want string, args ...string) {
		t.Helper()
		before := requests
		code, stderr := run(stdin, args...)
		if code != 2 || !strings.Contains(stderr, want) {
			t.Fatalf("exit=%d stderr=%q, want usage error containing %q", code, stderr, want)
		}
		if requests != before {
			t.Fatalf("rejected command made %d request(s)", requests-before)
		}
	}

	t.Run("inline body is refused", func(t *testing.T) {
		reject(t, bytes.NewReader(nil), "refuses --body", "provider", "login", "--body", body)
	})
	t.Run("inline and file conflict is refused", func(t *testing.T) {
		reject(t, strings.NewReader(body), "cannot be combined", "provider", "login", "--body", body, "--body-file", "-")
	})
	for name, requestPath := range map[string]string{
		"exact":                  "/provider/v1/auth/login",
		"leading repeated slash": "//provider/v1/auth/login",
		"query":                  "/provider/v1/auth/login?attempt=1",
		"dot segment":            "/provider/v1/auth/x/../login",
		"encoded dot segment":    "/provider/v1/auth/x/%2e%2e/login",
		"repeated slash":         "/provider//v1/auth/login",
		"trailing slash":         "/provider/v1/auth/login/",
		"relative spelling":      "provider/v1/auth/login",
		"relative parent escape": "../provider/v1/auth/login",
		"encoded path character": "/provider/v1/auth/%6cogin",
		"encoded separators":     "%2fprovider%2fv1%2fauth%2flogin",
	} {
		t.Run("raw api "+name+" cannot bypass policy", func(t *testing.T) {
			reject(t, bytes.NewReader(nil), "refuses --body", "api", "POST", requestPath, "--body", body)
		})
	}
	t.Run("world-readable file is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "login.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		reject(t, bytes.NewReader(nil), "want 0600", "provider", "login", "--body-file", path)
	})
	t.Run("symlink is refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "login.json")
		link := filepath.Join(dir, "login-link.json")
		if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		reject(t, bytes.NewReader(nil), "real regular file", "provider", "login", "--body-file", link)
	})
	t.Run("oversize file is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "login.json")
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, int(maxSensitiveRequestBodyBytes)+1), 0o600); err != nil {
			t.Fatal(err)
		}
		reject(t, bytes.NewReader(nil), "1..1048576 bytes", "provider", "login", "--body-file", path)
	})
	t.Run("oversize stdin is refused", func(t *testing.T) {
		reject(t, bytes.NewReader(bytes.Repeat([]byte{'x'}, int(maxSensitiveRequestBodyBytes)+1)), "1048576-byte limit", "provider", "login", "--body-file", "-")
	})
}

type countingCLIReader struct {
	reads atomic.Int32
}

func (r *countingCLIReader) Read([]byte) (int, error) {
	r.reads.Add(1)
	return 0, io.EOF
}

func TestSensitiveProviderAuthCannotHideBehindBasePath(t *testing.T) {
	const body = `{"email":"operator@example.test","password":"must-not-enter-argv"}`
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	for name, tc := range map[string]struct {
		baseURL string
		path    string
	}{
		"leading slash":   {baseURL: srv.URL + "/provider/v1/auth", path: "/login"},
		"relative target": {baseURL: srv.URL + "/provider/v1/auth/", path: "login"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := RunWithStdin(
				[]string{"api", http.MethodPost, tc.path, "--body", body},
				func(key string) string {
					if key == "PROBECTL_API_URL" {
						return tc.baseURL
					}
					return ""
				},
				bytes.NewReader(nil),
				&stdout,
				&stderr,
			)
			if code != 2 || !strings.Contains(stderr.String(), "refuses --body") {
				t.Fatalf("exit=%d stderr=%q, want credential-body policy refusal", code, stderr.String())
			}
			if requests.Load() != 0 {
				t.Fatalf("hidden sensitive route made %d request(s)", requests.Load())
			}
		})
	}
}

func TestUnsafeAPITargetIsRejectedBeforeReadingBody(t *testing.T) {
	for name, tc := range map[string]struct {
		baseURL string
		args    []string
		want    string
	}{
		"named provider over remote plaintext": {
			baseURL: "http://api.example.test",
			args:    []string{"provider", "login", "--body-file", "-"},
			want:    "require HTTPS",
		},
		"base-path provider over remote plaintext": {
			baseURL: "http://api.example.test/provider/v1/auth",
			args:    []string{"api", http.MethodPost, "/login", "--body-file", "-"},
			want:    "require HTTPS",
		},
		"authority injection": {
			baseURL: "https://control.example.test",
			args:    []string{"api", http.MethodPost, "@evil.example.test/provider/v1/auth/login", "--body-file", "-"},
			want:    "changes authority",
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader := &countingCLIReader{}
			var stdout, stderr bytes.Buffer
			code := RunWithStdin(
				tc.args,
				func(key string) string {
					if key == "PROBECTL_API_URL" {
						return tc.baseURL
					}
					return ""
				},
				reader,
				&stdout,
				&stderr,
			)
			if code != 2 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit=%d stderr=%q, want pre-body target refusal containing %q", code, stderr.String(), tc.want)
			}
			if reader.reads.Load() != 0 {
				t.Fatalf("unsafe target read request body %d time(s)", reader.reads.Load())
			}
		})
	}
}

func TestSensitiveProviderAuthRedirectNeverReplaysBody(t *testing.T) {
	const body = `{"email":"operator@example.test","password":"redirect-secret","totp":"654321"}`
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, topology := range []string{"cross-origin", "same-origin-with-base-prefix"} {
			t.Run(fmt.Sprintf("%s-%d", topology, status), func(t *testing.T) {
				var sourceRequests, redirectedRequests atomic.Int32
				var redirectTarget string
				var targetServer *httptest.Server
				if topology == "cross-origin" {
					targetServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						redirectedRequests.Add(1)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"ok":true}`))
					}))
					t.Cleanup(targetServer.Close)
					redirectTarget = targetServer.URL + "/capture"
				}

				sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/capture" {
						redirectedRequests.Add(1)
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"ok":true}`))
						return
					}
					sourceRequests.Add(1)
					location := redirectTarget
					if topology == "same-origin-with-base-prefix" {
						location = "/capture"
					}
					w.Header().Set("Location", location)
					w.WriteHeader(status)
				}))
				t.Cleanup(sourceServer.Close)

				baseURL := sourceServer.URL
				if topology == "same-origin-with-base-prefix" {
					// The final path is deliberately not the canonical provider route;
					// redirect safety must also classify the original named operation.
					baseURL += "/prefix"
				}
				var stdout, stderr bytes.Buffer
				code := RunWithStdin(
					[]string{"provider", "login", "--body-file", "-"},
					func(key string) string {
						if key == "PROBECTL_API_URL" {
							return baseURL
						}
						return ""
					},
					strings.NewReader(body),
					&stdout,
					&stderr,
				)
				if code == 0 {
					t.Fatalf("sensitive %d redirect unexpectedly succeeded", status)
				}
				if sourceRequests.Load() != 1 || redirectedRequests.Load() != 0 {
					t.Fatalf("source requests=%d redirected requests=%d, want 1 and 0", sourceRequests.Load(), redirectedRequests.Load())
				}
				for _, secret := range []string{"redirect-secret", "654321"} {
					if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
						t.Fatalf("credential %q leaked to CLI output", secret)
					}
				}
			})
		}
	}
}

func TestOwnerOnlyCLIFileRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX FIFO contract")
	}
	path := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(path, []byte(`{"password":"generation-one"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := readOwnerOnlyCLIFileWithHook(path, maxSensitiveRequestBodyBytes, func() {
		if removeErr := os.Remove(path); removeErr != nil {
			t.Fatal(removeErr)
		}
		if fifoErr := syscall.Mkfifo(path, 0o600); fifoErr != nil {
			t.Fatal(fifoErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("error = %v, want raced replacement refusal", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO replacement blocked credential loading for %s", elapsed)
	}
}

func TestCLIHelpListsExpandedSurfaceGroups(t *testing.T) {
	var out, errs bytes.Buffer
	code := runCLI([]string{"help"}, func(string) string { return "" }, &out, &errs)
	if code != 0 {
		t.Fatalf("help exit = %d, stderr=%s", code, errs.String())
	}
	for _, want := range []string{
		"Resource groups (generated from the served API surface):",
		"  bgp",
		"  device",
		"  ebpf",
		"  hierarchy",
		"  key",
		"  scim",
		"  secret",
		"  siem",
		"  tenant",
		"  threat",
		"  topology",
		"rollout create",
		"api <method> <path>",
		"Examples:",
		"probectl --url https://control.example --tenant 00000000-0000-0000-0000-000000000001 test create --name checkout-http --type http --target https://checkout.example/health --interval 60",
		`probectl --tenant 00000000-0000-0000-0000-000000000001 agent enroll-token --body '{"name":"edge-canary-1","ttl_seconds":3600}'`,
		"probectl --tenant 00000000-0000-0000-0000-000000000001 audit verify",
		`probectl --tenant 00000000-0000-0000-0000-000000000001 lifecycle subject-erase --subject user:ada@example.com --confirm user:ada@example.com --reason "requested deletion"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, out.String())
		}
	}
}

func TestCLIHelpInventoryMatchesSurfaceCommands(t *testing.T) {
	for _, tc := range []struct {
		name   string
		locale string
	}{
		{name: "english", locale: "en"},
		{name: "spanish", locale: "es-MX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			env := func(k string) string {
				if k == "PROBECTL_LOCALE" {
					return tc.locale
				}
				return ""
			}
			code := runCLI([]string{"help"}, env, &out, &errs)
			if code != 0 {
				t.Fatalf("help exit = %d, stderr=%s", code, errs.String())
			}
			listed := topLevelHelpGroups(out.String())
			var missing []string
			for name := range surfaceCommands {
				if !listed[name] {
					missing = append(missing, name)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Fatalf("%s help is missing surface groups:\n%s\n\nhelp:\n%s", tc.name, strings.Join(missing, "\n"), out.String())
			}
		})
	}
}

func topLevelHelpGroups(help string) map[string]bool {
	groups := map[string]bool{}
	inInventory := false
	for _, line := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Resource groups") || strings.HasPrefix(trimmed, "Grupos de recursos") {
			inInventory = true
			continue
		}
		if inInventory && strings.HasPrefix(trimmed, "version ") {
			break
		}
		if !inInventory {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, ok := surfaceCommands[fields[0]]; ok {
			groups[fields[0]] = true
		}
	}
	return groups
}

func opKey(method, path string) string { return strings.ToUpper(method) + " " + path }
