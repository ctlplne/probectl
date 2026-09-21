// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package cli implements the probectl command-line interface for the
// control-plane /v1 API. run is the testable entry point; cmd/probectl is a thin
// wrapper around it.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/httpbody"
	"github.com/ctlplne/probectl/internal/i18n"
)

// Config is the resolved CLI configuration (flags override environment).
type Config struct {
	BaseURL string
	Token   string
	Tenant  string
	JSON    bool
	Locale  string
	// SessionCookieFile is the owner-only file used by investigation commands
	// that require an MFA-bearing browser/OIDC session rather than a bearer
	// token. SessionCookie exists only in memory after that file is read.
	SessionCookieFile string
	SessionCookie     string
	// CAFile is a PEM bundle that verifies the control plane's certificate
	// (DPR-077). Enterprises front probectl with a private CA; Go on macOS
	// ignores SSL_CERT_FILE, so without this knob the CLI could only reach a
	// control plane whose issuer is in the OS trust store.
	CAFile string
}

// run executes one CLI invocation and returns a process exit code. It is pure
// with respect to its arguments, environment accessor, and writers, so it is
// straightforward to test.
func runCLI(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	return RunWithStdin(args, getenv, bytes.NewReader(nil), stdout, stderr)
}

// RunWithStdin is run with an explicit input stream. Dashboard manifest import
// uses it for Unix-friendly pipelines while run remains source-compatible for
// embedders and existing tests.
func RunWithStdin(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg := Config{
		BaseURL: envOr(getenv, "PROBECTL_API_URL", "https://localhost:8443"),
		Token:   getenv("PROBECTL_API_TOKEN"),
		Tenant:  getenv("PROBECTL_TENANT"),
		Locale:  i18n.Resolve(getenv("PROBECTL_LOCALE")),
		SessionCookieFile: getenv(
			"PROBECTL_SESSION_COOKIE_FILE",
		),
		CAFile: getenv("PROBECTL_CA_FILE"),
	}
	// --json may appear anywhere; strip it before flag parsing.
	args, cfg.JSON = extractBoolFlag(args, "--json")
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		usage(stdout, cfg.Locale)
		return 0
	}

	fs := flag.NewFlagSet("probectl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr, cfg.Locale) }
	fs.StringVar(&cfg.BaseURL, "url", cfg.BaseURL, "control-plane API base URL (env PROBECTL_API_URL)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "API auth token, sent as Bearer (env PROBECTL_API_TOKEN)")
	fs.StringVar(&cfg.Tenant, "tenant", cfg.Tenant, "tenant UUID, sent as X-Probectl-Tenant (env PROBECTL_TENANT)")
	fs.StringVar(&cfg.CAFile, "ca-file", cfg.CAFile, "PEM CA bundle that verifies the control plane's certificate (env PROBECTL_CA_FILE); default: the OS trust store")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr, cfg.Locale)
		return 2
	}

	switch rest[0] {
	case "help", "-h", "--help":
		usage(stdout, cfg.Locale)
		return 0
	case "version":
		if cfg.JSON {
			return printJSON(stdout, buildInfo())
		}
		fmt.Fprintln(stdout, "probectl "+buildVersion())
		return 0
	case "test":
		return cmdTest(cfg, rest[1:], stdout, stderr)
	case "agent":
		return cmdAgent(cfg, rest[1:], stdout, stderr)
	case "lifecycle":
		return cmdLifecycle(cfg, rest[1:], stdout, stderr)
	case "dashboard-report":
		return cmdDashboardReport(cfg, rest[1:], stdout, stderr)
	case "dashboard":
		return cmdDashboard(cfg, rest[1:], stdin, stdout, stderr)
	case "device":
		return cmdDevice(cfg, rest[1:], stdout, stderr)
	case "ai":
		return cmdAI(cfg, rest[1:], stdout, stderr)
	case "audit":
		return cmdAudit(cfg, rest[1:], stdin, stdout, stderr)
	case "incident":
		return cmdIncident(cfg, rest[1:], stdout, stderr)
	case "api":
		return cmdAPIWithStdin(cfg, rest[1:], stdin, stdout, stderr)
	case "verify-bundle":
		return cmdVerifyBundle(cfg, rest[1:], stdout, stderr)
	default:
		if spec, ok := surfaceCommands[rest[0]]; ok {
			return cmdSurfaceWithStdin(cfg, spec, rest[1:], stdin, stdout, stderr)
		}
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.error.unknown", map[string]string{
			"command": fmt.Sprintf("%q", rest[0]),
		}))
		usage(stderr, cfg.Locale)
		return 2
	}
}

func usage(w io.Writer, locale string) {
	fmt.Fprint(w, renderUsage(locale))
}

// client is a thin JSON HTTP client for the /v1 API.
type client struct {
	cfg Config
	hc  *http.Client
}

const (
	maxBufferedResponseBody      = httpbody.MaxClientResponseBodyBytes
	maxBufferedErrorResponseBody = httpbody.MaxClientErrorResponseBodyBytes
)

func newClient(cfg Config) *client {
	return &client{cfg: cfg, hc: &http.Client{Timeout: 15 * time.Second, Transport: clientTransport(cfg)}}
}

// clientTransport verifies the control plane against the OS trust store, or
// against the operator's private CA bundle when PROBECTL_CA_FILE / --ca-file
// is set (DPR-077). Verification is never disabled; an unreadable or
// non-PEM bundle fails at the first request with the reason, not silently.
func clientTransport(cfg Config) http.RoundTripper {
	if cfg.CAFile == "" {
		return &http.Transport{TLSClientConfig: crypto.HardenedClientTLSConfig(), Proxy: http.ProxyFromEnvironment}
	}
	tlsCfg, err := crypto.HardenedClientTLSConfigWithCAFile(cfg.CAFile)
	if err != nil {
		return failingTransport{err: fmt.Errorf("cli: PROBECTL_CA_FILE: %w", err)}
	}
	return &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// composeAPIURL preserves the CLI's established base-path prefix behavior but
// proves string concatenation cannot change the configured origin. Without
// this check a target beginning with "@other-host" could reinterpret the
// configured host as URL userinfo and receive tenant/auth headers.
func composeAPIURL(baseRaw, requestTarget string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(baseRaw))
	if err != nil || base.Scheme == "" || base.Host == "" || base.Opaque != "" {
		return nil, errors.New("CLI API base URL must be an absolute http(s) origin")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, errors.New("CLI API base URL must use http or https")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("CLI API base URL must not contain credentials, a query, or a fragment")
	}
	target, err := url.Parse(base.String() + requestTarget)
	if err != nil || target.Scheme == "" || target.Host == "" || target.Opaque != "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("CLI API request target is malformed or changes authority")
	}
	if !sameAPIOrigin(base, target) {
		return nil, errors.New("CLI API request target must remain on the configured origin")
	}
	return target, nil
}

func resolveAPIURL(baseRaw, requestTarget string) (*url.URL, error) {
	target, err := composeAPIURL(baseRaw, requestTarget)
	if err != nil {
		return nil, err
	}
	if target.Scheme != "https" && !apiLoopbackHost(target.Hostname()) {
		return nil, errors.New("CLI API requests require HTTPS (plaintext HTTP is limited to loopback development)")
	}
	return target, nil
}

func apiLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && address.Unmap().IsLoopback()
}

func sameAPIOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) ||
		!strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	effectivePort := func(target *url.URL) string {
		if port := target.Port(); port != "" {
			return port
		}
		if strings.EqualFold(target.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return effectivePort(left) == effectivePort(right)
}

func (c *client) requestHTTPClient(initial *url.URL, sensitive bool) *http.Client {
	base := c.hc
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	clone := *base
	previous := clone.CheckRedirect
	clone.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		// Passwords, enrollment tokens, and TOTP values are valid only for the
		// exact endpoint selected by the operator. Never replay that body, even
		// to another path on the same control-plane origin.
		if sensitive {
			return http.ErrUseLastResponse
		}
		// All other authenticated requests may follow same-origin redirects,
		// but tenant/auth headers and request bodies never cross an origin or a
		// TLS downgrade boundary.
		if !sameAPIOrigin(initial, next.URL) {
			return http.ErrUseLastResponse
		}
		if previous != nil {
			return previous(next, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &clone
}

// do performs a request and returns the decoded body or a domain error message.
func (c *client) do(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	target, err := resolveAPIURL(c.cfg.BaseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, target.String(), r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.SessionCookie != "" {
		req.AddCookie(&http.Cookie{
			Name:  auth.SessionCookie,
			Value: c.cfg.SessionCookie,
		})
	} else if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}

	_, sensitiveTarget := sensitiveProviderOperationURL(method, target)
	_, sensitivePath := sensitiveProviderOperationPath(method, path)
	sensitive := sensitiveTarget || sensitivePath
	resp, err := c.requestHTTPClient(target, sensitive).Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := readBufferedResponse(resp)
	if err != nil {
		return err
	}

	if resp.StatusCode/100 != 2 {
		if ok, err := formatAPIError(data, c.cfg.Locale); ok {
			return err
		}
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *client) stream(method, path string, body any, w io.Writer) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	target, err := resolveAPIURL(c.cfg.BaseURL, path)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, target.String(), r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/gzip")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.SessionCookie != "" {
		req.AddCookie(&http.Cookie{
			Name:  auth.SessionCookie,
			Value: c.cfg.SessionCookie,
		})
	} else if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}
	_, sensitiveTarget := sensitiveProviderOperationURL(method, target)
	_, sensitivePath := sensitiveProviderOperationPath(method, path)
	sensitive := sensitiveTarget || sensitivePath
	resp, err := c.requestHTTPClient(target, sensitive).Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		data, err := readBufferedResponse(resp)
		if err != nil {
			return err
		}
		if ok, err := formatAPIError(data, c.cfg.Locale); ok {
			return err
		}
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func readBufferedResponse(resp *http.Response) ([]byte, error) {
	limit := maxBufferedResponseBody
	if resp.StatusCode/100 != 2 {
		limit = maxBufferedErrorResponseBody
	}
	data, err := httpbody.ReadLimited(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("read API response body (limit %d bytes): %w", limit, err)
	}
	return data, nil
}

func formatAPIError(data []byte, locale string) (bool, error) {
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &env) != nil || env.Error.Message == "" {
		return false, nil
	}
	msg := i18n.ErrorMessage(locale, env.Error.Code, env.Error.Message)
	if env.Error.RequestID != "" {
		return true, fmt.Errorf("%s (%s, request_id=%s)", msg, env.Error.Code, env.Error.RequestID)
	}
	return true, fmt.Errorf("%s (%s)", msg, env.Error.Code)
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// extractBoolFlag removes every occurrence of name from args, reporting presence.
func extractBoolFlag(args []string, name string) ([]string, bool) {
	out := args[:0:0]
	found := false
	for _, a := range args {
		if a == name {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}
