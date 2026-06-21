// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package cli implements the probectl command-line interface for the
// control-plane /v1 API. Run is the testable entry point; cmd/probectl is a thin
// wrapper around it.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/i18n"
)

// Config is the resolved CLI configuration (flags override environment).
type Config struct {
	BaseURL string
	Token   string
	Tenant  string
	JSON    bool
	Locale  string
}

// Run executes one CLI invocation and returns a process exit code. It is pure
// with respect to its arguments, environment accessor, and writers, so it is
// straightforward to test.
func Run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cfg := Config{
		BaseURL: envOr(getenv, "PROBECTL_API_URL", "http://localhost:8080"),
		Token:   getenv("PROBECTL_API_TOKEN"),
		Tenant:  getenv("PROBECTL_TENANT"),
		Locale:  i18n.Resolve(getenv("PROBECTL_LOCALE")),
	}
	// --json may appear anywhere; strip it before flag parsing.
	args, cfg.JSON = extractBoolFlag(args, "--json")

	fs := flag.NewFlagSet("probectl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr, cfg.Locale) }
	fs.StringVar(&cfg.BaseURL, "url", cfg.BaseURL, "control-plane API base URL (env PROBECTL_API_URL)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "API auth token, sent as Bearer (env PROBECTL_API_TOKEN)")
	fs.StringVar(&cfg.Tenant, "tenant", cfg.Tenant, "tenant UUID, sent as X-Probectl-Tenant (env PROBECTL_TENANT)")
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
		fmt.Fprintln(stdout, "probectl "+buildVersion())
		return 0
	case "test":
		return cmdTest(cfg, rest[1:], stdout, stderr)
	case "agent":
		return cmdAgent(cfg, rest[1:], stdout, stderr)
	case "lifecycle":
		return cmdLifecycle(cfg, rest[1:], stdout, stderr)
	case "api":
		return cmdAPI(cfg, rest[1:], stdout, stderr)
	default:
		if spec, ok := surfaceCommands[rest[0]]; ok {
			return cmdSurface(cfg, spec, rest[1:], stdout, stderr)
		}
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.error.unknown", map[string]string{
			"command": fmt.Sprintf("%q", rest[0]),
		}))
		usage(stderr, cfg.Locale)
		return 2
	}
}

func usage(w io.Writer, locale string) {
	fmt.Fprint(w, i18n.T(locale, "cli.usage", nil))
}

// client is a thin JSON HTTP client for the /v1 API.
type client struct {
	cfg Config
	hc  *http.Client
}

func newClient(cfg Config) *client {
	return &client{cfg: cfg, hc: &http.Client{Timeout: 15 * time.Second}}
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
	req, err := http.NewRequest(method, c.cfg.BaseURL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

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
	req, err := http.NewRequest(method, c.cfg.BaseURL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/gzip")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(resp.Body)
		if ok, err := formatAPIError(data, c.cfg.Locale); ok {
			return err
		}
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
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
