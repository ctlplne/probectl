// Package cli implements the netctl command-line interface — a web-parity client
// for the control-plane /v1 API. Run is the testable entry point; cmd/netctl is
// a thin wrapper around it.
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config is the resolved CLI configuration (flags override environment).
type Config struct {
	BaseURL string
	Token   string
	Tenant  string
	JSON    bool
}

// Run executes one CLI invocation and returns a process exit code. It is pure
// with respect to its arguments, environment accessor, and writers, so it is
// straightforward to test.
func Run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	cfg := Config{
		BaseURL: envOr(getenv, "NETCTL_API_URL", "http://localhost:8080"),
		Token:   getenv("NETCTL_API_TOKEN"),
		Tenant:  getenv("NETCTL_TENANT"),
	}
	// --json may appear anywhere; strip it before flag parsing.
	args, cfg.JSON = extractBoolFlag(args, "--json")

	fs := flag.NewFlagSet("netctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.StringVar(&cfg.BaseURL, "url", cfg.BaseURL, "control-plane API base URL (env NETCTL_API_URL)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "API auth token, sent as Bearer (env NETCTL_API_TOKEN)")
	fs.StringVar(&cfg.Tenant, "tenant", cfg.Tenant, "tenant UUID, sent as X-Netctl-Tenant (env NETCTL_TENANT)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}

	switch rest[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "version":
		fmt.Fprintln(stdout, "netctl "+buildVersion())
		return 0
	case "test":
		return cmdTest(cfg, rest[1:], stdout, stderr)
	case "agent":
		return cmdAgent(cfg, rest[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", rest[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `netctl — control-plane CLI

Usage:
  netctl [global flags] <command> [args]

Commands:
  test list                      list synthetic tests
  test get <id>                  show one test
  test create --name --type ...  create a test
  test delete <id>               delete a test
  agent list                     list agents
  agent get <id>                 show one agent
  agent delete <id>              deregister an agent
  version                        print the CLI version

Global flags:
  --url <url>       API base URL (env NETCTL_API_URL, default http://localhost:8080)
  --token <token>   Bearer auth token (env NETCTL_API_TOKEN)
  --tenant <uuid>   tenant scope (env NETCTL_TENANT)
  --json            output JSON instead of a table

'test create' flags:
  --name <name>     required
  --type <type>     required: icmp|tcp|udp|dns|http|a2a|noop
  --target <target> required (except noop), e.g. host:port or an address
  --interval <sec>  default 60
  --timeout <sec>   default 3
  --param k=v       repeatable
  --disabled        create the test disabled
`)
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
		req.Header.Set("X-Netctl-Tenant", c.cfg.Tenant)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode/100 != 2 {
		var env struct {
			Error struct {
				Code, Message string
			} `json:"error"`
		}
		if json.Unmarshal(data, &env) == nil && env.Error.Message != "" {
			return fmt.Errorf("%s (%s)", env.Error.Message, env.Error.Code)
		}
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
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
