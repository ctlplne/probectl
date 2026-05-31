package cli

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func cmdTest(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "test: expected a subcommand (list|get|create|delete)")
		return 2
	}
	c := newClient(cfg)
	switch args[0] {
	case "list":
		var l list[Test]
		if err := c.do(http.MethodGet, "/v1/tests", nil, &l); err != nil {
			return fail(stderr, err)
		}
		if cfg.JSON {
			return printJSON(stdout, l.Items)
		}
		printTests(stdout, l.Items)
		return 0
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "test get: missing <id>")
			return 2
		}
		var t Test
		if err := c.do(http.MethodGet, "/v1/tests/"+args[1], nil, &t); err != nil {
			return fail(stderr, err)
		}
		if cfg.JSON {
			return printJSON(stdout, t)
		}
		printTest(stdout, t)
		return 0
	case "create":
		return testCreate(cfg, c, args[1:], stdout, stderr)
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "test delete: missing <id>")
			return 2
		}
		if err := c.do(http.MethodDelete, "/v1/tests/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "deleted test "+args[1])
		return 0
	default:
		fmt.Fprintf(stderr, "test: unknown subcommand %q\n", args[0])
		return 2
	}
}

func testCreate(cfg Config, c *client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "test name (required)")
	typ := fs.String("type", "", "probe type (required)")
	target := fs.String("target", "", "target (host:port or address)")
	interval := fs.Int("interval", 60, "interval seconds")
	timeout := fs.Int("timeout", 3, "timeout seconds")
	disabled := fs.Bool("disabled", false, "create disabled")
	params := kvFlag{}
	fs.Var(&params, "param", "a k=v parameter (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *typ == "" {
		fmt.Fprintln(stderr, "test create: --name and --type are required")
		return 2
	}
	body := testRequest{
		Name: *name, Type: *typ, Target: *target,
		IntervalSeconds: *interval, TimeoutSeconds: *timeout,
		Params: map[string]string(params), Enabled: !*disabled,
	}
	var t Test
	if err := c.do(http.MethodPost, "/v1/tests", body, &t); err != nil {
		return fail(stderr, err)
	}
	if cfg.JSON {
		return printJSON(stdout, t)
	}
	fmt.Fprintf(stdout, "created test %s (%s)\n", t.ID, t.Name)
	return 0
}

func cmdAgent(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "agent: expected a subcommand (list|get|delete)")
		return 2
	}
	c := newClient(cfg)
	switch args[0] {
	case "list":
		var l list[Agent]
		if err := c.do(http.MethodGet, "/v1/agents", nil, &l); err != nil {
			return fail(stderr, err)
		}
		if cfg.JSON {
			return printJSON(stdout, l.Items)
		}
		printAgents(stdout, l.Items)
		return 0
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "agent get: missing <id>")
			return 2
		}
		var a Agent
		if err := c.do(http.MethodGet, "/v1/agents/"+args[1], nil, &a); err != nil {
			return fail(stderr, err)
		}
		if cfg.JSON {
			return printJSON(stdout, a)
		}
		printAgent(stdout, a)
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "agent delete: missing <id>")
			return 2
		}
		if err := c.do(http.MethodDelete, "/v1/agents/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintln(stdout, "deregistered agent "+args[1])
		return 0
	default:
		fmt.Fprintf(stderr, "agent: unknown subcommand %q\n", args[0])
		return 2
	}
}

// kvFlag collects repeated --param k=v flags into a map.
type kvFlag map[string]string

func (k *kvFlag) String() string { return "" }

func (k *kvFlag) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i < 0 {
		return fmt.Errorf("expected k=v, got %q", v)
	}
	if *k == nil {
		*k = kvFlag{}
	}
	(*k)[v[:i]] = v[i+1:]
	return nil
}

func fail(w io.Writer, err error) int {
	fmt.Fprintln(w, "error: "+err.Error())
	return 1
}
