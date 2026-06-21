// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	case "update":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "test update: missing <id>")
			return 2
		}
		return runRawOperation(cfg, apiOp{Method: http.MethodPut, Path: "/v1/tests/{id}", ArgName: "id"}, args[1:], stdout, stderr)
	case "bundle":
		return runRawOperation(cfg, apiOp{Method: http.MethodGet, Path: "/v1/tests/bundle"}, args[1:], stdout, stderr)
	case "path":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "test path: missing <id>")
			return 2
		}
		method := http.MethodGet
		for i, a := range args[2:] {
			if a == "--body" && i+3 <= len(args) {
				method = http.MethodPost
				break
			}
		}
		return runRawOperation(cfg, apiOp{Method: method, Path: "/v1/tests/{id}/path", ArgName: "id"}, args[1:], stdout, stderr)
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
	case "patch":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "agent patch: missing <id>")
			return 2
		}
		return runRawOperation(cfg, apiOp{Method: http.MethodPatch, Path: "/v1/agents/{id}", ArgName: "id"}, args[1:], stdout, stderr)
	case "enroll-token":
		return runRawOperation(cfg, apiOp{Method: http.MethodPost, Path: "/v1/agents/enroll-tokens"}, args[1:], stdout, stderr)
	case "ci":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "agent ci: missing <id>")
			return 2
		}
		return runRawOperation(cfg, apiOp{Method: http.MethodGet, Path: "/v1/agents/{id}/ci", ArgName: "id"}, args[1:], stdout, stderr)
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "agent revoke: missing <id>")
			return 2
		}
		return runRawOperation(cfg, apiOp{Method: http.MethodPost, Path: "/v1/agents/{id}/revoke", ArgName: "id"}, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "agent: unknown subcommand %q\n", args[0])
		return 2
	}
}

func cmdLifecycle(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "lifecycle: expected a subcommand")
		return 2
	}
	c := newClient(cfg)
	switch args[0] {
	case "export":
		return lifecycleExport(c, args[1:], stdout, stderr)
	case "subject-export":
		return lifecycleSubjectExport(c, args[1:], stdout, stderr)
	case "subject-erase":
		return lifecycleSubjectErase(cfg, c, args[1:], stdout, stderr)
	default:
		spec := surfaceCommands["lifecycle"]
		return cmdSurface(cfg, spec, args, stdout, stderr)
	}
}

func lifecycleExport(c *client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lifecycle export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	redact := fs.Bool("redact", false, "redact PII in the bundle")
	query := kvFlag{}
	fs.Var(&query, "query", "query parameter k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	params := map[string]string(query)
	if *redact {
		params["redact"] = "true"
	}
	path := withQuery("/v1/lifecycle/export", params)
	if err := c.stream(http.MethodGet, path, nil, stdout); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func lifecycleSubjectExport(c *client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lifecycle subject-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "subject identifier (required)")
	redact := fs.Bool("redact", false, "redact PII in the bundle")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if strings.TrimSpace(*subject) == "" {
		fmt.Fprintln(stderr, "lifecycle subject-export: --subject is required")
		return 2
	}
	body := map[string]any{"subject": strings.TrimSpace(*subject), "redact": *redact}
	if err := c.stream(http.MethodPost, "/v1/lifecycle/subjects/export", body, stdout); err != nil {
		return fail(stderr, err)
	}
	return 0
}

func lifecycleSubjectErase(cfg Config, c *client, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lifecycle subject-erase", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "subject identifier (required)")
	confirm := fs.String("confirm", "", "must exactly match --subject")
	reason := fs.String("reason", "", "operator reason")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	subj := strings.TrimSpace(*subject)
	if subj == "" {
		fmt.Fprintln(stderr, "lifecycle subject-erase: --subject is required")
		return 2
	}
	if strings.TrimSpace(*confirm) != subj {
		fmt.Fprintln(stderr, "lifecycle subject-erase: --confirm must equal --subject exactly")
		return 2
	}
	body := map[string]any{"subject": subj, "confirm": *confirm, "reason": strings.TrimSpace(*reason)}
	var report any
	if err := c.do(http.MethodPost, "/v1/lifecycle/subjects/erase", body, &report); err != nil {
		return fail(stderr, err)
	}
	return printGeneric(stdout, report, cfg.JSON, http.MethodPost)
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
