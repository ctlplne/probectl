// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"
)

func cmdAPI(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "api: expected <method> <path>")
		return 2
	}
	method := strings.ToUpper(args[0])
	path := args[1]
	return runRawOperation(cfg, apiOp{Method: method, Path: path}, args[2:], stdout, stderr)
}

func cmdSurface(cfg Config, spec surfaceCommand, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" {
		printSurfaceUsage(stderr, spec)
		return 2
	}
	op, ok := spec.Ops[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "%s: unknown subcommand %q\n", spec.Name, args[0])
		printSurfaceUsage(stderr, spec)
		return 2
	}
	return runRawOperation(cfg, op, args[1:], stdout, stderr)
}

func runRawOperation(cfg Config, op apiOp, args []string, stdout, stderr io.Writer) int {
	path := op.Path
	if op.ArgName != "" {
		if len(args) == 0 {
			fmt.Fprintf(stderr, "%s: missing <%s>\n", op.Path, op.ArgName)
			return 2
		}
		path = strings.ReplaceAll(path, "{"+op.ArgName+"}", url.PathEscape(args[0]))
		args = args[1:]
	}

	fs := flag.NewFlagSet(op.Method+" "+op.Path, flag.ContinueOnError)
	fs.SetOutput(stderr)
	bodyRaw := fs.String("body", "", "JSON request body")
	query := kvFlag{}
	fs.Var(&query, "query", "query parameter k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	path = withQuery(path, map[string]string(query))
	body, err := parseBody(*bodyRaw)
	if err != nil {
		fmt.Fprintln(stderr, "invalid --body: "+err.Error())
		return 2
	}
	var out any
	if err := newClient(cfg).do(op.Method, path, body, &out); err != nil {
		return fail(stderr, err)
	}
	return printGeneric(stdout, out, cfg.JSON, op.Method)
}

func parseBody(raw string) (any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func withQuery(path string, params map[string]string) string {
	if len(params) == 0 {
		return path
	}
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q.Set(k, params[k])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func printGeneric(w io.Writer, v any, jsonOut bool, method string) int {
	if v == nil {
		if method == http.MethodDelete {
			fmt.Fprintln(w, "ok")
		}
		return 0
	}
	if jsonOut {
		return printJSON(w, v)
	}
	if m, ok := v.(map[string]any); ok {
		if items, ok := m["items"].([]any); ok {
			printGenericItems(w, items)
			return 0
		}
	}
	return printJSON(w, v)
}

func printGenericItems(w io.Writer, items []any) {
	if len(items) == 0 {
		fmt.Fprintln(w, "No items.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tSUMMARY")
	for _, item := range items {
		m, _ := item.(map[string]any)
		id := firstString(m, "id", "window_id", "answer_id", "name")
		name := firstString(m, "name", "title", "target", "service")
		status := firstString(m, "status", "severity", "state", "confidence")
		summary := firstString(m, "summary", "description", "root_cause", "model")
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", short(id), name, status, summary)
	}
	_ = tw.Flush()
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				return x
			case fmt.Stringer:
				return x.String()
			}
		}
	}
	return ""
}

func printSurfaceUsage(w io.Writer, spec surfaceCommand) {
	fmt.Fprintf(w, "%s — %s\n\n", spec.Name, spec.Summary)
	fmt.Fprintln(w, "Subcommands:")
	names := make([]string, 0, len(spec.Ops))
	for name := range spec.Ops {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		op := spec.Ops[name]
		arg := ""
		if op.ArgName != "" {
			arg = " <" + op.ArgName + ">"
		}
		fmt.Fprintf(w, "  %-18s %s %s\n", name+arg, op.Method, op.Path)
	}
	fmt.Fprintln(w, "\nFlags: --query k=v (repeatable), --body JSON, global --json")
}
