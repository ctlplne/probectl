// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/ctlplne/probectl/internal/httpbody"
)

const maxSensitiveRequestBodyBytes int64 = 1 << 20

func cmdAPIWithStdin(cfg Config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "api: expected <method> <path>")
		return 2
	}
	method := strings.ToUpper(args[0])
	path := args[1]
	op := apiOp{Method: method, Path: path}
	if providerOp, ok := sensitiveProviderOperation(method, cfg.BaseURL, path); ok {
		op.SensitiveBody = providerOp.SensitiveBody
	}
	return runRawOperationWithStdin(cfg, op, args[2:], stdin, stdout, stderr)
}

func cmdSurface(cfg Config, spec surfaceCommand, args []string, stdout, stderr io.Writer) int {
	return cmdSurfaceWithStdin(cfg, spec, args, bytes.NewReader(nil), stdout, stderr)
}

func cmdSurfaceWithStdin(cfg Config, spec surfaceCommand, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	if spec.Name == "alert" {
		warnIfAlertingInactive(cfg, stderr)
	}
	return runRawOperationWithStdin(cfg, op, args[1:], stdin, stdout, stderr)
}

func sensitiveProviderOperation(method, baseURL, requestTarget string) (apiOp, bool) {
	if operation, ok := sensitiveProviderOperationPath(method, requestTarget); ok {
		return operation, true
	}
	target, err := composeAPIURL(baseURL, requestTarget)
	if err != nil {
		return apiOp{}, false
	}
	return sensitiveProviderOperationURL(method, target)
}

func sensitiveProviderOperationURL(method string, target *url.URL) (apiOp, bool) {
	if target == nil {
		return apiOp{}, false
	}
	return sensitiveProviderOperationPath(method, target.Path)
}

func sensitiveProviderOperationPath(method, path string) (apiOp, bool) {
	// The generic client appends paths to its configured origin. Treat a
	// network-path-looking spelling (//provider/...) as the same origin-relative
	// route before classification; otherwise net/url interprets "provider" as a
	// host and an argv body could bypass the credential-bearing operation rule.
	// The HTTP request path may still be normalized by a server or proxy later,
	// so the stricter classification has to happen here, before reading --body.
	if strings.HasPrefix(path, "//") {
		path = "/" + strings.TrimLeft(path, "/")
	}
	parsed, err := url.Parse(path)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return apiOp{}, false
	}
	// URL.Path is percent-decoded by net/url. Make every origin-relative
	// spelling root-relative before cleaning it: when BaseURL ends in '/', a raw
	// path such as "provider/v1/auth/login" or "../provider/v1/auth/login"
	// concatenates into the protected route even though it omitted the leading
	// slash. Classify that spelling conservatively before any argv body is read.
	canonicalPath := pathpkg.Clean("/" + strings.TrimLeft(parsed.Path, "/"))
	for _, op := range surfaceCommands["provider"].Ops {
		if op.SensitiveBody && strings.EqualFold(op.Method, method) && op.Path == canonicalPath {
			return op, true
		}
	}
	return apiOp{}, false
}

// warnIfAlertingInactive makes every alert-group command honest about an inert
// evaluator. The status probe is read-only and tenant-scoped. Failure to read
// status does not block the requested operation, and warnings stay on stderr so
// --json stdout remains machine-parseable.
func warnIfAlertingInactive(cfg Config, stderr io.Writer) {
	var status struct {
		AlertingActive *bool  `json:"alerting_active"`
		Warning        string `json:"warning"`
	}
	if err := newClient(cfg).do(http.MethodGet, "/v1/alerts", nil, &status); err != nil || status.AlertingActive == nil || *status.AlertingActive {
		return
	}
	message := strings.TrimSpace(status.Warning)
	if message == "" {
		message = "ALERTING INACTIVE: stored rules are not evaluated; configure a query-capable TSDB backend (see docs/alerting.md#evaluation-loop)"
	}
	fmt.Fprintln(stderr, "WARNING: "+message)
}

func runRawOperation(cfg Config, op apiOp, args []string, stdout, stderr io.Writer) int {
	return runRawOperationWithStdin(cfg, op, args, bytes.NewReader(nil), stdout, stderr)
}

func runRawOperationWithStdin(cfg Config, op apiOp, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	path := op.Path
	// ArgName names the positional path parameters in order ("id" or
	// "id,role"); each consumes one leading argument (DPR-027).
	for _, name := range op.argNames() {
		if len(args) == 0 {
			fmt.Fprintf(stderr, "%s: missing <%s>\n", op.Path, name)
			return 2
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(args[0]))
		args = args[1:]
	}

	fs := flag.NewFlagSet(op.Method+" "+op.Path, flag.ContinueOnError)
	fs.SetOutput(stderr)
	bodyRaw := fs.String("body", "", "JSON request body")
	bodyFile := fs.String("body-file", "", "JSON request body path; - reads stdin (sensitive bodies require a 0600 file or stdin)")
	query := queryFlag{}
	fs.Var(&query, "query", "query parameter k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	var bodySet, bodyFileSet bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "body":
			bodySet = true
		case "body-file":
			bodyFileSet = true
		}
	})
	if bodySet && bodyFileSet {
		fmt.Fprintln(stderr, "--body and --body-file cannot be combined")
		return 2
	}
	if op.SensitiveBody {
		if bodySet {
			fmt.Fprintln(stderr, "credential-bearing request refuses --body; use --body-file <0600-file|->")
			return 2
		}
		if !bodyFileSet || strings.TrimSpace(*bodyFile) == "" {
			fmt.Fprintln(stderr, "credential-bearing request requires --body-file <0600-file|->")
			return 2
		}
	}
	path = withQueryValues(path, query)
	// Resolve and enforce the transport/origin policy before reading any request
	// body. This keeps credentials out of memory when the target is malformed,
	// changes authority, or would use plaintext transport off loopback.
	if _, err := resolveAPIURL(cfg.BaseURL, path); err != nil {
		fmt.Fprintln(stderr, "API request target is unsafe: "+err.Error())
		return 2
	}
	var (
		body any
		err  error
	)
	if bodyFileSet {
		body, err = readSensitiveRequestBody(*bodyFile, stdin)
	} else {
		body, err = parseBody(*bodyRaw)
	}
	if err != nil {
		label := "--body"
		if bodyFileSet {
			label = "--body-file"
		}
		fmt.Fprintln(stderr, "invalid "+label+": "+err.Error())
		return 2
	}
	var out any
	if err := newClient(cfg).do(op.Method, path, body, &out); err != nil {
		return fail(stderr, err)
	}
	return printGenericColumns(stdout, out, cfg.JSON, op.Method, op.Columns)
}

func readSensitiveRequestBody(filename string, stdin io.Reader) (any, error) {
	var (
		raw []byte
		err error
	)
	if filename == "-" {
		if stdin == nil {
			return nil, fmt.Errorf("stdin is unavailable")
		}
		raw, err = httpbody.ReadLimited(stdin, maxSensitiveRequestBodyBytes)
		if err != nil {
			if err == httpbody.ErrTooLarge {
				return nil, fmt.Errorf("stdin exceeds %d-byte limit", maxSensitiveRequestBodyBytes)
			}
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	} else {
		if strings.TrimSpace(filename) == "" {
			return nil, fmt.Errorf("path is required")
		}
		raw, err = readOwnerOnlyCLIFile(filename, maxSensitiveRequestBodyBytes)
		if err != nil {
			return nil, err
		}
	}
	defer clearBytes(raw)
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("request body is empty")
	}
	var body any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	if _, ok := body.(map[string]any); !ok {
		return nil, fmt.Errorf("request body must be one JSON object")
	}
	return body, nil
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

// queryFlag preserves repeated keys. Flow exploration uses repeated
// filter=field:value values, so collapsing --query into a map would silently
// discard every chip except the last one.
type queryFlag map[string][]string

func (q *queryFlag) String() string { return "" }

func (q *queryFlag) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("expected k=v, got %q", v)
	}
	if *q == nil {
		*q = queryFlag{}
	}
	key := v[:i]
	(*q)[key] = append((*q)[key], v[i+1:])
	return nil
}

func withQueryValues(path string, params queryFlag) string {
	if len(params) == 0 {
		return path
	}
	u, err := url.Parse(path)
	if err != nil {
		return path
	}
	q := u.Query()
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range params[key] {
			q.Add(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func printGeneric(w io.Writer, v any, jsonOut bool, method string) int {
	return printGenericColumns(w, v, jsonOut, method, nil)
}

// printGenericColumns renders a collection with the operation's declared
// columns (DPR-040) or, without any, the generic ID/NAME/STATUS/SUMMARY table.
func printGenericColumns(w io.Writer, v any, jsonOut bool, method string, columns []string) int {
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
			if len(columns) > 0 {
				printColumnItems(w, items, columns)
			} else {
				printGenericItems(w, items)
			}
			return 0
		}
	}
	return printJSON(w, v)
}

// printColumnItems prints one row per item with exactly the declared keys;
// nested values are JSON so nothing is silently dropped.
func printColumnItems(w io.Writer, items []any, columns []string) {
	if len(items) == 0 {
		fmt.Fprintln(w, "No items.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	headers := make([]string, len(columns))
	for i, c := range columns {
		headers[i] = strings.ToUpper(strings.TrimSuffix(c, "_at"))
	}
	fmt.Fprintln(tw, strings.Join(headers, "\t"))
	for _, item := range items {
		m, _ := item.(map[string]any)
		cells := make([]string, len(columns))
		for i, c := range columns {
			cells[i] = cellString(m[c])
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	_ = tw.Flush()
}

func cellString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
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
		id, name, status, summary := genericDisplayFields(m)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", short(id), name, status, summary)
	}
	_ = tw.Flush()
}

func genericDisplayFields(m map[string]any) (id, name, status, summary string) {
	// Flow aggregates expose observation multiplicity explicitly. It is a
	// distinct count of tenant-local exporter identities, never a claim that
	// packets or conversations were deduplicated.
	if observation := flowExporterObservation(m); observation != "" {
		id = firstString(m, "key")
		name = strings.Join(nonEmptyStrings(id, firstString(m, "detail")), " -> ")
		summary = observation
		return id, name, status, summary
	}
	// Flow quality receipts use exporter + protocol as their tenant-local
	// identity. Keep the allowlisted reason and safe action visible without
	// inventing a synthetic ID or exposing any decoded flow field.
	if exporter := firstString(m, "exporter_address"); exporter != "" {
		id = firstString(m, "agent_id")
		name = strings.Join(nonEmptyStrings(firstString(m, "agent_id"), exporter), " @ ")
		status = firstString(m, "state")
		summary = strings.Join(nonEmptyStrings(
			firstString(m, "protocol"),
			firstString(m, "reason"),
			firstString(m, "next_action"),
		), " / ")
		return id, name, status, summary
	}
	// Collection outcomes deliberately have no synthetic global ID: their
	// tenant-local identity is agent + configured target + protocol. Preserve
	// that evidence in the human table without changing the stable JSON shape.
	if target := firstString(m, "configured_target"); target != "" {
		id = firstString(m, "agent_id")
		name = target
		status = firstString(m, "state")
		summary = strings.Join(nonEmptyStrings(
			firstString(m, "protocol"),
			firstString(m, "reason"),
			firstString(m, "next_action"),
		), " / ")
		return id, name, status, summary
	}
	id = firstString(m, "id", "window_id", "answer_id", "name")
	name = firstString(m, "name", "title", "target", "service")
	status = firstString(m, "status", "severity", "state", "confidence")
	summary = firstString(m, "summary", "description", "root_cause", "model")
	return id, name, status, summary
}

func flowExporterObservation(m map[string]any) string {
	value, ok := m["exporter_count"]
	if !ok {
		return ""
	}
	var count uint64
	switch n := value.(type) {
	case float64:
		if n < 0 {
			return ""
		}
		count = uint64(n)
	case int:
		if n < 0 {
			return ""
		}
		count = uint64(n)
	case uint64:
		count = n
	default:
		return ""
	}
	if count == 0 {
		return "exporter identity unavailable"
	}
	noun := "exporters"
	if count == 1 {
		noun = "exporter"
	}
	return fmt.Sprintf("observed by %d %s", count, noun)
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
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
		for _, name := range op.argNames() {
			arg += " <" + name + ">"
		}
		fmt.Fprintf(w, "  %-18s %s %s\n", name+arg, op.Method, op.Path)
	}
	fmt.Fprintln(w, "\nFlags: --query k=v (repeatable), --body JSON, global --json")
	for _, op := range spec.Ops {
		if op.SensitiveBody {
			fmt.Fprintln(w, "Credential-bearing operations require --body-file <0600-file|->; inline --body is refused. Stdin is preserved on this secure path.")
			break
		}
	}
}
