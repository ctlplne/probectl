// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

type cliDispatch struct {
	explicit map[string]string
	cases    map[string]bool
	generic  bool
}

func (v *Validator) validateGenericCLISpine() error {
	path, err := v.resolveWithinRoot("internal/cli/generic.go")
	if err != nil {
		return fmt.Errorf("read generic CLI dispatcher: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fmt.Errorf("parse generic CLI dispatcher: %w", err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		functions[fn.Name.Name] = fn
	}
	cmdSurface := functions["cmdSurface"]
	if cmdSurface == nil || !cliBodyMatches(cmdSurface.Body, cmdSurfaceWrapperSpine) {
		return fmt.Errorf("generic CLI dispatcher: cmdSurface must delegate to the stdin-aware dispatcher with an empty input stream")
	}
	cmdSurfaceWithStdin := functions["cmdSurfaceWithStdin"]
	if cmdSurfaceWithStdin == nil || !cmdSurfaceWithStdinHasExactSpine(cmdSurfaceWithStdin.Body) {
		return fmt.Errorf("generic CLI dispatcher: cmdSurfaceWithStdin must select spec.Ops[args[0]] and directly return runRawOperationWithStdin")
	}
	runRaw := functions["runRawOperation"]
	if runRaw == nil || !cliBodyMatches(runRaw.Body, runRawOperationWrapperSpine) {
		return fmt.Errorf("generic CLI dispatcher: runRawOperation must delegate to the stdin-aware request executor with an empty input stream")
	}
	runRawWithStdin := functions["runRawOperationWithStdin"]
	if runRawWithStdin == nil || !runRawOperationWithStdinExecutesRequest(runRawWithStdin.Body) {
		return fmt.Errorf("generic CLI dispatcher: runRawOperationWithStdin must securely execute the tenant-scoped HTTP client request")
	}
	return nil
}

func cmdSurfaceWithStdinHasExactSpine(body *ast.BlockStmt) bool {
	if len(body.List) != 4 && len(body.List) != 5 {
		return false
	}
	if !isCLIUsageGuard(body.List[0]) {
		return false
	}
	assignment, ok := body.List[1].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return false
	}
	op, opOK := assignment.Lhs[0].(*ast.Ident)
	bound, boundOK := assignment.Lhs[1].(*ast.Ident)
	indexed, indexOK := assignment.Rhs[0].(*ast.IndexExpr)
	if !opOK || !boundOK || !indexOK || op.Name != "op" || bound.Name != "ok" {
		return false
	}
	selector, selectorOK := indexed.X.(*ast.SelectorExpr)
	if !selectorOK || !isIdentifier(selector.X, "spec") || selector.Sel.Name != "Ops" || !isIndexedIdentifier(indexed.Index, "args", 0) {
		return false
	}
	if !isCLIUnknownOperationGuard(body.List[2]) {
		return false
	}
	last := 3
	if len(body.List) == 5 {
		if !isCLIAlertWarning(body.List[3]) {
			return false
		}
		last = 4
	}
	returned, ok := body.List[last].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	call, ok := returned.Results[0].(*ast.CallExpr)
	return ok && isIdentifier(call.Fun, "runRawOperationWithStdin") && len(call.Args) == 6 &&
		isIdentifier(call.Args[0], "cfg") && isIdentifier(call.Args[1], "op") && isArgsTail(call.Args[2]) &&
		isIdentifier(call.Args[3], "stdin") && isIdentifier(call.Args[4], "stdout") && isIdentifier(call.Args[5], "stderr")
}

func isCLIUsageGuard(statement ast.Stmt) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || !cliBlockReturnsCode(conditional.Body, "2") {
		return false
	}
	combined, ok := conditional.Cond.(*ast.BinaryExpr)
	if !ok || combined.Op != token.LOR {
		return false
	}
	return isCLILengthComparison(combined.X, token.EQL, 0) && isCLIArgComparison(combined.Y, token.EQL, "help")
}

func isCLIUnknownOperationGuard(statement ast.Stmt) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || !cliBlockReturnsCode(conditional.Body, "2") {
		return false
	}
	negated, ok := conditional.Cond.(*ast.UnaryExpr)
	return ok && negated.Op == token.NOT && isIdentifier(negated.X, "ok")
}

func isCLIAlertWarning(statement ast.Stmt) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || len(conditional.Body.List) != 1 {
		return false
	}
	comparison, ok := conditional.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return false
	}
	selector, ok := comparison.X.(*ast.SelectorExpr)
	name, nameOK := cliStringLiteral(comparison.Y)
	if !ok || !nameOK || !isIdentifier(selector.X, "spec") || selector.Sel.Name != "Name" || name != "alert" {
		return false
	}
	expression, ok := conditional.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	return ok && isIdentifier(call.Fun, "warnIfAlertingInactive") && len(call.Args) == 2 &&
		isIdentifier(call.Args[0], "cfg") && isIdentifier(call.Args[1], "stderr")
}

func cliBlockReturnsCode(body *ast.BlockStmt, code string) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	returned, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return false
	}
	literal, ok := returned.Results[0].(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == code
}

func isCLILengthComparison(expression ast.Expr, operator token.Token, integer int64) bool {
	comparison, ok := expression.(*ast.BinaryExpr)
	if !ok || comparison.Op != operator || !cliArgsLength(comparison.X) {
		return false
	}
	literal, ok := cliIntegerLiteral(comparison.Y)
	return ok && literal == integer
}

func isCLIArgComparison(expression ast.Expr, operator token.Token, literal string) bool {
	comparison, ok := expression.(*ast.BinaryExpr)
	if !ok || comparison.Op != operator || !isIndexedIdentifier(comparison.X, "args", 0) {
		return false
	}
	value, ok := cliStringLiteral(comparison.Y)
	return ok && value == literal
}

func cliBodyMatches(body *ast.BlockStmt, spine string) bool {
	canonical, ok := canonicalGoBody(body)
	return ok && canonical == spine
}

func runRawOperationWithStdinExecutesRequest(body *ast.BlockStmt) bool {
	return cliBodyMatches(body, runRawOperationWithStdinSpine)
}

func canonicalGoBody(body *ast.BlockStmt) (string, bool) {
	var canonical bytes.Buffer
	if err := format.Node(&canonical, token.NewFileSet(), body); err != nil {
		return "", false
	}
	return canonical.String(), true
}

const cmdSurfaceWrapperSpine = `{
	return cmdSurfaceWithStdin(cfg, spec, args, bytes.NewReader(nil), stdout, stderr)
}`

const runRawOperationWrapperSpine = `{
	return runRawOperationWithStdin(cfg, op, args, bytes.NewReader(nil), stdout, stderr)
}`

const runRawOperationWithStdinSpine = `{
	path := op.Path
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
}`

var customCLIHandlerSpines = map[string]string{
	"lifecycleExport": `{
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
}`,
	"aiAsk": `{
	fs := flag.NewFlagSet("ai ask", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bodyRaw := fs.String("body", "", i18n.T(cfg.Locale, "cli.ai.handoff.body_help", nil))
	handoff := fs.Bool("handoff", false, i18n.T(cfg.Locale, "cli.ai.handoff.flag_help", nil))
	query := queryFlag{}
	fs.Var(&query, "query", i18n.T(cfg.Locale, "cli.ai.handoff.query_help", nil))
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*handoff {
		if len(fs.Args()) > 0 {
			fmt.Fprintf(stderr, "unexpected args: %s\n", strings.Join(fs.Args(), " "))
			return 2
		}
		body, err := parseBody(*bodyRaw)
		if err != nil {
			fmt.Fprintln(stderr, "invalid --body: "+err.Error())
			return 2
		}
		var out any
		if err := newClient(cfg).do(http.MethodPost, withQueryValues("/v1/ai/ask", query), body, &out); err != nil {
			return fail(stderr, err)
		}
		return printGeneric(stdout, out, cfg.JSON, http.MethodPost)
	}
	if cfg.JSON {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.json_conflict", nil))
		return 2
	}
	if len(query) > 0 {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.query_conflict", nil))
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.unexpected", map[string]string{"args": strings.Join(fs.Args(), " ")}))
		return 2
	}
	if strings.TrimSpace(*bodyRaw) == "" {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.body_required", nil))
		return 2
	}
	body, err := parseBody(*bodyRaw)
	if err != nil {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.invalid_body", map[string]string{"error": err.Error()}))
		return 2
	}
	request, ok := body.(map[string]any)
	if !ok {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.object_required", nil))
		return 2
	}
	question, ok := request["question"].(string)
	if !ok || strings.TrimSpace(question) == "" {
		fmt.Fprintln(stderr, i18n.T(cfg.Locale, "cli.ai.handoff.question_required", nil))
		return 2
	}
	var answer ai.Answer
	if err := newClient(cfg).do(http.MethodPost, "/v1/ai/ask", request, &answer); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprint(stdout, ai.RenderHandoff(answer, cfg.Locale))
	return 0
}`,
}

func (v *Validator) loadExplicitCLIOperations(handlers map[string]string, commands []string) (map[string]map[string]bool, error) {
	const relativeDir = "internal/cli"
	directory, err := v.resolveWithinRoot(relativeDir)
	if err != nil {
		return nil, fmt.Errorf("read CLI handlers: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read CLI handlers: %w", err)
	}
	functions := map[string][]*ast.FuncDecl{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path, err := v.resolveWithinRoot(filepath.ToSlash(filepath.Join(relativeDir, entry.Name())))
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse CLI handler %q: %w", entry.Name(), err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			functions[fn.Name.Name] = append(functions[fn.Name.Name], fn)
		}
	}
	out := map[string]map[string]bool{}
	callable := map[string]bool{}
	for name, definitions := range functions {
		callable[name] = len(definitions) == 1 && customCLIHandlerExecutesRequest(name, definitions[0].Body)
	}
	for group, handler := range handlers {
		definitions := functions[handler]
		if len(definitions) != 1 {
			return nil, fmt.Errorf("parse CLI handlers: %s needs one implementation for explicit group %q", handler, group)
		}
		handlerCallable := cloneCLIBindings(callable)
		localBindings := cliLocallyBoundIdentifiers(definitions[0].Body)
		for name := range localBindings {
			delete(handlerCallable, name)
		}
		out[group] = map[string]bool{}
		for _, command := range commands {
			fields := strings.Fields(command)
			if len(fields) < 3 || fields[0] != "probectl" || fields[1] != group {
				continue
			}
			operation := fields[2]
			if localBindings["cmdSurface"] {
				out[group][operation] = false
				continue
			}
			out[group][operation] = cliOperationRoutes(definitions[0].Body.List, group, operation, map[string]bool{}, map[string]bool{}, map[string]bool{}, handlerCallable)
		}
	}
	return out, nil
}

func customCLIHandlerExecutesRequest(name string, body *ast.BlockStmt) bool {
	want, ok := customCLIHandlerSpines[name]
	if !ok {
		return false
	}
	got, ok := canonicalGoBody(body)
	return ok && got == want
}

// cliOperationRoutes symbolically follows one exact subcommand through an
// explicit handler. A group-level fallback check is not enough: an earlier
// branch can shadow one advertised operation while every sibling stays live.
func cliOperationRoutes(statements []ast.Stmt, group, operation string, bindings, clients, aliases, callable map[string]bool) bool {
	for index, statement := range statements {
		rest := statements[index+1:]
		switch value := statement.(type) {
		case *ast.AssignStmt:
			if cliAssignmentMutatesProtected(value, bindings, clients, aliases) {
				return false
			}
			if len(value.Lhs) == 1 && len(value.Rhs) == 1 {
				identifier, ok := value.Lhs[0].(*ast.Ident)
				if ok {
					if cliExpressionAliasesProtected(value.Rhs[0], bindings, clients, aliases) {
						aliases[identifier.Name] = true
					} else {
						delete(aliases, identifier.Name)
					}
					if isSurfaceGroupIndex(value.Rhs[0], group) {
						bindings[identifier.Name] = true
					} else {
						delete(bindings, identifier.Name)
					}
					if isNewClientWithConfig(value.Rhs[0]) {
						clients[identifier.Name] = true
					} else {
						delete(clients, identifier.Name)
					}
				}
			}
		case *ast.DeclStmt:
			if cliDeclarationBindsIdentifier(value, "args") || cliDeclarationBindsIdentifier(value, "surfaceCommands") {
				return false
			}
			continue
		case *ast.EmptyStmt:
			continue
		case *ast.ExprStmt, *ast.IncDecStmt:
			// An unmodelled side effect (for example clear(args)) can rewrite
			// the operation before the proved delegate. Fail closed.
			return false
		case *ast.ReturnStmt:
			return cliReturnRoutesOperation(value, group, operation, bindings, clients, callable)
		case *ast.IfStmt:
			switch evaluateCLIOperationCondition(value.Cond, operation) {
			case cliConditionTrue:
				return cliOperationRoutes(joinCLIStatements(value.Body.List, rest), group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable)
			case cliConditionFalse:
				if value.Else == nil {
					continue
				}
				return cliOperationRoutes(joinCLIStatements(cliElseStatements(value.Else), rest), group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable)
			default:
				truePath := joinCLIStatements(value.Body.List, rest)
				falsePath := rest
				if value.Else != nil {
					falsePath = joinCLIStatements(cliElseStatements(value.Else), rest)
				}
				return cliOperationRoutes(truePath, group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable) &&
					cliOperationRoutes(falsePath, group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable)
			}
		case *ast.SwitchStmt:
			if value.Init != nil || !isIndexedIdentifier(value.Tag, "args", 0) {
				return false
			}
			var selected []ast.Stmt
			matched := false
			for _, rawClause := range value.Body.List {
				clause, ok := rawClause.(*ast.CaseClause)
				if !ok {
					return false
				}
				if len(clause.List) == 0 {
					if !matched {
						selected = clause.Body
					}
					continue
				}
				for _, expression := range clause.List {
					literal, ok := expression.(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						return false
					}
					candidate, err := strconv.Unquote(literal.Value)
					if err != nil {
						return false
					}
					if candidate == operation {
						selected = clause.Body
						matched = true
					}
				}
			}
			return cliOperationRoutes(joinCLIStatements(selected, rest), group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable)
		case *ast.BlockStmt:
			return cliOperationRoutes(joinCLIStatements(value.List, rest), group, operation, cloneCLIBindings(bindings), cloneCLIBindings(clients), cloneCLIBindings(aliases), callable)
		default:
			return false
		}
	}
	return false
}

func cliReturnRoutesOperation(statement *ast.ReturnStmt, group, operation string, bindings, clients, callable map[string]bool) bool {
	if len(statement.Results) != 1 {
		return false
	}
	call, ok := statement.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	if isSurfaceFallbackCall(call, group, bindings) {
		return true
	}
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || !callable[identifier.Name] || !cliCustomHandlerMatches(identifier.Name, group, operation) {
		return false
	}
	if identifier.Name == "aiAsk" {
		return len(call.Args) == 4 && isIdentifier(call.Args[0], "cfg") && isArgsTail(call.Args[1]) &&
			isIdentifier(call.Args[2], "stdout") && isIdentifier(call.Args[3], "stderr")
	}
	if identifier.Name == "lifecycleExport" {
		if len(call.Args) != 4 {
			return false
		}
		client, ok := call.Args[0].(*ast.Ident)
		return ok && clients[client.Name] && isArgsTail(call.Args[1]) &&
			isIdentifier(call.Args[2], "stdout") && isIdentifier(call.Args[3], "stderr")
	}
	return false
}

func isNewClientWithConfig(expression ast.Expr) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok && isIdentifier(call.Fun, "newClient") && len(call.Args) == 1 && isIdentifier(call.Args[0], "cfg")
}

func cliLocallyBoundIdentifiers(body *ast.BlockStmt) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for _, expression := range value.Lhs {
				if identifier, ok := expression.(*ast.Ident); ok {
					out[identifier.Name] = true
				}
			}
		case *ast.ValueSpec:
			for _, identifier := range value.Names {
				out[identifier.Name] = true
			}
		case *ast.RangeStmt:
			for _, expression := range []ast.Expr{value.Key, value.Value} {
				if identifier, ok := expression.(*ast.Ident); ok {
					out[identifier.Name] = true
				}
			}
		}
		return true
	})
	return out
}

func cliCustomHandlerMatches(handler, group, operation string) bool {
	normalize := func(value string) string {
		var out strings.Builder
		for _, r := range value {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				out.WriteRune(unicode.ToLower(r))
			}
		}
		return out.String()
	}
	want := normalize(group + operation)
	got := normalize(strings.TrimPrefix(handler, "cmd"))
	return got == want
}

func isArgsTail(expression ast.Expr) bool {
	slice, ok := expression.(*ast.SliceExpr)
	if !ok || slice.High != nil || slice.Max != nil || !isIdentifier(slice.X, "args") {
		return false
	}
	literal, ok := slice.Low.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == "1"
}

type cliCondition uint8

const (
	cliConditionUnknown cliCondition = iota
	cliConditionFalse
	cliConditionTrue
)

func evaluateCLIOperationCondition(expression ast.Expr, operation string) cliCondition {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return evaluateCLIOperationCondition(value.X, operation)
	case *ast.Ident:
		if value.Name == "true" {
			return cliConditionTrue
		}
		if value.Name == "false" {
			return cliConditionFalse
		}
	case *ast.UnaryExpr:
		if value.Op == token.NOT {
			return invertCLICondition(evaluateCLIOperationCondition(value.X, operation))
		}
	case *ast.BinaryExpr:
		if value.Op == token.LAND || value.Op == token.LOR {
			left := evaluateCLIOperationCondition(value.X, operation)
			right := evaluateCLIOperationCondition(value.Y, operation)
			if value.Op == token.LAND {
				if left == cliConditionFalse || right == cliConditionFalse {
					return cliConditionFalse
				}
				if left == cliConditionTrue && right == cliConditionTrue {
					return cliConditionTrue
				}
				return cliConditionUnknown
			}
			if left == cliConditionTrue || right == cliConditionTrue {
				return cliConditionTrue
			}
			if left == cliConditionFalse && right == cliConditionFalse {
				return cliConditionFalse
			}
			return cliConditionUnknown
		}
		if isIndexedIdentifier(value.X, "args", 0) {
			if literal, ok := cliStringLiteral(value.Y); ok {
				return evaluateCLIStringComparison(operation, literal, value.Op)
			}
		}
		if isIndexedIdentifier(value.Y, "args", 0) {
			if literal, ok := cliStringLiteral(value.X); ok {
				return evaluateCLIStringComparison(literal, operation, value.Op)
			}
		}
		if cliArgsLength(value.X) {
			if literal, ok := cliIntegerLiteral(value.Y); ok {
				return evaluateCLIIntegerComparison(1, literal, value.Op)
			}
		}
		if cliArgsLength(value.Y) {
			if literal, ok := cliIntegerLiteral(value.X); ok {
				return evaluateCLIIntegerComparison(literal, 1, value.Op)
			}
		}
	}
	return cliConditionUnknown
}

func cliStringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func cliArgsLength(expression ast.Expr) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok && isIdentifier(call.Fun, "len") && len(call.Args) == 1 && isIdentifier(call.Args[0], "args")
}

func cliIntegerLiteral(expression ast.Expr) (int64, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.ParseInt(literal.Value, 0, 64)
	return value, err == nil
}

func evaluateCLIStringComparison(left, right string, operator token.Token) cliCondition {
	equal := left == right
	if operator == token.EQL && equal || operator == token.NEQ && !equal {
		return cliConditionTrue
	}
	if operator == token.EQL || operator == token.NEQ {
		return cliConditionFalse
	}
	return cliConditionUnknown
}

func evaluateCLIIntegerComparison(left, right int64, operator token.Token) cliCondition {
	var result bool
	switch operator {
	case token.EQL:
		result = left == right
	case token.NEQ:
		result = left != right
	case token.LSS:
		result = left < right
	case token.LEQ:
		result = left <= right
	case token.GTR:
		result = left > right
	case token.GEQ:
		result = left >= right
	default:
		return cliConditionUnknown
	}
	if result {
		return cliConditionTrue
	}
	return cliConditionFalse
}

func invertCLICondition(condition cliCondition) cliCondition {
	if condition == cliConditionTrue {
		return cliConditionFalse
	}
	if condition == cliConditionFalse {
		return cliConditionTrue
	}
	return cliConditionUnknown
}

func cliElseStatements(statement ast.Stmt) []ast.Stmt {
	switch value := statement.(type) {
	case *ast.BlockStmt:
		return value.List
	case *ast.IfStmt:
		return []ast.Stmt{value}
	default:
		return nil
	}
}

func joinCLIStatements(first, second []ast.Stmt) []ast.Stmt {
	out := make([]ast.Stmt, 0, len(first)+len(second))
	out = append(out, first...)
	out = append(out, second...)
	return out
}

func cloneCLIBindings(bindings map[string]bool) map[string]bool {
	out := make(map[string]bool, len(bindings))
	for name, value := range bindings {
		out[name] = value
	}
	return out
}

func cliAssignmentMutatesProtected(assignment *ast.AssignStmt, bindings, clients, aliases map[string]bool) bool {
	for _, expression := range assignment.Lhs {
		root := cliAssignmentRootIdentifier(expression)
		if cliCoreProtectedIdentifier(root) || bindings[root] || clients[root] || aliases[root] {
			return true
		}
	}
	return false
}

func cliExpressionAliasesProtected(expression ast.Expr, bindings, clients, aliases map[string]bool) bool {
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return cliExpressionAliasesProtected(value.X, bindings, clients, aliases)
	case *ast.Ident:
		return cliCoreProtectedIdentifier(value.Name) || bindings[value.Name] || clients[value.Name] || aliases[value.Name]
	case *ast.SliceExpr:
		root := cliAssignmentRootIdentifier(value.X)
		return cliCoreProtectedIdentifier(root) || bindings[root] || clients[root] || aliases[root]
	case *ast.IndexExpr:
		root := cliAssignmentRootIdentifier(value.X)
		// A string selected from args is copied, but a value selected from a
		// protected map or composite binding can retain map/slice/pointer state.
		return root != "args" && (cliCoreProtectedIdentifier(root) || bindings[root] || clients[root] || aliases[root])
	case *ast.SelectorExpr, *ast.StarExpr:
		root := cliAssignmentRootIdentifier(expression)
		return cliCoreProtectedIdentifier(root) || bindings[root] || clients[root] || aliases[root]
	case *ast.UnaryExpr:
		if value.Op != token.AND {
			return false
		}
		root := cliAssignmentRootIdentifier(value.X)
		return cliCoreProtectedIdentifier(root) || bindings[root] || clients[root] || aliases[root]
	case *ast.CallExpr:
		if !isIdentifier(value.Fun, "append") || len(value.Args) == 0 {
			return false
		}
		return cliExpressionAliasesProtected(value.Args[0], bindings, clients, aliases)
	default:
		return false
	}
}

func cliCoreProtectedIdentifier(name string) bool {
	switch name {
	case "cfg", "args", "stdout", "stderr", "surfaceCommands":
		return true
	default:
		return false
	}
}

func cliAssignmentRootIdentifier(expression ast.Expr) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.IndexExpr:
		return cliAssignmentRootIdentifier(value.X)
	case *ast.SliceExpr:
		return cliAssignmentRootIdentifier(value.X)
	case *ast.SelectorExpr:
		return cliAssignmentRootIdentifier(value.X)
	case *ast.StarExpr:
		return cliAssignmentRootIdentifier(value.X)
	case *ast.ParenExpr:
		return cliAssignmentRootIdentifier(value.X)
	default:
		return ""
	}
}

func cliDeclarationBindsIdentifier(declaration *ast.DeclStmt, identifier string) bool {
	general, ok := declaration.Decl.(*ast.GenDecl)
	if !ok {
		return false
	}
	for _, rawSpec := range general.Specs {
		spec, ok := rawSpec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range spec.Names {
			if name.Name == identifier {
				return true
			}
		}
	}
	return false
}

func isSurfaceFallbackCall(call *ast.CallExpr, group string, bindings map[string]bool) bool {
	if !isIdentifier(call.Fun, "cmdSurface") || len(call.Args) != 5 ||
		!isIdentifier(call.Args[0], "cfg") || !isIdentifier(call.Args[2], "args") ||
		!isIdentifier(call.Args[3], "stdout") || !isIdentifier(call.Args[4], "stderr") {
		return false
	}
	if isSurfaceGroupIndex(call.Args[1], group) {
		return true
	}
	identifier, ok := call.Args[1].(*ast.Ident)
	return ok && bindings[identifier.Name]
}

func isSurfaceGroupIndex(expression ast.Expr, group string) bool {
	indexed, ok := expression.(*ast.IndexExpr)
	if !ok || !isIdentifier(indexed.X, "surfaceCommands") {
		return false
	}
	literal, ok := indexed.Index.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == group
}

// loadCLIDispatch proves that catalog entries have a route through the actual
// top-level CLI dispatcher. The catalog is data-driven, so validating the map
// alone would otherwise keep passing after RunWithStdin stopped invoking it.
func (v *Validator) loadCLIDispatch() (cliDispatch, error) {
	const relative = "internal/cli/cli.go"
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return cliDispatch{}, fmt.Errorf("read CLI top-level dispatcher: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: %w", err)
	}

	var runWithStdin *ast.FuncDecl
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "RunWithStdin" || fn.Recv != nil || fn.Body == nil {
			continue
		}
		if runWithStdin != nil {
			return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: RunWithStdin is declared more than once")
		}
		runWithStdin = fn
	}
	if runWithStdin == nil {
		return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: RunWithStdin is missing")
	}

	statements := runWithStdin.Body.List
	if len(statements) < 3 || !isCLIRestAssignment(statements[len(statements)-3]) || !isCLIEmptyCommandGuard(statements[len(statements)-2]) {
		return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: exact rest := fs.Args(), empty-command guard, switch tail is missing")
	}
	prelude, preludeOK := canonicalGoStatements(statements[:len(statements)-3])
	if !preludeOK || prelude != cliRunPreludeSpine {
		return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: command prelude does not preserve the trusted config and flag-parser spine")
	}
	commandSwitch, ok := statements[len(statements)-1].(*ast.SwitchStmt)
	if !ok || !isIndexedIdentifier(commandSwitch.Tag, "rest", 0) {
		return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher: unique final switch on rest[0] is missing")
	}

	dispatch := cliDispatch{explicit: map[string]string{}, cases: map[string]bool{}}
	for _, rawClause := range commandSwitch.Body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok {
			continue
		}
		if len(clause.List) == 0 {
			dispatch.generic = hasGenericSurfaceDispatch(clause.Body)
			continue
		}
		for _, expression := range clause.List {
			literal, ok := expression.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			group, err := strconv.Unquote(literal.Value)
			if err != nil {
				return cliDispatch{}, fmt.Errorf("parse CLI top-level dispatcher case: %w", err)
			}
			dispatch.cases[group] = true
			handler := returnedCLIHandler(clause.Body)
			if handlerMatchesCLIGroup(handler, group) {
				dispatch.explicit[group] = handler
			}
		}
	}
	return dispatch, nil
}

func canonicalGoStatements(statements []ast.Stmt) (string, bool) {
	return canonicalGoBody(&ast.BlockStmt{List: statements})
}

const cliRunPreludeSpine = `{
	cfg := Config{BaseURL: envOr(getenv, "PROBECTL_API_URL", "https://localhost:8443"), Token: getenv("PROBECTL_API_TOKEN"), Tenant: getenv("PROBECTL_TENANT"), Locale: i18n.Resolve(getenv("PROBECTL_LOCALE")), SessionCookieFile: getenv("PROBECTL_SESSION_COOKIE_FILE")}
	args, cfg.JSON = extractBoolFlag(args, "--json")
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		usage(stdout, cfg.Locale)
		return 0
	}
	fs := flag.NewFlagSet("probectl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		usage(stderr, cfg.Locale)
	}
	fs.StringVar(&cfg.BaseURL, "url", cfg.BaseURL, "control-plane API base URL (env PROBECTL_API_URL)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "API auth token, sent as Bearer (env PROBECTL_API_TOKEN)")
	fs.StringVar(&cfg.Tenant, "tenant", cfg.Tenant, "tenant UUID, sent as X-Probectl-Tenant (env PROBECTL_TENANT)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
}`

func isCLIRestAssignment(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || !isIdentifier(assignment.Lhs[0], "rest") {
		return false
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && isIdentifier(selector.X, "fs") && selector.Sel.Name == "Args"
}

func isCLIEmptyCommandGuard(statement ast.Stmt) bool {
	conditional, ok := statement.(*ast.IfStmt)
	if !ok || conditional.Init != nil || conditional.Else != nil || !cliBlockReturnsCode(conditional.Body, "2") {
		return false
	}
	comparison, ok := conditional.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return false
	}
	call, ok := comparison.X.(*ast.CallExpr)
	if !ok || !isIdentifier(call.Fun, "len") || len(call.Args) != 1 || !isIdentifier(call.Args[0], "rest") {
		return false
	}
	literal, ok := cliIntegerLiteral(comparison.Y)
	return ok && literal == 0
}

func returnedCLIHandler(statements []ast.Stmt) string {
	if len(statements) != 1 {
		return ""
	}
	returned, ok := statements[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		return ""
	}
	call, ok := returned.Results[0].(*ast.CallExpr)
	if !ok || len(call.Args) < 2 || !isIdentifier(call.Args[0], "cfg") || !isRestTail(call.Args[1]) {
		return ""
	}
	fn, ok := call.Fun.(*ast.Ident)
	if ok && strings.HasPrefix(fn.Name, "cmd") {
		return fn.Name
	}
	return ""
}

func handlerMatchesCLIGroup(handler, group string) bool {
	if !strings.HasPrefix(handler, "cmd") {
		return false
	}
	normalize := func(value string) string {
		var out strings.Builder
		for _, r := range value {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				out.WriteRune(unicode.ToLower(r))
			}
		}
		return out.String()
	}
	return normalize(strings.TrimPrefix(handler, "cmd")) == normalize(group)
}

func hasGenericSurfaceDispatch(statements []ast.Stmt) bool {
	if len(statements) == 0 {
		return false
	}
	conditional, ok := statements[0].(*ast.IfStmt)
	if !ok || conditional.Else != nil {
		return false
	}
	assignment, ok := conditional.Init.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 2 || len(assignment.Rhs) != 1 {
		return false
	}
	spec, specOK := assignment.Lhs[0].(*ast.Ident)
	boundOK, okOK := assignment.Lhs[1].(*ast.Ident)
	indexed, indexOK := assignment.Rhs[0].(*ast.IndexExpr)
	if !specOK || !okOK || !indexOK || spec.Name == "_" || boundOK.Name == "_" ||
		!isIdentifier(indexed.X, "surfaceCommands") || !isIndexedIdentifier(indexed.Index, "rest", 0) {
		return false
	}
	if !isIdentifier(conditional.Cond, boundOK.Name) {
		return false
	}
	if len(conditional.Body.List) != 1 {
		return false
	}
	for _, bodyStatement := range conditional.Body.List {
		returned, ok := bodyStatement.(*ast.ReturnStmt)
		if !ok || len(returned.Results) != 1 {
			continue
		}
		call, ok := returned.Results[0].(*ast.CallExpr)
		if !ok || !isIdentifier(call.Fun, "cmdSurfaceWithStdin") || len(call.Args) != 6 {
			continue
		}
		if isIdentifier(call.Args[0], "cfg") && isIdentifier(call.Args[1], spec.Name) &&
			isRestTail(call.Args[2]) && isIdentifier(call.Args[3], "stdin") &&
			isIdentifier(call.Args[4], "stdout") && isIdentifier(call.Args[5], "stderr") {
			return true
		}
	}
	return false
}

func isRestTail(expression ast.Expr) bool {
	slice, ok := expression.(*ast.SliceExpr)
	if !ok || slice.High != nil || slice.Max != nil || !isIdentifier(slice.X, "rest") {
		return false
	}
	literal, ok := slice.Low.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == "1"
}

func isIndexedIdentifier(expression ast.Expr, identifier string, index int) bool {
	indexed, ok := expression.(*ast.IndexExpr)
	if !ok || !isIdentifier(indexed.X, identifier) {
		return false
	}
	literal, ok := indexed.Index.(*ast.BasicLit)
	return ok && literal.Kind == token.INT && literal.Value == fmt.Sprintf("%d", index)
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}
