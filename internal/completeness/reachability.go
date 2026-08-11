// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	topLevelSymbolPrefix = "func:"
	methodSymbolPrefix   = "method:"
)

// parserObject is used only for identity links produced by go/parser inside a
// single file. Package-crossing facts are resolved separately and unknown
// bindings stay live; this avoids treating parser object links as type facts.
//
//nolint:staticcheck // go/parser still exposes ast.Object for this bounded identity use.
type parserObject = ast.Object

type parsedReachabilityFile struct {
	relative        string
	withoutComments []byte
	set             *token.FileSet
	file            *ast.File
}

type reachableFunction struct {
	file        string
	references  map[string]bool
	calls       []executableCall
	assignments []string
	composites  []string
	protocols   map[string]bool
}

type executableCall struct {
	callee string
	code   string
}

type packageReachability struct {
	functions map[string][]reachableFunction
	reachable map[string]bool
}

func (v *Validator) validateBinaryReachability(payload string) error {
	pathText, anchor, ok := strings.Cut(payload, "#")
	if !ok || strings.TrimSpace(anchor) == "" {
		return fmt.Errorf("binary evidence %q needs a #literal anchor", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	relative = filepath.ToSlash(relative)
	rootFunction := "main"
	directory := filepath.ToSlash(filepath.Dir(relative))
	if strings.HasPrefix(relative, "internal/control/") {
		controlMain, err := v.loadPackageReachability("cmd/probectl-control", "main")
		if err != nil {
			return err
		}
		if !controlMain.reachableAnchor("cmd/probectl-control/serve_runtime.go", "control.New(") {
			return fmt.Errorf("internal control assembly is not reachable from the probectl-control main function")
		}
		directory = "internal/control"
		rootFunction = "New"
	}
	pkg, err := v.loadPackageReachability(directory, rootFunction)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(anchor)
	if strings.HasPrefix(trimmed, "func ") {
		name := strings.TrimSpace(strings.TrimPrefix(trimmed, "func "))
		if fields := strings.FieldsFunc(name, func(r rune) bool { return r == '(' || r == '[' || r == ' ' || r == '\t' }); len(fields) > 0 {
			name = fields[0]
		}
		key := topLevelSymbol(name)
		if !pkg.reachable[key] || !pkg.functionDefinedIn(key, relative) {
			return fmt.Errorf("binary function %s in %q is not reachable from %s", name, relative, rootFunction)
		}
		return nil
	}
	if !pkg.reachableAnchor(relative, anchor) {
		return fmt.Errorf("binary anchor %q in %q is not inside code reachable from %s", anchor, relative, rootFunction)
	}
	return nil
}

func (v *Validator) loadPackageReachability(relativeDir, rootFunction string) (*packageReachability, error) {
	cacheKey := relativeDir + "#" + rootFunction
	if cached := v.reachability[cacheKey]; cached != nil {
		return cached, nil
	}
	directory, err := v.resolveWithinRoot(relativeDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read binary package %q: %w", relativeDir, err)
	}

	var parsedFiles []parsedReachabilityFile
	functions := map[string]bool{}
	returns := map[string]string{}
	packageName := ""
	buildContext := build.Default
	buildContext.GOOS = "linux"
	buildContext.GOARCH = "amd64"
	buildContext.CgoEnabled = false
	buildContext.BuildTags = nil
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		matched, err := buildContext.MatchFile(directory, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("evaluate binary build constraints for %q: %w", filepath.ToSlash(filepath.Join(relativeDir, entry.Name())), err)
		}
		if !matched {
			continue
		}
		relative := filepath.ToSlash(filepath.Join(relativeDir, entry.Name()))
		path, err := v.resolveWithinRoot(relative)
		if err != nil {
			return nil, err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read binary source %q: %w", relative, err)
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, source, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse binary source %q: %w", relative, err)
		}
		if packageName == "" {
			packageName = file.Name.Name
		} else if file.Name.Name != packageName {
			return nil, fmt.Errorf(
				"parse binary package %q: default-build files declare both package %q and package %q",
				relativeDir,
				packageName,
				file.Name.Name,
			)
		}
		withoutComments := append([]byte(nil), source...)
		for _, group := range file.Comments {
			start := set.Position(group.Pos()).Offset
			end := set.Position(group.End()).Offset
			if start < 0 || end < start || end > len(withoutComments) {
				return nil, fmt.Errorf("parse binary source %q: invalid comment offsets", relative)
			}
			for i := start; i < end; i++ {
				withoutComments[i] = ' '
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || (literal.Kind != token.STRING && literal.Kind != token.CHAR) {
				return true
			}
			start := set.Position(literal.Pos()).Offset
			end := set.Position(literal.End()).Offset
			if start >= 0 && end >= start && end <= len(withoutComments) {
				for i := start; i < end; i++ {
					withoutComments[i] = ' '
				}
			}
			return true
		})
		parsed := parsedReachabilityFile{
			relative: relative, withoutComments: withoutComments,
			set: set, file: file,
		}
		parsedFiles = append(parsedFiles, parsed)
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := functionSymbol(fn)
			functions[key] = true
			if fn.Recv == nil {
				if result := singleResultType(fn.Type.Results); result != "" {
					returns[fn.Name.Name] = result
				}
			}
		}
	}

	pkg := &packageReachability{functions: map[string][]reachableFunction{}, reachable: map[string]bool{}}
	packageConstants := packageConstantValues(parsedFiles)
	for _, parsed := range parsedFiles {
		for _, declaration := range parsed.file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := parsed.set.Position(fn.Body.Pos()).Offset
			end := parsed.set.Position(fn.Body.End()).Offset
			if start < 0 || end < start || end > len(parsed.withoutComments) {
				return nil, fmt.Errorf("parse binary source %q: invalid function offsets", parsed.relative)
			}
			excluded := excludedSyntaxWithConstants(fn.Body, packageConstants)
			item := reachableFunction{
				file:       parsed.relative,
				references: map[string]bool{},
				protocols:  map[string]bool{},
			}
			collectReachabilityReferences(fn.Body, functions, returns, excluded, item.references)
			collectExecutableEvidence(fn.Body, parsed, excluded, packageConstants, &item)
			key := functionSymbol(fn)
			pkg.functions[key] = append(pkg.functions[key], item)
		}
	}

	rootKey := rootFunction
	if !strings.HasPrefix(rootKey, topLevelSymbolPrefix) && !strings.HasPrefix(rootKey, methodSymbolPrefix) {
		rootKey = topLevelSymbol(rootFunction)
	}
	if len(pkg.functions[rootKey]) == 0 {
		return nil, fmt.Errorf("binary package %q has no %s function", relativeDir, rootFunction)
	}
	queue := []string{rootKey}
	if len(pkg.functions[topLevelSymbol("init")]) > 0 {
		queue = append(queue, topLevelSymbol("init"))
	}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if pkg.reachable[key] {
			continue
		}
		pkg.reachable[key] = true
		for _, fn := range pkg.functions[key] {
			for referenced := range fn.references {
				if len(pkg.functions[referenced]) > 0 && !pkg.reachable[referenced] {
					queue = append(queue, referenced)
				}
			}
		}
	}
	v.reachability[cacheKey] = pkg
	return pkg, nil
}

func collectReachabilityReferences(
	body *ast.BlockStmt,
	functions map[string]bool,
	returns map[string]string,
	excluded []syntaxRange,
	out map[string]bool,
) {
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			return false
		}
		if syntaxExcluded(node, excluded) {
			return false
		}
		if _, ok := node.(*ast.FuncLit); ok {
			// An assigned or passed closure is not a statically proven call edge.
			return false
		}
		if expression, ok := node.(*ast.CallExpr); ok {
			switch called := expression.Fun.(type) {
			case *ast.Ident:
				key := topLevelSymbol(called.Name)
				if functions[key] && identifierCanResolveTopLevelFunction(called) {
					out[key] = true
				}
			case *ast.SelectorExpr:
				if receiverType := expressionObjectType(called.X, returns, map[*parserObject]bool{}); receiverType != "" {
					key := methodSymbol(receiverType, called.Sel.Name)
					if functions[key] {
						out[key] = true
					}
				}
			}
		}
		return true
	})
}

type syntaxRange struct {
	start token.Pos
	end   token.Pos
}

type sequentialFlow struct {
	terminal  bool
	gotoLabel string
	branch    token.Token
}

func sequentialTransfer(statement ast.Stmt, packageConstants map[string]constant.Value) sequentialFlow {
	switch value := statement.(type) {
	case *ast.ReturnStmt:
		return sequentialFlow{terminal: true}
	case *ast.BranchStmt:
		if value.Tok == token.GOTO && value.Label != nil {
			return sequentialFlow{terminal: true, gotoLabel: value.Label.Name}
		}
		if value.Tok == token.BREAK || value.Tok == token.CONTINUE {
			return sequentialFlow{terminal: true, branch: value.Tok}
		}
	case *ast.ExprStmt:
		call, ok := value.X.(*ast.CallExpr)
		if !ok {
			break
		}
		callee, ok := call.Fun.(*ast.Ident)
		if ok && callee.Name == "panic" && callee.Obj == nil {
			return sequentialFlow{terminal: true}
		}
	case *ast.BlockStmt:
		return blockSequentialTransfer(value.List, packageConstants)
	case *ast.LabeledStmt:
		return sequentialTransfer(value.Stmt, packageConstants)
	case *ast.IfStmt:
		if condition, constant := constantBooleanWithConstants(value.Cond, packageConstants); constant {
			if condition {
				return blockSequentialTransfer(value.Body.List, packageConstants)
			}
			if value.Else != nil {
				return sequentialTransfer(value.Else, packageConstants)
			}
			return sequentialFlow{}
		}
		if value.Else == nil {
			return sequentialFlow{}
		}
		left := blockSequentialTransfer(value.Body.List, packageConstants)
		right := sequentialTransfer(value.Else, packageConstants)
		if !left.terminal || !right.terminal {
			return sequentialFlow{}
		}
		if left.gotoLabel == right.gotoLabel {
			return left
		}
		if left.gotoLabel == "" {
			return right
		}
		if right.gotoLabel == "" {
			return left
		}
	case *ast.SwitchStmt:
		selected, constant := constantSwitchClauses(value, packageConstants)
		if !constant {
			break
		}
		for index, rawClause := range value.Body.List {
			if !selected[index] {
				continue
			}
			clause, ok := rawClause.(*ast.CaseClause)
			if !ok {
				continue
			}
			flow := blockSequentialTransfer(clause.Body, packageConstants)
			if !flow.terminal {
				continue
			}
			if flow.branch == token.BREAK {
				return sequentialFlow{}
			}
			return flow
		}
	}
	return sequentialFlow{}
}

func blockSequentialTransfer(statements []ast.Stmt, packageConstants map[string]constant.Value) sequentialFlow {
	for _, statement := range statements {
		if transfer := sequentialTransfer(statement, packageConstants); transfer.terminal {
			return transfer
		}
	}
	return sequentialFlow{}
}

func constantSwitchClauses(statement *ast.SwitchStmt, packageConstants map[string]constant.Value) (map[int]bool, bool) {
	tag := constant.MakeBool(true)
	if statement.Tag != nil {
		value, ok := constantExpressionValueWithConstants(statement.Tag, map[*parserObject]bool{}, packageConstants)
		if !ok {
			return nil, false
		}
		tag = value
	}
	selected := -1
	defaultIndex := -1
	for index, rawClause := range statement.Body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok {
			return nil, false
		}
		if len(clause.List) == 0 {
			defaultIndex = index
			continue
		}
		for _, expression := range clause.List {
			candidate, constantCase := constantExpressionValueWithConstants(expression, map[*parserObject]bool{}, packageConstants)
			if !constantCase {
				return nil, false
			}
			if selected < 0 && constantValuesEqual(tag, candidate) {
				selected = index
			}
		}
	}
	if selected < 0 {
		selected = defaultIndex
	}
	live := map[int]bool{}
	for selected >= 0 && selected < len(statement.Body.List) {
		live[selected] = true
		clause := statement.Body.List[selected].(*ast.CaseClause)
		if !caseFallsThrough(clause.Body) {
			break
		}
		selected++
	}
	return live, true
}

func caseFallsThrough(statements []ast.Stmt) bool {
	if len(statements) == 0 {
		return false
	}
	branch, ok := statements[len(statements)-1].(*ast.BranchStmt)
	return ok && branch.Tok == token.FALLTHROUGH
}

func constantValuesEqual(left, right constant.Value) (equal bool) {
	defer func() {
		if recover() != nil {
			equal = false
		}
	}()
	return constant.Compare(left, token.EQL, right)
}

func excludedSyntax(body *ast.BlockStmt) []syntaxRange {
	return excludedSyntaxWithConstants(body, nil)
}

func excludedSyntaxWithConstants(body *ast.BlockStmt, packageConstants map[string]constant.Value) []syntaxRange {
	var out []syntaxRange
	var visitBlock func(*ast.BlockStmt)
	var visitIf func(*ast.IfStmt)
	var visitStatement func(ast.Stmt)
	var visitSwitch func(*ast.SwitchStmt)
	visitIf = func(value *ast.IfStmt) {
		condition, constant := constantBooleanWithConstants(value.Cond, packageConstants)
		if constant && !condition {
			out = append(out, syntaxRange{start: value.Body.Pos(), end: value.Body.End()})
		} else {
			visitBlock(value.Body)
		}
		switch alternate := value.Else.(type) {
		case *ast.BlockStmt:
			if constant && condition {
				out = append(out, syntaxRange{start: alternate.Pos(), end: alternate.End()})
			} else {
				visitBlock(alternate)
			}
		case *ast.IfStmt:
			if constant && condition {
				out = append(out, syntaxRange{start: alternate.Pos(), end: alternate.End()})
			} else {
				visitIf(alternate)
			}
		}
	}
	visitSwitch = func(value *ast.SwitchStmt) {
		selected, constant := constantSwitchClauses(value, packageConstants)
		for index, rawClause := range value.Body.List {
			clause, ok := rawClause.(*ast.CaseClause)
			if !ok {
				continue
			}
			if constant && !selected[index] {
				out = append(out, syntaxRange{start: clause.Pos(), end: clause.End()})
				continue
			}
			visitBlock(&ast.BlockStmt{List: clause.Body})
		}
	}
	visitStatement = func(statement ast.Stmt) {
		switch value := statement.(type) {
		case *ast.BlockStmt:
			visitBlock(value)
		case *ast.IfStmt:
			visitIf(value)
		case *ast.SwitchStmt:
			visitSwitch(value)
		case *ast.TypeSwitchStmt:
			for _, rawClause := range value.Body.List {
				if clause, ok := rawClause.(*ast.CaseClause); ok {
					visitBlock(&ast.BlockStmt{List: clause.Body})
				}
			}
		case *ast.SelectStmt:
			for _, rawClause := range value.Body.List {
				if clause, ok := rawClause.(*ast.CommClause); ok {
					visitBlock(&ast.BlockStmt{List: clause.Body})
				}
			}
		case *ast.ForStmt:
			condition, constant := constantBooleanWithConstants(value.Cond, packageConstants)
			if constant && !condition {
				out = append(out, syntaxRange{start: value.Body.Pos(), end: value.Body.End()})
			} else {
				visitBlock(value.Body)
			}
		case *ast.RangeStmt:
			visitBlock(value.Body)
		case *ast.LabeledStmt:
			visitStatement(value.Stmt)
		}
	}
	visitBlock = func(block *ast.BlockStmt) {
		dead := false
		resumeLabel := ""
		for _, statement := range block.List {
			if dead {
				if labeled, ok := statement.(*ast.LabeledStmt); ok && resumeLabel != "" && labeled.Label.Name == resumeLabel {
					dead = false
					resumeLabel = ""
					visitStatement(labeled.Stmt)
					continue
				}
				out = append(out, syntaxRange{start: statement.Pos(), end: statement.End()})
				continue
			}
			visitStatement(statement)
			transfer := sequentialTransfer(statement, packageConstants)
			if transfer.terminal {
				dead = true
				resumeLabel = transfer.gotoLabel
			}
		}
	}
	visitBlock(body)
	ast.Inspect(body, func(node ast.Node) bool {
		literal, ok := node.(*ast.FuncLit)
		if !ok {
			return true
		}
		out = append(out, syntaxRange{start: literal.Pos(), end: literal.End()})
		return false
	})
	ast.Inspect(body, func(node ast.Node) bool {
		binary, ok := node.(*ast.BinaryExpr)
		if !ok || (binary.Op != token.LAND && binary.Op != token.LOR) {
			return true
		}
		left, constant := constantBooleanWithConstants(binary.X, packageConstants)
		if constant && (binary.Op == token.LAND && !left || binary.Op == token.LOR && left) {
			out = append(out, syntaxRange{start: binary.Y.Pos(), end: binary.Y.End()})
			return false
		}
		return true
	})
	return out
}

// constantBoolean evaluates literal and locally resolved Go constant
// expressions. Unknown expressions stay live: reachability discards a branch
// only when its value can be proven without executing code.
func constantBoolean(expression ast.Expr) (bool, bool) {
	return constantBooleanWithConstants(expression, nil)
}

func constantBooleanWithConstants(expression ast.Expr, packageConstants map[string]constant.Value) (bool, bool) {
	value, ok := constantExpressionValueWithConstants(expression, map[*parserObject]bool{}, packageConstants)
	if !ok {
		result, err := types.Eval(token.NewFileSet(), nil, token.NoPos, types.ExprString(expression))
		if err != nil || result.Value == nil {
			return false, false
		}
		value = result.Value
	}
	if value.Kind() != constant.Bool {
		return false, false
	}
	return constant.BoolVal(value), true
}

func constantExpressionValueWithConstants(expression ast.Expr, seen map[*parserObject]bool, packageConstants map[string]constant.Value) (value constant.Value, ok bool) {
	defer func() {
		if recover() != nil {
			value, ok = nil, false
		}
	}()
	if expression == nil {
		return nil, false
	}
	switch item := expression.(type) {
	case *ast.BasicLit:
		value := constant.MakeFromLiteral(item.Value, item.Kind, 0)
		return value, value.Kind() != constant.Unknown
	case *ast.ParenExpr:
		return constantExpressionValueWithConstants(item.X, seen, packageConstants)
	case *ast.Ident:
		if item.Name == "true" {
			return constant.MakeBool(true), true
		}
		if item.Name == "false" {
			return constant.MakeBool(false), true
		}
		if item.Obj == nil {
			value, exists := packageConstants[item.Name]
			return value, exists
		}
		if item.Obj.Kind != ast.Con || seen[item.Obj] {
			return nil, false
		}
		seen[item.Obj] = true
		spec, declared := item.Obj.Decl.(*ast.ValueSpec)
		if !declared {
			return nil, false
		}
		for index, name := range spec.Names {
			if name.Obj == item.Obj && index < len(spec.Values) {
				return constantExpressionValueWithConstants(spec.Values[index], seen, packageConstants)
			}
		}
	case *ast.UnaryExpr:
		operand, known := constantExpressionValueWithConstants(item.X, seen, packageConstants)
		if !known {
			return nil, false
		}
		if item.Op == token.NOT {
			if operand.Kind() != constant.Bool {
				return nil, false
			}
			return constant.MakeBool(!constant.BoolVal(operand)), true
		}
		return constant.UnaryOp(item.Op, operand, 0), true
	case *ast.BinaryExpr:
		left, leftKnown := constantExpressionValueWithConstants(item.X, cloneObjectSet(seen), packageConstants)
		right, rightKnown := constantExpressionValueWithConstants(item.Y, cloneObjectSet(seen), packageConstants)
		if !leftKnown || !rightKnown {
			return nil, false
		}
		switch item.Op {
		case token.LAND, token.LOR:
			if left.Kind() != constant.Bool || right.Kind() != constant.Bool {
				return nil, false
			}
			leftBool, rightBool := constant.BoolVal(left), constant.BoolVal(right)
			return constant.MakeBool(item.Op == token.LAND && leftBool && rightBool || item.Op == token.LOR && (leftBool || rightBool)), true
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			return constant.MakeBool(constant.Compare(left, item.Op, right)), true
		case token.SHL, token.SHR:
			shift, exact := constant.Uint64Val(right)
			if !exact {
				return nil, false
			}
			return constant.Shift(left, item.Op, uint(shift)), true
		default:
			return constant.BinaryOp(left, item.Op, right), true
		}
	}
	return nil, false
}

func cloneObjectSet(source map[*parserObject]bool) map[*parserObject]bool {
	clone := make(map[*parserObject]bool, len(source))
	for object, included := range source {
		clone[object] = included
	}
	return clone
}

// packageConstantValues resolves the simple package constants needed to prove
// dead branches across Go files. The parser binds identifiers only within one
// file, so without this package-level pass `const enabled = false` in flags.go
// could make an unreachable call in main.go look live. Unknown or cyclic
// expressions are deliberately omitted and therefore remain live/fail-open for
// reachability discovery rather than being guessed.
func packageConstantValues(files []parsedReachabilityFile) map[string]constant.Value {
	expressions := map[string]ast.Expr{}
	duplicates := map[string]bool{}
	for _, parsed := range files {
		for _, declaration := range parsed.file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			var inherited []ast.Expr
			for _, rawSpec := range group.Specs {
				spec, ok := rawSpec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				values := spec.Values
				if len(values) > 0 {
					inherited = values
				} else {
					values = inherited
				}
				if len(values) != len(spec.Names) {
					continue
				}
				for index, name := range spec.Names {
					if _, exists := expressions[name.Name]; exists {
						duplicates[name.Name] = true
						delete(expressions, name.Name)
						continue
					}
					if !duplicates[name.Name] {
						expressions[name.Name] = values[index]
					}
				}
			}
		}
	}
	resolved := map[string]constant.Value{}
	for progress := true; progress; {
		progress = false
		for name, expression := range expressions {
			if _, exists := resolved[name]; exists {
				continue
			}
			value, ok := constantExpressionValueWithConstants(expression, map[*parserObject]bool{}, resolved)
			if !ok {
				continue
			}
			resolved[name] = value
			progress = true
		}
	}
	return resolved
}

func syntaxExcluded(node ast.Node, ranges []syntaxRange) bool {
	for _, item := range ranges {
		if node.Pos() >= item.start && node.End() <= item.end {
			return true
		}
	}
	return false
}

func collectExecutableEvidence(
	body *ast.BlockStmt,
	parsed parsedReachabilityFile,
	excluded []syntaxRange,
	packageConstants map[string]constant.Value,
	item *reachableFunction,
) {
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			return false
		}
		if syntaxExcluded(node, excluded) {
			return false
		}
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		code := func() string {
			start := parsed.set.Position(node.Pos()).Offset
			end := parsed.set.Position(node.End()).Offset
			if start < 0 || end < start || end > len(parsed.withoutComments) {
				return ""
			}
			return string(parsed.withoutComments[start:end])
		}
		switch value := node.(type) {
		case *ast.CallExpr:
			item.calls = append(item.calls, executableCall{
				callee: canonicalExpression(value.Fun),
				code:   canonicalExpression(value),
			})
		case *ast.AssignStmt:
			item.assignments = append(item.assignments, code())
		case *ast.CompositeLit:
			item.composites = append(item.composites, code())
		case *ast.CaseClause:
			if !protocolStatementsHaveWork(value.Body, excluded) {
				break
			}
			for _, expression := range value.List {
				if protocol := constantString(expression, packageConstants); protocol != "" {
					item.protocols[protocol] = true
				}
			}
		case *ast.IfStmt:
			if !protocolStatementsHaveWork(value.Body.List, excluded) {
				break
			}
			binary, ok := value.Cond.(*ast.BinaryExpr)
			if !ok || binary.Op != token.EQL {
				break
			}
			for _, expression := range []ast.Expr{binary.X, binary.Y} {
				if protocol := constantString(expression, packageConstants); protocol != "" {
					item.protocols[protocol] = true
				}
			}
		}
		return true
	})
}

func protocolStatementsHaveWork(statements []ast.Stmt, excluded []syntaxRange) bool {
	found := false
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			if node == nil || found {
				return false
			}
			if syntaxExcluded(node, excluded) {
				return false
			}
			if _, closure := node.(*ast.FuncLit); closure {
				return false
			}
			switch value := node.(type) {
			case *ast.CallExpr:
				if identifier, ok := value.Fun.(*ast.Ident); ok && identifier.Obj == nil && identifier.Name == "panic" {
					return true
				}
				found = true
			case *ast.ReturnStmt:
				found = len(value.Results) > 0
			case *ast.SendStmt:
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func constantString(expression ast.Expr, packageConstants map[string]constant.Value) string {
	value, ok := constantExpressionValueWithConstants(expression, map[*parserObject]bool{}, packageConstants)
	if !ok || value.Kind() != constant.String {
		return ""
	}
	return constant.StringVal(value)
}

func canonicalExpression(expression ast.Expr) string {
	return types.ExprString(expression)
}

func identifierCanResolveTopLevelFunction(identifier *ast.Ident) bool {
	if identifier.Obj == nil {
		// The parser resolves only declarations in the current file. An
		// unresolved identifier may therefore be a package-level function in
		// another file, but a resolved local variable can never be one.
		return true
	}
	_, declaredFunction := identifier.Obj.Decl.(*ast.FuncDecl)
	return identifier.Obj.Kind == ast.Fun && declaredFunction
}

func expressionObjectType(expression ast.Expr, returns map[string]string, seen map[*parserObject]bool) string {
	switch value := expression.(type) {
	case *ast.Ident:
		return objectDeclaredType(value.Obj, returns, seen)
	case *ast.ParenExpr:
		return expressionObjectType(value.X, returns, seen)
	case *ast.UnaryExpr:
		return expressionObjectType(value.X, returns, seen)
	case *ast.CompositeLit:
		return localTypeName(value.Type)
	case *ast.TypeAssertExpr:
		return localTypeName(value.Type)
	case *ast.CallExpr:
		if identifier, ok := value.Fun.(*ast.Ident); ok {
			if identifier.Name == "new" && len(value.Args) == 1 {
				return localTypeName(value.Args[0])
			}
			if identifierCanResolveTopLevelFunction(identifier) {
				return returns[identifier.Name]
			}
		}
	}
	return ""
}

func objectDeclaredType(object *parserObject, returns map[string]string, seen map[*parserObject]bool) string {
	if object == nil || seen[object] {
		return ""
	}
	seen[object] = true
	switch declaration := object.Decl.(type) {
	case *ast.Field:
		return localTypeName(declaration.Type)
	case *ast.ValueSpec:
		if declared := localTypeName(declaration.Type); declared != "" {
			return declared
		}
		for index, name := range declaration.Names {
			if name.Obj != object || index >= len(declaration.Values) {
				continue
			}
			return expressionObjectType(declaration.Values[index], returns, seen)
		}
	case *ast.AssignStmt:
		if len(declaration.Lhs) != len(declaration.Rhs) {
			return ""
		}
		for index, target := range declaration.Lhs {
			identifier, ok := target.(*ast.Ident)
			if !ok || identifier.Obj != object {
				continue
			}
			return expressionObjectType(declaration.Rhs[index], returns, seen)
		}
	}
	return ""
}

func singleResultType(results *ast.FieldList) string {
	if results == nil || len(results.List) != 1 || len(results.List[0].Names) > 1 {
		return ""
	}
	return localTypeName(results.List[0].Type)
}

func localTypeName(expression ast.Expr) string {
	switch value := expression.(type) {
	case nil:
		return ""
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return localTypeName(value.X)
	case *ast.ParenExpr:
		return localTypeName(value.X)
	case *ast.IndexExpr:
		return localTypeName(value.X)
	case *ast.IndexListExpr:
		return localTypeName(value.X)
	}
	return ""
}

func functionSymbol(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return topLevelSymbol(fn.Name.Name)
	}
	return methodSymbol(localTypeName(fn.Recv.List[0].Type), fn.Name.Name)
}

func topLevelSymbol(name string) string { return topLevelSymbolPrefix + name }

func methodSymbol(receiver, name string) string {
	return methodSymbolPrefix + receiver + "." + name
}

func (p *packageReachability) functionDefinedIn(key, file string) bool {
	for _, fn := range p.functions[key] {
		if fn.file == file {
			return true
		}
	}
	return false
}

func (p *packageReachability) reachableAnchor(file, anchor string) bool {
	exactCallee, exactCall, exact := exactSelectorCallAnchor(anchor)
	callCallee, callAnchor := partialCallAnchor(anchor)
	for key, functions := range p.functions {
		if !p.reachable[key] {
			continue
		}
		for _, fn := range functions {
			if fn.file != file {
				continue
			}
			if exact {
				for _, candidate := range fn.calls {
					if candidate.callee == exactCallee && candidate.code == exactCall {
						return true
					}
				}
				continue
			}
			if callAnchor {
				for _, candidate := range fn.calls {
					if callCalleeMatches(candidate.callee, callCallee) && strings.Contains(candidate.code, anchor) {
						return true
					}
				}
				continue
			}
			var candidates []string
			switch {
			case strings.Contains(anchor, "="):
				candidates = fn.assignments
			default:
				for _, call := range fn.calls {
					candidates = append(candidates, call.code)
				}
				candidates = append(candidates, fn.composites...)
			}
			for _, candidate := range candidates {
				if containsGoTokenSequence(candidate, anchor) {
					return true
				}
			}
		}
	}
	return false
}

func containsGoTokenSequence(candidate, anchor string) bool {
	candidateTokens := scanGoFragment(candidate)
	anchorTokens := scanGoFragment(strings.TrimSpace(anchor))
	if len(anchorTokens) == 0 || len(anchorTokens) > len(candidateTokens) {
		return false
	}
	for start := 0; start <= len(candidateTokens)-len(anchorTokens); start++ {
		matched := true
		for offset, wanted := range anchorTokens {
			if candidateTokens[start+offset] != wanted {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func scanGoFragment(source string) []string {
	set := token.NewFileSet()
	file := set.AddFile("binary-anchor.go", -1, len(source))
	var lexer scanner.Scanner
	lexer.Init(file, []byte(source), nil, 0)
	var out []string
	for {
		_, kind, literal := lexer.Scan()
		if kind == token.EOF {
			return out
		}
		if kind == token.SEMICOLON {
			continue
		}
		if literal == "" {
			literal = kind.String()
		}
		out = append(out, kind.String()+":"+literal)
	}
}

func (v *Validator) validateGoProtocolReachability(payload string) error {
	pathText, anchor, ok := strings.Cut(payload, "#")
	if !ok || strings.TrimSpace(anchor) == "" {
		return fmt.Errorf("non-REST Go API evidence %q needs a #protocol anchor", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	relative = filepath.ToSlash(relative)
	if filepath.Ext(relative) != ".go" {
		return nil
	}
	directory := filepath.ToSlash(filepath.Dir(relative))
	roots, err := v.exportedPackageRoots(directory)
	if err != nil {
		return err
	}
	for _, root := range roots {
		pkg, err := v.loadPackageReachability(directory, root)
		if err != nil {
			return err
		}
		if pkg.reachableProtocolAnchor(relative, strings.TrimSpace(anchor)) {
			return nil
		}
	}
	return fmt.Errorf("non-REST Go API anchor %q in %q is not a live dispatch value reachable from an exported package entrypoint", anchor, relative)
}

func (v *Validator) exportedPackageRoots(relativeDir string) ([]string, error) {
	directory, err := v.resolveWithinRoot(relativeDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read non-REST API package %q: %w", relativeDir, err)
	}
	buildContext := build.Default
	buildContext.GOOS = "linux"
	buildContext.GOARCH = "amd64"
	buildContext.CgoEnabled = false
	buildContext.BuildTags = nil
	var roots []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		matched, err := buildContext.MatchFile(directory, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("evaluate non-REST API build constraints for %q: %w", filepath.ToSlash(filepath.Join(relativeDir, entry.Name())), err)
		}
		if !matched {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse non-REST API source %q: %w", filepath.ToSlash(filepath.Join(relativeDir, entry.Name())), err)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !ast.IsExported(fn.Name.Name) {
				continue
			}
			if fn.Recv != nil && (len(fn.Recv.List) == 0 || !ast.IsExported(localTypeName(fn.Recv.List[0].Type))) {
				continue
			}
			roots = append(roots, functionSymbol(fn))
		}
	}
	sort.Strings(roots)
	return roots, nil
}

func (p *packageReachability) reachableProtocolAnchor(file, anchor string) bool {
	for key, functions := range p.functions {
		if !p.reachable[key] {
			continue
		}
		for _, function := range functions {
			if function.file == file && function.protocols[anchor] {
				return true
			}
		}
	}
	return false
}

// A complete selector call is an exact assembly statement. Requiring the
// complete canonical call ties evidence to both the intended callee and the
// ordered argument roles. In particular, reg.Register("noop",
// canary.NewNoop) cannot be replaced by an unrelated call that merely mentions
// canary.NewNoop.
func exactSelectorCallAnchor(anchor string) (callee, call string, ok bool) {
	set := token.NewFileSet()
	expression, err := parser.ParseExprFrom(set, "binary-anchor.go", strings.TrimSpace(anchor), 0)
	if err != nil {
		return "", "", false
	}
	invocation, ok := expression.(*ast.CallExpr)
	if !ok {
		return "", "", false
	}
	if _, ok := invocation.Fun.(*ast.SelectorExpr); !ok {
		return "", "", false
	}
	return canonicalExpression(invocation.Fun), canonicalExpression(invocation), true
}

func partialCallAnchor(anchor string) (string, bool) {
	before, _, ok := strings.Cut(strings.TrimSpace(anchor), "(")
	if !ok || strings.TrimSpace(before) == "" {
		return "", false
	}
	set := token.NewFileSet()
	expression, err := parser.ParseExprFrom(set, "binary-callee.go", strings.TrimSpace(before), 0)
	if err != nil {
		return "", false
	}
	switch expression.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return canonicalExpression(expression), true
	default:
		return "", false
	}
}

func callCalleeMatches(candidate, anchor string) bool {
	if candidate == anchor {
		return true
	}
	return !strings.Contains(anchor, ".") && strings.HasSuffix(candidate, "."+anchor)
}
