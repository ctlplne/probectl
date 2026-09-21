// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	pythonDeclarationPattern = regexp.MustCompile(`(?m)^\s*(?:async\s+)?(?:def|class)\s+[A-Za-z_][A-Za-z0-9_]*\b|^\s*[A-Za-z_][A-Za-z0-9_]*\s*(?::[^=\n]+)?=`)
	pythonSignalPattern      = regexp.MustCompile(`(?i)\.(?:debug|info|warning|warn|error|critical|exception|emit|publish|observe)\s*\(|\b(?:emit|publish|observe|record|report|export)_[a-z0-9_]*\s*\(|\bclass\s+[A-Za-z0-9_]*(?:event|result|metric|telemetry|observation|signal|snapshot|stats|measurement|trace|span)\b`)
	javascriptDeclaration    = regexp.MustCompile(`(?m)\b(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(|\bclass\s+[A-Za-z_$][A-Za-z0-9_$]*\b|\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=`)
	javascriptSignalPattern  = regexp.MustCompile(`(?i)\.(?:debug|info|warn|error|emit|publish|observe)\s*\(|\b(?:emit|publish|observe|record|report|export)(?:[A-Z_$][A-Za-z0-9_$]*)?\s*\(|\b(?:class|const|let|var)\s+[A-Za-z0-9_$]*(?:event|result|metric|telemetry|observation|signal|snapshot|stats|measurement|trace|span)\b`)
	terraFormBlockPattern    = regexp.MustCompile(`(?m)^\s*(?:terraform|resource|data|module|provider|variable|output|locals|moved|import|check)\b[^\n{]*\{`)
	yamlAPIKindPattern       = regexp.MustCompile(`(?m)^apiVersion\s*:\s*\S+\s*$`)
	yamlKindPattern          = regexp.MustCompile(`(?m)^kind\s*:\s*\S+\s*$`)
	yamlBodyPattern          = regexp.MustCompile(`(?m)^(?:spec|jobs)\s*:\s*(?:\S.*)?$`)
)

// validateImplementationEvidence proves that engine and telemetry references
// point to production syntax, rather than trusting path existence or comments.
// It deliberately excludes tests and fixture trees. Directory evidence passes
// when at least one regular production source file provides the required proof.
func (v *Validator) validateImplementationEvidence(cell, payload string) error {
	if cell != "engine" && cell != "telemetry" {
		return fmt.Errorf("implementation evidence validation does not support cell %q", cell)
	}
	pathText, _, _ := strings.Cut(payload, "#")
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect implementation evidence %q: %w", pathText, err)
	}
	if !info.IsDir() && isTestSource(path) {
		return fmt.Errorf("%s evidence %q points to a test file, not production implementation", cell, filepath.ToSlash(relative))
	}

	foundProduction := false
	foundSignal := false
	var firstInspectionError error
	err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if firstInspectionError == nil {
				firstInspectionError = walkErr
			}
			return nil
		}
		if entry.IsDir() {
			if candidate != path && excludedEvidenceDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || isTestSource(candidate) || !isProductionSource(candidate) {
			return nil
		}
		matches, matchErr := matchesProductionBuild(candidate)
		if matchErr != nil {
			if firstInspectionError == nil {
				firstInspectionError = matchErr
			}
			return nil
		}
		if !matches {
			return nil
		}
		production, signal, inspectErr := inspectProductionSource(candidate)
		if inspectErr != nil {
			if firstInspectionError == nil {
				firstInspectionError = inspectErr
			}
			return nil
		}
		foundProduction = foundProduction || production
		foundSignal = foundSignal || signal
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk implementation evidence %q: %w", pathText, err)
	}
	if cell == "telemetry" && foundSignal {
		return nil
	}
	if cell == "engine" && foundProduction {
		return nil
	}
	if firstInspectionError != nil {
		return fmt.Errorf("inspect %s evidence %q: %w", cell, filepath.ToSlash(relative), firstInspectionError)
	}
	if cell == "telemetry" {
		return fmt.Errorf("telemetry evidence %q has no production signal/log/metric/OTel emission or explicit telemetry model declaration", filepath.ToSlash(relative))
	}
	return fmt.Errorf("engine evidence %q has no non-test production declaration or executable body", filepath.ToSlash(relative))
}

func matchesProductionBuild(path string) (bool, error) {
	if strings.ToLower(filepath.Ext(path)) != ".go" {
		return true, nil
	}
	context := build.Default
	context.GOOS = "linux"
	context.GOARCH = "amd64"
	context.CgoEnabled = false
	matches, err := context.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return false, fmt.Errorf("match production build constraints for %q: %w", filepath.ToSlash(path), err)
	}
	return matches, nil
}

func excludedEvidenceDirectory(name string) bool {
	switch name {
	case ".git", ".idea", ".vscode", "__pycache__", "dist", "fixtures", "node_modules", "test", "testdata", "tests", "vendor":
		return true
	default:
		return false
	}
}

func isProductionSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".tf", ".yaml", ".yml":
		return true
	default:
		return filepath.Base(path) == "Dockerfile"
	}
}

func isTestSource(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(name))
	stem := strings.TrimSuffix(name, ext)
	switch ext {
	case ".go":
		return strings.HasSuffix(stem, "_test")
	case ".py":
		return strings.HasPrefix(stem, "test_") || strings.HasSuffix(stem, "_test")
	case ".js", ".mjs", ".cjs", ".ts", ".tsx":
		return strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec") || strings.HasPrefix(stem, "test_")
	default:
		return false
	}
}

func inspectProductionSource(path string) (bool, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return inspectGoProduction(path, data)
	case ".py":
		code := stripPythonCommentsAndStrings(string(data))
		return pythonDeclarationPattern.MatchString(code), pythonSignalPattern.MatchString(code), nil
	case ".js", ".mjs", ".cjs", ".ts", ".tsx":
		code := stripCStyleCommentsAndStrings(string(data))
		return javascriptDeclaration.MatchString(code), javascriptSignalPattern.MatchString(code), nil
	case ".tf":
		code := stripHashComments(stripCStyleCommentsAndStrings(string(data)))
		return terraFormBlockPattern.MatchString(code), false, nil
	case ".yaml", ".yml":
		code := stripYAMLComments(string(data))
		production := yamlAPIKindPattern.MatchString(code) && yamlKindPattern.MatchString(code) && yamlBodyPattern.MatchString(code)
		return production, false, nil
	default:
		if filepath.Base(path) == "Dockerfile" {
			code := stripDockerfileComments(string(data))
			return regexp.MustCompile(`(?mi)^\s*FROM\s+\S+`).MatchString(code), false, nil
		}
		return false, false, nil
	}
}

func inspectGoProduction(path string, data []byte) (bool, bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		return false, false, err
	}
	production := false
	signal := false
	for _, declaration := range file.Decls {
		switch node := declaration.(type) {
		case *ast.FuncDecl:
			if substantiveGoFunction(node.Body) {
				production = true
			}
		case *ast.GenDecl:
			for _, spec := range node.Specs {
				switch item := spec.(type) {
				case *ast.TypeSpec:
					production = production || substantiveGoType(item.Type)
					if telemetryStruct(item.Name.Name, item.Type) {
						signal = true
					}
				case *ast.ValueSpec:
					if telemetryValueSpec(item) {
						signal = true
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if item, ok := node.(*ast.CallExpr); ok && goTelemetryCall(item) {
			signal = true
		}
		return true
	})
	return production, signal, nil
}

func substantiveGoType(expression ast.Expr) bool {
	switch declaration := expression.(type) {
	case *ast.StructType:
		return declaration.Fields != nil && len(declaration.Fields.List) > 0
	case *ast.InterfaceType:
		return declaration.Methods != nil && len(declaration.Methods.List) > 0
	default:
		return false
	}
}

func substantiveGoFunction(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil || found {
			return false
		}
		if _, closure := node.(*ast.FuncLit); closure {
			return false
		}
		switch value := node.(type) {
		case *ast.CallExpr:
			identifier, builtinPanic := value.Fun.(*ast.Ident)
			if !builtinPanic || identifier.Obj != nil || identifier.Name != "panic" {
				found = true
			}
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt:
			found = true
		case *ast.ReturnStmt:
			found = len(value.Results) > 0
		}
		return !found
	})
	return found
}

func telemetryStruct(typeName string, expression ast.Expr) bool {
	structure, ok := expression.(*ast.StructType)
	if !ok || structure.Fields == nil {
		return false
	}
	markers := map[string]bool{}
	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			if _, callback := field.Type.(*ast.FuncType); callback && strings.HasPrefix(name.Name, "On") && len(name.Name) > len("On") {
				return true
			}
			if marker := telemetryFieldMarker(name.Name); marker != "" {
				markers[marker] = true
			}
		}
		if field.Tag != nil {
			if unquoted, err := strconv.Unquote(field.Tag.Value); err == nil {
				for _, segment := range strings.Fields(unquoted) {
					if marker := telemetryFieldMarker(strings.Trim(strings.SplitN(segment, ":", 2)[0], `"`)); marker != "" {
						markers[marker] = true
					}
				}
			}
		}
	}
	return len(markers) >= 2 || len(markers) == 1 && telemetryModelName(typeName)
}

func telemetryValueSpec(spec *ast.ValueSpec) bool {
	for _, value := range spec.Values {
		literal, ok := value.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			continue
		}
		if strings.HasPrefix(text, "probectl.") && (strings.Contains(text, ".events") || strings.Contains(text, ".results")) {
			return true
		}
	}
	return false
}

func telemetryModelName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"event", "evidence", "finding", "health", "result", "metric", "telemetry", "observation", "signal", "snapshot", "stats", "measurement", "synthesis", "summary", "provenance", "trace", "span", "logrecord"} {
		if lower == marker || strings.HasPrefix(lower, marker) || strings.HasSuffix(lower, marker) {
			return true
		}
	}
	return false
}

func telemetryFieldMarker(name string) string {
	for _, word := range identifierWords(name) {
		switch word {
		case "failures":
			return "failure"
		case "errors":
			return "error"
		case "accepted", "bytes", "count", "duration", "error", "failed", "failure", "latency", "loss", "metric", "observed", "occurred", "packets", "received", "rejected", "rtt", "sent", "success", "timestamp", "total", "value":
			return word
		}
	}
	return ""
}

func goTelemetryCall(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	name := ""
	receiver := ""
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
		receiver = expressionIdentifierText(fun.X)
	default:
		return false
	}
	lowerName := strings.ToLower(name)
	lowerReceiver := strings.ToLower(receiver)
	if lowerName == "fprintf" && lowerReceiver == "fmt" && telemetryFormatLiteral(call.Args) {
		return true
	}
	if lowerReceiver != "" {
		switch lowerName {
		case "debug", "info", "warn", "warning", "error", "critical", "log", "logattrs":
			return true
		}
	}
	if lowerName == "emit" || lowerName == "publish" || lowerName == "observe" || lowerName == "record" || lowerName == "report" || lowerName == "export" || lowerName == "send" || strings.HasSuffix(lowerName, "append") || lowerName == "add" || lowerName == "inc" || lowerName == "set" {
		for _, marker := range []string{"accepted", "audit", "bus", "counter", "event", "failed", "failure", "gauge", "histogram", "log", "metric", "observ", "otel", "producer", "rejected", "signal", "span", "stats", "success", "telemetr", "total", "trace"} {
			if strings.Contains(lowerReceiver, marker) {
				return true
			}
		}
	}
	return false
}

func telemetryFormatLiteral(arguments []ast.Expr) bool {
	for _, argument := range arguments {
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && (strings.Contains(value, "# HELP ") || strings.Contains(value, "# TYPE ") || strings.Contains(value, "probectl_")) {
			return true
		}
	}
	return false
}

func expressionIdentifierText(expression ast.Expr) string {
	switch node := expression.(type) {
	case *ast.Ident:
		return node.Name
	case *ast.SelectorExpr:
		prefix := expressionIdentifierText(node.X)
		if prefix == "" {
			return node.Sel.Name
		}
		return prefix + "." + node.Sel.Name
	case *ast.IndexExpr:
		return expressionIdentifierText(node.X)
	case *ast.IndexListExpr:
		return expressionIdentifierText(node.X)
	case *ast.ParenExpr:
		return expressionIdentifierText(node.X)
	default:
		return ""
	}
}

func identifierWords(name string) []string {
	var words []string
	start := -1
	previousUpper := false
	runes := []rune(name)
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}
	for index, current := range runes {
		if !unicode.IsLetter(current) && !unicode.IsDigit(current) {
			flush(index)
			previousUpper = false
			continue
		}
		if start < 0 {
			start = index
			previousUpper = unicode.IsUpper(current)
			continue
		}
		currentUpper := unicode.IsUpper(current)
		nextLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
		if currentUpper && (!previousUpper || nextLower) {
			flush(index)
			start = index
		}
		previousUpper = currentUpper
	}
	flush(len(runes))
	return words
}

func stripPythonCommentsAndStrings(source string) string {
	var out strings.Builder
	for index := 0; index < len(source); {
		if source[index] == '#' {
			for index < len(source) && source[index] != '\n' {
				out.WriteByte(' ')
				index++
			}
			continue
		}
		if source[index] == '\'' || source[index] == '"' {
			quote := source[index]
			width := 1
			if index+2 < len(source) && source[index+1] == quote && source[index+2] == quote {
				width = 3
			}
			for consumed := 0; consumed < width; consumed++ {
				out.WriteByte(' ')
				index++
			}
			for index < len(source) {
				if source[index] == '\n' {
					out.WriteByte('\n')
					index++
					continue
				}
				if source[index] == '\\' && width == 1 && index+1 < len(source) {
					out.WriteString("  ")
					index += 2
					continue
				}
				closed := source[index] == quote
				if width == 3 {
					closed = index+2 < len(source) && source[index] == quote && source[index+1] == quote && source[index+2] == quote
				}
				if closed {
					for consumed := 0; consumed < width; consumed++ {
						out.WriteByte(' ')
						index++
					}
					break
				}
				out.WriteByte(' ')
				index++
			}
			continue
		}
		out.WriteByte(source[index])
		index++
	}
	return out.String()
}

func stripCStyleCommentsAndStrings(source string) string {
	var out strings.Builder
	for index := 0; index < len(source); {
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '/' {
			out.WriteString("  ")
			index += 2
			for index < len(source) && source[index] != '\n' {
				out.WriteByte(' ')
				index++
			}
			continue
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
			out.WriteString("  ")
			index += 2
			for index < len(source) {
				if index+1 < len(source) && source[index] == '*' && source[index+1] == '/' {
					out.WriteString("  ")
					index += 2
					break
				}
				if source[index] == '\n' {
					out.WriteByte('\n')
				} else {
					out.WriteByte(' ')
				}
				index++
			}
			continue
		}
		if source[index] == '\'' || source[index] == '"' || source[index] == '`' {
			quote := source[index]
			out.WriteByte(' ')
			index++
			for index < len(source) {
				if source[index] == '\n' {
					out.WriteByte('\n')
					index++
					if quote != '`' {
						break
					}
					continue
				}
				if source[index] == '\\' && index+1 < len(source) {
					out.WriteString("  ")
					index += 2
					continue
				}
				closed := source[index] == quote
				out.WriteByte(' ')
				index++
				if closed {
					break
				}
			}
			continue
		}
		out.WriteByte(source[index])
		index++
	}
	return out.String()
}

func stripYAMLComments(source string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(source, "\n") {
		quote := rune(0)
		escaped := false
		for _, current := range line {
			if quote != 0 {
				out.WriteRune(current)
				switch {
				case escaped:
					escaped = false
				case current == '\\' && quote == '"':
					escaped = true
				case current == quote:
					quote = 0
				}
				continue
			}
			if current == '\'' || current == '"' {
				quote = current
				out.WriteRune(current)
				continue
			}
			if current == '#' {
				break
			}
			out.WriteRune(current)
		}
		if !strings.HasSuffix(line, "\n") {
			continue
		}
		if out.Len() == 0 || !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func stripHashComments(source string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(source, "\n") {
		if offset := strings.IndexByte(line, '#'); offset >= 0 {
			out.WriteString(line[:offset])
			if strings.HasSuffix(line, "\n") {
				out.WriteByte('\n')
			}
			continue
		}
		out.WriteString(line)
	}
	return out.String()
}

func stripDockerfileComments(source string) string {
	var out strings.Builder
	for _, line := range strings.SplitAfter(source, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			if strings.HasSuffix(line, "\n") {
				out.WriteByte('\n')
			}
			continue
		}
		out.WriteString(line)
	}
	return out.String()
}
