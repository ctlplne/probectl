// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"fmt"
	"strings"
)

type surfaceDeclaration struct {
	featureIDs map[string]bool
	kind       string
	route      string
}

type typeScriptTokenKind uint8

const (
	typeScriptIdentifier typeScriptTokenKind = iota
	typeScriptString
	typeScriptPunctuation
)

type typeScriptToken struct {
	kind   typeScriptTokenKind
	text   string
	offset int
}

// parseSurfaceCatalog lexes just enough TypeScript to read the executable
// SURFACES array. Comments and string contents never become identifier or
// punctuation tokens, so source-looking prose cannot impersonate a registry
// declaration. String tokens are accepted only as values of the exact
// featureIds, kind, and route properties of top-level array objects.
func parseSurfaceCatalog(source []byte) ([]surfaceDeclaration, error) {
	tokens, err := lexTypeScript(source)
	if err != nil {
		return nil, err
	}
	arrayStart := -1
	declarations := 0
	for i := 0; i+2 < len(tokens); i++ {
		if !isTypeScriptIdentifier(tokens[i], "export") ||
			!isTypeScriptIdentifier(tokens[i+1], "const") ||
			!isTypeScriptIdentifier(tokens[i+2], "SURFACES") {
			continue
		}
		declarations++
		for j := i + 3; j < len(tokens); j++ {
			if isTypeScriptPunctuation(tokens[j], ";") {
				break
			}
			if !isTypeScriptPunctuation(tokens[j], "=") {
				continue
			}
			if j+1 >= len(tokens) || !isTypeScriptPunctuation(tokens[j+1], "[") {
				return nil, fmt.Errorf("SURFACES initializer must be an array literal")
			}
			arrayStart = j + 1
			break
		}
	}
	if declarations == 0 {
		return nil, fmt.Errorf("SURFACES declaration is missing")
	}
	if declarations != 1 {
		return nil, fmt.Errorf("SURFACES must have exactly one executable declaration")
	}
	if arrayStart < 0 {
		return nil, fmt.Errorf("SURFACES array initializer is missing")
	}

	var out []surfaceDeclaration
	for i := arrayStart + 1; i < len(tokens); {
		switch {
		case isTypeScriptPunctuation(tokens[i], "]"):
			if len(out) == 0 {
				return nil, fmt.Errorf("SURFACES contains no top-level object declarations")
			}
			return out, nil
		case isTypeScriptPunctuation(tokens[i], "{"):
			end, err := matchingTypeScriptToken(tokens, i, "{", "}")
			if err != nil {
				return nil, fmt.Errorf("SURFACES object at byte %d: %w", tokens[i].offset, err)
			}
			declaration, err := parseSurfaceObject(tokens[i+1 : end])
			if err != nil {
				return nil, fmt.Errorf("SURFACES object at byte %d: %w", tokens[i].offset, err)
			}
			out = append(out, declaration)
			i = end + 1
		case isTypeScriptPunctuation(tokens[i], ","):
			i++
		default:
			return nil, fmt.Errorf("SURFACES entries must be top-level object literals (unexpected token at byte %d)", tokens[i].offset)
		}
	}
	return nil, fmt.Errorf("SURFACES array is not closed")
}

func parseSurfaceObject(tokens []typeScriptToken) (surfaceDeclaration, error) {
	declaration := surfaceDeclaration{featureIDs: map[string]bool{}}
	seen := map[string]bool{}
	for i := 0; i < len(tokens); {
		for i < len(tokens) && isTypeScriptPunctuation(tokens[i], ",") {
			i++
		}
		if i >= len(tokens) {
			break
		}
		if tokens[i].kind != typeScriptIdentifier && tokens[i].kind != typeScriptString {
			return surfaceDeclaration{}, fmt.Errorf("properties must use static identifier or string keys (unexpected token at byte %d)", tokens[i].offset)
		}
		name := tokens[i].text
		if i+1 >= len(tokens) || !isTypeScriptPunctuation(tokens[i+1], ":") {
			return surfaceDeclaration{}, fmt.Errorf("property %q must use a static ':' initializer", name)
		}
		valueStart := i + 2
		valueEnd := typeScriptPropertyEnd(tokens, valueStart)
		if name == "featureIds" || name == "kind" || name == "route" {
			if seen[name] {
				return surfaceDeclaration{}, fmt.Errorf("duplicate %s property", name)
			}
			seen[name] = true
			value := tokens[valueStart:valueEnd]
			switch name {
			case "featureIds":
				ids, err := parseTypeScriptStringArray(value)
				if err != nil {
					return surfaceDeclaration{}, fmt.Errorf("featureIds: %w", err)
				}
				for _, id := range ids {
					declaration.featureIDs[id] = true
				}
			case "kind":
				kind, err := parseSingleTypeScriptString(value)
				if err != nil {
					return surfaceDeclaration{}, fmt.Errorf("kind: %w", err)
				}
				declaration.kind = kind
			case "route":
				route, err := parseSingleTypeScriptString(value)
				if err != nil {
					return surfaceDeclaration{}, fmt.Errorf("route: %w", err)
				}
				declaration.route = route
			}
		}
		i = valueEnd
		if i < len(tokens) && isTypeScriptPunctuation(tokens[i], ",") {
			i++
		}
	}
	if len(declaration.featureIDs) == 0 {
		return declaration, nil
	}
	switch declaration.kind {
	case "native":
		if declaration.route == "" || !strings.HasPrefix(declaration.route, "/") {
			return surfaceDeclaration{}, fmt.Errorf("native declaration needs an absolute route")
		}
	case "federated", "none-by-design":
		if declaration.route != "" {
			return surfaceDeclaration{}, fmt.Errorf("%s declaration must not claim a native route", declaration.kind)
		}
	default:
		return surfaceDeclaration{}, fmt.Errorf("feature declaration has unsupported or missing kind %q", declaration.kind)
	}
	return declaration, nil
}

func typeScriptPropertyEnd(tokens []typeScriptToken, start int) int {
	braces, brackets, parentheses := 0, 0, 0
	for i := start; i < len(tokens); i++ {
		if tokens[i].kind != typeScriptPunctuation {
			continue
		}
		switch tokens[i].text {
		case "{":
			braces++
		case "}":
			if braces > 0 {
				braces--
			}
		case "[":
			brackets++
		case "]":
			if brackets > 0 {
				brackets--
			}
		case "(":
			parentheses++
		case ")":
			if parentheses > 0 {
				parentheses--
			}
		case ",":
			if braces == 0 && brackets == 0 && parentheses == 0 {
				return i
			}
		}
	}
	return len(tokens)
}

func parseTypeScriptStringArray(tokens []typeScriptToken) ([]string, error) {
	if len(tokens) < 2 || !isTypeScriptPunctuation(tokens[0], "[") || !isTypeScriptPunctuation(tokens[len(tokens)-1], "]") {
		return nil, fmt.Errorf("must be a string array literal")
	}
	var values []string
	expectValue := true
	for _, token := range tokens[1 : len(tokens)-1] {
		if expectValue {
			if token.kind != typeScriptString {
				return nil, fmt.Errorf("contains a non-string value")
			}
			values = append(values, token.text)
			expectValue = false
			continue
		}
		if !isTypeScriptPunctuation(token, ",") {
			return nil, fmt.Errorf("contains a non-comma separator")
		}
		expectValue = true
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("must not be empty")
	}
	return values, nil
}

func parseSingleTypeScriptString(tokens []typeScriptToken) (string, error) {
	if len(tokens) != 1 || tokens[0].kind != typeScriptString {
		return "", fmt.Errorf("must be one string literal")
	}
	return tokens[0].text, nil
}

func matchingTypeScriptToken(tokens []typeScriptToken, start int, open, closing string) (int, error) {
	depth := 0
	for i := start; i < len(tokens); i++ {
		if isTypeScriptPunctuation(tokens[i], open) {
			depth++
		}
		if isTypeScriptPunctuation(tokens[i], closing) {
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("missing closing %s", closing)
}

func isTypeScriptIdentifier(token typeScriptToken, value string) bool {
	return token.kind == typeScriptIdentifier && token.text == value
}

func isTypeScriptPunctuation(token typeScriptToken, value string) bool {
	return token.kind == typeScriptPunctuation && token.text == value
}

func lexTypeScript(source []byte) ([]typeScriptToken, error) {
	var tokens []typeScriptToken
	for i := 0; i < len(source); {
		switch {
		case isTypeScriptSpace(source[i]):
			i++
		case source[i] == '/' && i+1 < len(source) && source[i+1] == '/':
			i += 2
			for i < len(source) && source[i] != '\n' {
				i++
			}
		case source[i] == '/' && i+1 < len(source) && source[i+1] == '*':
			start := i
			i += 2
			for i+1 < len(source) && (source[i] != '*' || source[i+1] != '/') {
				i++
			}
			if i+1 >= len(source) {
				return nil, fmt.Errorf("unterminated block comment at byte %d", start)
			}
			i += 2
		case source[i] == '\'' || source[i] == '"' || source[i] == '`':
			token, next, err := lexTypeScriptString(source, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
			i = next
		case isTypeScriptIdentifierStart(source[i]):
			start := i
			i++
			for i < len(source) && isTypeScriptIdentifierContinue(source[i]) {
				i++
			}
			tokens = append(tokens, typeScriptToken{kind: typeScriptIdentifier, text: string(source[start:i]), offset: start})
		default:
			tokens = append(tokens, typeScriptToken{kind: typeScriptPunctuation, text: string(source[i]), offset: i})
			i++
		}
	}
	return tokens, nil
}

func lexTypeScriptString(source []byte, start int) (typeScriptToken, int, error) {
	quote := source[start]
	var value strings.Builder
	for i := start + 1; i < len(source); i++ {
		if source[i] == quote {
			return typeScriptToken{kind: typeScriptString, text: value.String(), offset: start}, i + 1, nil
		}
		if source[i] != '\\' {
			value.WriteByte(source[i])
			continue
		}
		i++
		if i >= len(source) {
			break
		}
		switch source[i] {
		case 'n':
			value.WriteByte('\n')
		case 'r':
			value.WriteByte('\r')
		case 't':
			value.WriteByte('\t')
		default:
			value.WriteByte(source[i])
		}
	}
	return typeScriptToken{}, 0, fmt.Errorf("unterminated string at byte %d", start)
}

func isTypeScriptSpace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func isTypeScriptIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isTypeScriptIdentifierContinue(value byte) bool {
	return isTypeScriptIdentifierStart(value) || value >= '0' && value <= '9'
}
