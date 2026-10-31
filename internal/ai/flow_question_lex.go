// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type questionToken struct {
	text   string
	lower  string
	quoted bool
	start  int
	end    int
}

// Quoted literals keep exact case/decimal/regex bytes. Punctuation separates
// grammar, never a storage expression. All allocation is input/cost bounded.
func lexFlowQuestion(ctx context.Context, question string, budget FlowQuestionBudget) ([]questionToken, error) {
	if budget.Validate() != nil || len(question) > budget.Bytes {
		return nil, ErrFlowQuestionBudget
	}
	if strings.TrimSpace(question) == "" || !utf8.ValidString(question) {
		return nil, ErrFlowQuestionInput
	}
	var tokens []questionToken
	depth := 0
	for offset := 0; offset < len(question); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, size := utf8.DecodeRuneInString(question[offset:])
		if unicode.IsSpace(r) {
			offset += size
			continue
		}
		if r < 32 || r == 127 {
			return nil, ErrFlowQuestionInput
		}
		start := offset
		token := questionToken{start: start}
		switch {
		case r == '\'' || r == '"' || r == '`':
			value, next, err := quotedQuestionValue(question, offset, byte(r))
			if err != nil {
				return nil, err
			}
			token.text, token.quoted, offset = value, true, next
		case strings.ContainsRune("(),;?=<>!&|", r):
			offset += size
			if offset < len(question) {
				switch question[start : offset+1] {
				case "==", "!=", "<=", ">=", "<>", "&&", "||":
					offset++
				}
			}
			token.text = question[start:offset]
			switch token.text {
			case "(":
				depth++
				if depth > budget.Nesting {
					return nil, ErrFlowQuestionBudget
				}
			case ")":
				depth--
				if depth < 0 {
					return nil, ErrFlowQuestionInput
				}
			}
		default:
			for offset < len(question) {
				next, width := utf8.DecodeRuneInString(question[offset:])
				if unicode.IsSpace(next) || strings.ContainsRune("(),;?=<>!&|\"'`", next) {
					break
				}
				if next < 32 || next == 127 {
					return nil, ErrFlowQuestionInput
				}
				offset += width
			}
			token.text = question[start:offset]
		}
		token.lower, token.end = strings.ToLower(token.text), offset
		if len(tokens) >= budget.Tokens {
			return nil, ErrFlowQuestionBudget
		}
		tokens = append(tokens, token)
	}
	if depth != 0 || len(tokens) == 0 {
		return nil, ErrFlowQuestionInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func quotedQuestionValue(input string, start int, quote byte) (string, int, error) {
	for offset := start + 1; offset < len(input); offset++ {
		if input[offset] == '\\' && quote != '`' {
			offset++
			continue
		}
		if input[offset] != quote {
			continue
		}
		text := input[start+1 : offset]
		switch quote {
		case '"':
			decoded, err := strconv.Unquote(input[start : offset+1])
			if err != nil {
				return "", 0, ErrFlowQuestionInput
			}
			text = decoded
		case '\'':
			text = strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(text)
		}
		if !utf8.ValidString(text) {
			return "", 0, ErrFlowQuestionInput
		}
		return text, offset + 1, nil
	}
	return "", 0, ErrFlowQuestionInput
}
