// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/wire"
)

var (
	ErrSubjectDocument       = errors.New("govern: invalid subject document or alias")
	ErrSubjectDocumentBudget = errors.New("govern: subject document scan resource budget exceeded")
)

// SubjectDocumentBudget bounds complete lifecycle scans, never history turns.
// A scan that exceeds any resource refuses instead of returning partial proof.
type SubjectDocumentBudget struct {
	Bytes, AliasBytes, Tokens, Depth int
	Work                             int64
}

func DefaultSubjectDocumentBudget() SubjectDocumentBudget {
	return SubjectDocumentBudget{Bytes: 8 << 20, AliasBytes: 1 << 20, Tokens: 1 << 20, Depth: 64, Work: 128 << 20}
}
func (b SubjectDocumentBudget) valid() bool {
	return b.Bytes > 0 && b.AliasBytes > 0 && b.Tokens > 0 && b.Depth > 0 && b.Work > 0
}

type subjectLiteral struct {
	pattern *regexp.Regexp
	url     bool
}

// SubjectDocumentMatcher is immutable and safe to share; aliases must already
// belong to the tenant/subject being exported or erased. It grants no access.
type SubjectDocumentMatcher struct {
	literals  []subjectLiteral
	addresses map[netip.Addr]bool
	budget    SubjectDocumentBudget
}

func NewSubjectDocumentMatcher(aliases []string, budget SubjectDocumentBudget) (*SubjectDocumentMatcher, error) {
	if !budget.valid() || len(aliases) == 0 {
		return nil, ErrSubjectDocument
	}
	matcher := &SubjectDocumentMatcher{budget: budget, addresses: map[netip.Addr]bool{}}
	used := 0
	seen := map[string]bool{}
	for _, alias := range aliases {
		if len(alias) > budget.AliasBytes-used {
			return nil, ErrSubjectDocumentBudget
		}
		used += len(alias)
		if !utf8.ValidString(alias) {
			return nil, ErrSubjectDocument
		}
		alias = strings.TrimSpace(alias)
		if alias == "" {
			return nil, ErrSubjectDocument
		}
		normalized := strings.ToLower(alias)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		if address, err := netip.ParseAddr(alias); err == nil {
			matcher.addresses[address.Unmap()] = true
			continue
		}
		if len(alias) > math.MaxInt/32 {
			return nil, ErrSubjectDocumentBudget
		}
		forms := []string{alias, regexp.QuoteMeta(alias), url.PathEscape(alias), url.QueryEscape(alias)}
		alternatives := make([]string, 0, len(forms))
		unique := map[string]bool{}
		for _, form := range forms {
			if !unique[form] {
				unique[form] = true
				alternatives = append(alternatives, regexp.QuoteMeta(form))
			}
		}
		pattern, err := regexp.Compile("(?i)(?:" + strings.Join(alternatives, "|") + ")")
		if err != nil {
			return nil, ErrSubjectDocumentBudget
		}
		matcher.literals = append(matcher.literals, subjectLiteral{pattern: pattern, url: strings.Contains(alias, "://")})
	}
	return matcher, nil
}

// MatchJSON validates and scans the entire document, including nested keys and
// values. Numbers are never coerced to identities. A positive prefix cannot
// hide malformed/truncated trailing data or an incomplete scan.
func (m *SubjectDocumentMatcher) MatchJSON(ctx context.Context, body []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if m == nil || !m.budget.valid() {
		return false, ErrSubjectDocument
	}
	if len(body) > m.budget.Bytes {
		return false, ErrSubjectDocumentBudget
	}
	if !wire.ExactJSONUnicode(ctx, string(body)) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return false, ErrSubjectDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	seen, matched := false, false
	depth, tokens := 0, 0
	remaining := m.budget.Work
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		token, err := decoder.Token()
		if err == io.EOF {
			if !seen || depth != 0 {
				return false, ErrSubjectDocument
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			return matched, nil
		}
		if err != nil || seen && depth == 0 {
			return false, ErrSubjectDocument
		}
		seen = true
		if tokens >= m.budget.Tokens {
			return false, ErrSubjectDocumentBudget
		}
		tokens++
		switch value := token.(type) {
		case json.Delim:
			if value == '{' || value == '[' {
				depth++
				if depth > m.budget.Depth {
					return false, ErrSubjectDocumentBudget
				}
			} else {
				depth--
			}
		case string:
			if !matched {
				matched, err = m.matchText(ctx, value, &remaining)
				if err != nil {
					return false, err
				}
			}
		}
	}
}

func consumeSubjectScan(remaining *int64, size int) error {
	if int64(size) > *remaining {
		return ErrSubjectDocumentBudget
	}
	*remaining -= int64(size)
	return nil
}

func (m *SubjectDocumentMatcher) matchText(ctx context.Context, text string, remaining *int64) (bool, error) {
	if len(m.addresses) > 0 {
		if err := consumeSubjectScan(remaining, len(text)); err != nil {
			return false, err
		}
		matched, err := m.addressMention(ctx, text)
		if err != nil || matched {
			return matched, err
		}
	}
	for _, literal := range m.literals {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := consumeSubjectScan(remaining, len(text)); err != nil {
			return false, err
		}
		offset := 0
		for offset < len(text) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			match := literal.pattern.FindStringIndex(text[offset:])
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if match == nil {
				break
			}
			first, last := offset+match[0], offset+match[1]
			if subjectBoundaryBefore(text, first) && subjectBoundaryAfter(text, last, literal.url) {
				return true, nil
			}
			offset = last
		}
	}
	return false, ctx.Err()
}

func subjectIdentifierRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsNumber(value) || unicode.IsMark(value) || strings.ContainsRune("_.@%+-", value)
}
func subjectBoundaryBefore(text string, index int) bool {
	if index == 0 {
		return true
	}
	before := strings.TrimRight(text[:index], ".")
	if before == "" {
		return true
	}
	value, _ := utf8.DecodeLastRuneInString(before)
	return !subjectIdentifierRune(value)
}
func subjectBoundaryAfter(text string, index int, url bool) bool {
	after := strings.TrimLeft(text[index:], ".")
	if after == "" {
		return true
	}
	value, _ := utf8.DecodeRuneInString(after)
	if url {
		return unicode.IsSpace(value) || strings.ContainsRune("\"'<>)]},;!", value)
	}
	return !subjectIdentifierRune(value)
}

func subjectAddressRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsNumber(value) || unicode.IsMark(value) || strings.ContainsRune("[]:.%_+-\\", value)
}
func (m *SubjectDocumentMatcher) addressMention(ctx context.Context, text string) (bool, error) {
	start := -1
	for index, value := range text {
		if index%4096 == 0 && ctx.Err() != nil {
			return false, ctx.Err()
		}
		if subjectAddressRune(value) {
			if start < 0 {
				start = index
			}
			continue
		}
		if start >= 0 {
			if m.addressToken(text[start:index]) {
				return true, nil
			}
			start = -1
		}
	}
	return start >= 0 && m.addressToken(text[start:]), ctx.Err()
}
func (m *SubjectDocumentMatcher) addressToken(text string) bool {
	text = strings.Trim(text, ".")
	if decoded, err := url.PathUnescape(text); err == nil && utf8.ValidString(decoded) {
		text = decoded
	}
	text = subjectAddressEscapes.Replace(text)
	address, err := netip.ParseAddr(text)
	if err != nil {
		if endpoint, parseErr := netip.ParseAddrPort(text); parseErr == nil {
			address = endpoint.Addr()
		} else {
			address, err = netip.ParseAddr(strings.Trim(text, "[]"))
			if err != nil {
				return false
			}
		}
	}
	address = address.Unmap()
	return m.addresses[address] || address.Zone() != "" && m.addresses[address.WithZone("")]
}

var subjectAddressEscapes = strings.NewReplacer(`\.`, `.`, `\:`, `:`, `\[`, `[`, `\]`, `]`)
