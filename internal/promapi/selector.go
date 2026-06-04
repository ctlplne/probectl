package promapi

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TenantLabel is the label that carries the tenant boundary on every series.
const TenantLabel = "tenant_id"

// maxRegexLen bounds caller-supplied regex matchers (untrusted input).
const maxRegexLen = 256

// Matcher is one label condition in a selector.
type Matcher struct {
	Name  string
	Op    string // "=" | "!=" | "=~" | "!~"
	Value string

	re *regexp.Regexp // compiled, fully anchored (regex ops only)
}

// Selector is a parsed series selector: a metric name (optional) plus matchers.
// It is the ONLY query shape probectl evaluates or forwards (see package doc).
type Selector struct {
	Metric   string
	Matchers []Matcher
}

var (
	metricRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelRe  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// ParseSelector parses a strict series selector:
//
//	metric
//	metric{label="v", other!="w", re=~"x.*", nre!~"y"}
//	{label="v"}
//
// Anything else — functions, operators, offsets, @ modifiers, subqueries —
// is an error: a query that cannot be fully parsed cannot be tenant-scoped.
func ParseSelector(expr string) (Selector, error) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return Selector{}, fmt.Errorf("empty query")
	}
	var sel Selector
	brace := strings.IndexByte(s, '{')
	if brace == -1 {
		if !metricRe.MatchString(s) {
			return Selector{}, errNotSelector(s)
		}
		sel.Metric = s
		return sel, nil
	}
	name := strings.TrimSpace(s[:brace])
	if name != "" {
		if !metricRe.MatchString(name) {
			return Selector{}, errNotSelector(s)
		}
		sel.Metric = name
	}
	if !strings.HasSuffix(s, "}") {
		return Selector{}, fmt.Errorf("unterminated selector")
	}
	body := s[brace+1 : len(s)-1]
	matchers, err := parseMatchers(body)
	if err != nil {
		return Selector{}, err
	}
	sel.Matchers = matchers
	return sel, nil
}

func errNotSelector(s string) error {
	return fmt.Errorf("unsupported expression %q: probectl serves series selectors only (metric{label=\"value\",...}); PromQL functions/operators are not supported", truncate(s, 80))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// parseMatchers parses `label op "value", ...` (trailing comma tolerated).
func parseMatchers(body string) ([]Matcher, error) {
	var out []Matcher
	i := 0
	for {
		// skip whitespace + separators
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == ',') {
			i++
		}
		if i >= len(body) {
			return out, nil
		}
		// label name
		j := i
		for j < len(body) && (isAlnum(body[j]) || body[j] == '_') {
			j++
		}
		name := body[i:j]
		if !labelRe.MatchString(name) {
			return nil, fmt.Errorf("invalid label name at %q", truncate(body[i:], 30))
		}
		i = j
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		// operator
		var op string
		switch {
		case strings.HasPrefix(body[i:], "=~"):
			op, i = "=~", i+2
		case strings.HasPrefix(body[i:], "!~"):
			op, i = "!~", i+2
		case strings.HasPrefix(body[i:], "!="):
			op, i = "!=", i+2
		case strings.HasPrefix(body[i:], "="):
			op, i = "=", i+1
		default:
			return nil, fmt.Errorf("expected matcher operator after %q", name)
		}
		for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
			i++
		}
		// quoted value (double or single quotes)
		if i >= len(body) || (body[i] != '"' && body[i] != '\'') {
			return nil, fmt.Errorf("expected quoted value for label %q", name)
		}
		quote := body[i]
		i++
		var val strings.Builder
		closed := false
		for i < len(body) {
			c := body[i]
			if c == '\\' && i+1 < len(body) {
				n := body[i+1]
				switch n {
				case '\\', '"', '\'':
					val.WriteByte(n)
				case 'n':
					val.WriteByte('\n')
				case 't':
					val.WriteByte('\t')
				default:
					val.WriteByte('\\')
					val.WriteByte(n)
				}
				i += 2
				continue
			}
			if c == quote {
				closed = true
				i++
				break
			}
			val.WriteByte(c)
			i++
		}
		if !closed {
			return nil, fmt.Errorf("unterminated value for label %q", name)
		}
		m := Matcher{Name: name, Op: op, Value: val.String()}
		if op == "=~" || op == "!~" {
			if len(m.Value) > maxRegexLen {
				return nil, fmt.Errorf("regex matcher for %q exceeds %d bytes", name, maxRegexLen)
			}
			re, err := regexp.Compile("^(?:" + m.Value + ")$")
			if err != nil {
				return nil, fmt.Errorf("invalid regex for label %q: %v", name, err)
			}
			m.re = re
		}
		out = append(out, m)
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ForceTenant returns the selector with every caller-supplied tenant_id matcher
// REMOVED and a single tenant_id="<tenant>" equality injected. This is the
// tenant boundary: whatever the caller asked for, they get their own tenant.
func ForceTenant(sel Selector, tenant string) Selector {
	out := Selector{Metric: sel.Metric}
	for _, m := range sel.Matchers {
		if m.Name == TenantLabel {
			continue
		}
		out.Matchers = append(out.Matchers, m)
	}
	out.Matchers = append(out.Matchers, Matcher{Name: TenantLabel, Op: "=", Value: tenant})
	return out
}

// String reconstructs the canonical selector from the parsed form (escaped,
// sorted matchers). Only this reconstruction — never raw caller input — is
// forwarded to an upstream TSDB.
func (s Selector) String() string {
	var b strings.Builder
	b.WriteString(s.Metric)
	ms := make([]Matcher, len(s.Matchers))
	copy(ms, s.Matchers)
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Name != ms[j].Name {
			return ms[i].Name < ms[j].Name
		}
		return ms[i].Op < ms[j].Op
	})
	if len(ms) > 0 {
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(m.Name)
			b.WriteString(m.Op)
			b.WriteString(quoteValue(m.Value))
		}
		b.WriteByte('}')
	}
	return b.String()
}

// quoteValue double-quotes v with Prometheus escaping.
func quoteValue(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Matches reports whether a series (metric name + labels) satisfies the
// selector. __name__ matchers are honored against the metric name.
func (s Selector) Matches(metric string, labels map[string]string) bool {
	if s.Metric != "" && metric != s.Metric {
		return false
	}
	for _, m := range s.Matchers {
		v := labels[m.Name]
		if m.Name == "__name__" {
			v = metric
		}
		switch m.Op {
		case "=":
			if v != m.Value {
				return false
			}
		case "!=":
			if v == m.Value {
				return false
			}
		case "=~":
			if m.re == nil || !m.re.MatchString(v) {
				return false
			}
		case "!~":
			if m.re != nil && m.re.MatchString(v) {
				return false
			}
		}
	}
	return true
}
