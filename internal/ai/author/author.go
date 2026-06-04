package author

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/testspec"
)

// Proposal is an AI-authored test config pending human confirmation. It is NEVER
// auto-applied — the user reviews it and creates the test via the test API
// (propose, don't auto-apply).
type Proposal struct {
	Spec      testspec.Spec `json:"spec"`
	Rationale string        `json:"rationale,omitempty"`
	Source    string        `json:"source"`
}

// Errors. ErrCannotAuthor: a valid config could not be derived from the request.
// ErrModelUnavailable: the model backend failed.
var (
	ErrCannotAuthor     = errors.New("could not derive a test from the request")
	ErrModelUnavailable = errors.New("the model backend is unavailable")
)

// Proposer turns a prompt into a candidate spec + rationale. Implementations: the
// deterministic HeuristicAuthor (default, air-gapped) and the model-backed
// ModelAuthor.
type Proposer interface {
	Propose(ctx context.Context, prompt string) (testspec.Spec, string, error)
	Name() string
}

// Engine authors test configs. Whatever the proposer, the result is ALWAYS
// schema-validated before it is returned, so an invalid config is never surfaced
// for confirmation (S26 watch-out).
type Engine struct{ p Proposer }

// NewEngine builds an authoring engine over a proposer.
func NewEngine(p Proposer) *Engine { return &Engine{p: p} }

// Author proposes a schema-valid test config from a natural-language request.
func (e *Engine) Author(ctx context.Context, prompt string) (Proposal, error) {
	spec, rationale, err := e.p.Propose(ctx, strings.TrimSpace(prompt))
	if err != nil {
		return Proposal{}, err
	}
	clean, err := testspec.Clean(spec)
	if err != nil {
		return Proposal{}, fmt.Errorf("%w: the authored config was invalid (%v)", ErrCannotAuthor, err)
	}
	return Proposal{Spec: clean, Rationale: rationale, Source: e.p.Name()}, nil
}

// --- heuristic (default, air-gapped) ---

// HeuristicAuthor derives a config deterministically — fully air-gapped, no model.
// It extracts a target + type from the request (URLs, IPs, hostnames, ports, and a
// few well-known services).
type HeuristicAuthor struct{}

// Name identifies the heuristic author.
func (HeuristicAuthor) Name() string { return "heuristic" }

// Propose derives a spec from the prompt.
func (HeuristicAuthor) Propose(_ context.Context, prompt string) (testspec.Spec, string, error) {
	return heuristicSpec(prompt)
}

var (
	reURL  = regexp.MustCompile(`https?://[^\s]+`)
	reIP   = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reHost = regexp.MustCompile(`\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b`)
	rePort = regexp.MustCompile(`(?:port\s+|:)(\d{2,5})`)
)

// serviceAliases lets the air-gapped heuristic recognize a few well-known
// services by name (so "check Salesforce login" yields a real HTTP target). The
// model path generalizes beyond these.
var serviceAliases = []struct{ alias, host string }{
	{"salesforce", "login.salesforce.com"},
	{"office 365", "login.microsoftonline.com"},
	{"office365", "login.microsoftonline.com"},
	{"microsoft 365", "login.microsoftonline.com"},
	{"gmail", "mail.google.com"},
	{"github", "github.com"},
	{"okta", "okta.com"},
	{"slack", "slack.com"},
	{"zoom", "zoom.us"},
}

func heuristicSpec(prompt string) (testspec.Spec, string, error) {
	lower := strings.ToLower(prompt)
	port := extractPort(lower)

	var typ, target, why string
	switch {
	case reURL.FindString(prompt) != "":
		typ, target, why = "http", reURL.FindString(prompt), "Detected a URL in the request."
	case reIP.FindString(prompt) != "":
		ip := reIP.FindString(prompt)
		switch {
		case port > 0:
			typ, target = portType(lower), hostPort(ip, port)
		// An explicit reachability verb wins over generic web-ish hints like "site"
		// (e.g. "ping 9.9.9.9 from every site" is an ICMP test, not an HTTP one).
		case containsAny(lower, "ping", "icmp", "reachab", "alive"):
			typ, target = "icmp", ip
		case containsAny(lower, "http", "https", "web", "login", "site"):
			typ, target = "http", "http://"+ip
		default:
			typ, target = "icmp", ip
		}
		why = "Detected an IP address in the request."
	case reHost.FindString(lower) != "":
		host := reHost.FindString(lower)
		typ, target = hostType(lower, host, port)
		why = "Detected a hostname in the request."
	default:
		if alias, host := matchAlias(lower); host != "" {
			typ, target, why = "http", "https://"+host, "Recognized the service "+alias+"."
		} else {
			return testspec.Spec{}, "", fmt.Errorf("%w (no hostname, IP, or URL found — try including one, or configure a model)", ErrCannotAuthor)
		}
	}

	name := truncate(displayHost(target)+" ("+strings.ToUpper(typ)+")", 200)
	return testspec.Spec{Name: name, Type: typ, Target: target, Enabled: true}, why, nil
}

func hostType(lower, host string, port int) (string, string) {
	switch {
	case port > 0:
		return portType(lower), hostPort(host, port)
	case containsAny(lower, "dns", "resolve", "lookup", "nameserver"):
		return "dns", host
	case containsAny(lower, "ping", "icmp", "reachab", "alive"):
		return "icmp", host
	default:
		return "http", "https://" + host // default a bare hostname to a web check
	}
}

func portType(lower string) string {
	if strings.Contains(lower, "udp") {
		return "udp"
	}
	return "tcp"
}

func extractPort(s string) int {
	if m := rePort.FindStringSubmatch(s); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 0
}

func matchAlias(lower string) (string, string) {
	for _, a := range serviceAliases {
		if strings.Contains(lower, a.alias) {
			return a.alias, a.host
		}
	}
	return "", ""
}

// --- model-backed ---

// Completer is the generic chat seam (satisfied by the S24 ai.HTTPModel).
type Completer interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// ModelAuthor proposes a config via a chat model. It asks for strict JSON; the
// Engine then schema-validates the result, so a malformed or invalid model answer
// is rejected, never surfaced.
type ModelAuthor struct {
	c    Completer
	name string
}

// NewModelAuthor wraps a Completer as a Proposer.
func NewModelAuthor(c Completer, name string) *ModelAuthor {
	if name == "" {
		name = "ai"
	}
	return &ModelAuthor{c: c, name: name}
}

// Name identifies the model author.
func (m *ModelAuthor) Name() string { return m.name }

const authorSystemPrompt = "You author probectl synthetic-test (canary) configs. Given a request, output ONLY a JSON " +
	`object: {"name":"...","type":"...","target":"...","interval_seconds":60,"timeout_seconds":3,"params":{},"rationale":"..."}. ` +
	"type MUST be one of icmp, tcp, udp, dns, http. target is a host/IP/URL: a full URL for http, a hostname for dns, " +
	"host:port for tcp/udp, a host or IP for icmp. Do not invent fields or wrap the JSON in prose."

// Propose asks the model for a config.
func (m *ModelAuthor) Propose(ctx context.Context, prompt string) (testspec.Spec, string, error) {
	out, err := m.c.Complete(ctx, authorSystemPrompt, "REQUEST: "+prompt)
	if err != nil {
		return testspec.Spec{}, "", fmt.Errorf("%w: %v", ErrModelUnavailable, err)
	}
	var dto struct {
		Name            string            `json:"name"`
		Type            string            `json:"type"`
		Target          string            `json:"target"`
		IntervalSeconds int               `json:"interval_seconds"`
		TimeoutSeconds  int               `json:"timeout_seconds"`
		Params          map[string]string `json:"params"`
		Rationale       string            `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(extractJSON(out)), &dto); err != nil {
		return testspec.Spec{}, "", fmt.Errorf("%w: model returned unparseable JSON", ErrCannotAuthor)
	}
	spec := testspec.Spec{
		Name: dto.Name, Type: dto.Type, Target: dto.Target,
		IntervalSeconds: dto.IntervalSeconds, TimeoutSeconds: dto.TimeoutSeconds,
		Params: dto.Params, Enabled: true,
	}
	return spec, dto.Rationale, nil
}

// --- shared helpers ---

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	if a, b := strings.IndexByte(s, '{'), strings.LastIndexByte(s, '}'); a >= 0 && b > a {
		return s[a : b+1]
	}
	return s
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

func displayHost(t string) string {
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexAny(t, "/?"); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return t
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
