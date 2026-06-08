package ai

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"regexp"
	"strings"
)

// Pre-egress redaction (U-013, C8): before a prompt leaves the network to a
// REMOTE model, IPs (configurable), hostnames (per policy) and obvious
// secrets/tokens (always) are masked. Masking is deterministic per value —
// the same IP becomes the same token within and across calls — so the model
// can still correlate evidence without ever seeing the value. The local
// paths (builtin model, loopback Ollama/vLLM) are never redacted.

// RedactionPolicy selects what is masked before remote egress. Secrets are
// ALWAYS masked for a remote model regardless of policy.
type RedactionPolicy struct {
	MaskIPs       bool
	MaskHostnames bool
	// MaskPII (AIRCA-002) masks free-text personal identifiers: email
	// addresses, phone numbers, and MAC addresses. Deterministic masking
	// preserves correlation ("the same user appears in both signals")
	// without the value ever leaving.
	MaskPII bool
	// CustomPatterns are operator-supplied regexes (compiled at config
	// load, fail-closed on a bad pattern) masked as [custom:xxxx] — for
	// org-specific identifiers (employee IDs, ticket numbers, internal
	// naming) no generic pattern can know.
	CustomPatterns []*regexp.Regexp
}

// DefaultRedaction is the remote-model default: IPs + free-text PII masked,
// hostnames kept (they are usually the subject of the question), secrets
// always masked.
var DefaultRedaction = RedactionPolicy{MaskIPs: true, MaskHostnames: false, MaskPII: true}

var (
	// Always-on secret shapes: bearer/authorization values, key=value
	// credentials, AWS access key IDs, PEM blocks.
	reBearer = regexp.MustCompile(`(?i)\b(bearer|authorization:)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// The value match excludes quotes so redacting JSON-RENDERED payloads
	// (the MCP surface masks the encoded form) never eats a structural
	// quote and corrupts the document.
	reKV   = regexp.MustCompile(`(?i)\b((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*)[^\s"']+`)
	reAKIA = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePEM  = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)

	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	// IPv6 candidates: two-plus colons over hex groups (covers :: compression
	// and zones); each candidate is then VALIDATED with netip.ParseAddr, so
	// times ("12:30") and C++ scope operators never match.
	reIPv6Candidate = regexp.MustCompile(`(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:%[0-9a-zA-Z]+)?(?:/\d{1,3})?|::[fF]{4}:(?:\d{1,3}\.){3}\d{1,3}`)

	reHostname = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b`)

	// Free-text PII (AIRCA-002). Email masking runs before the hostname
	// pass, so the domain part is consumed as part of the address. Phone
	// patterns are deliberately conservative (international +prefix, or
	// separator-structured shapes) — telemetry is full of digit runs, and
	// the IP pass has already consumed dotted quads.
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	rePhone = regexp.MustCompile(`\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]\d{2,4}){1,3}\b|\(\d{3}\)\s?\d{3}[-.]\d{4}\b|\b\d{3}[-.]\d{3}[-.]\d{4}\b`)
	reMAC   = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
)

// redactText applies the policy to one string.
func redactText(s string, pol RedactionPolicy) string {
	// Secrets first (always), so an IP inside a token is gone either way.
	s = rePEM.ReplaceAllString(s, "[pem:redacted]")
	s = reBearer.ReplaceAllStringFunc(s, func(m string) string { return mask("secret", m) })
	s = reKV.ReplaceAllStringFunc(s, func(m string) string {
		kv := reKV.FindStringSubmatch(m)
		return kv[1] + mask("secret", m)
	})
	s = reAKIA.ReplaceAllStringFunc(s, func(m string) string { return mask("secret", m) })

	if pol.MaskIPs {
		s = reIPv6Candidate.ReplaceAllStringFunc(s, func(m string) string {
			bare := strings.TrimSuffix(m, "/"+lastSlashPart(m))
			if _, err := netip.ParseAddr(strings.TrimSpace(bare)); err != nil {
				return m // not a real v6 address (e.g. a time, "::" prose)
			}
			return mask("ip", m)
		})
		s = reIPv4.ReplaceAllStringFunc(s, func(m string) string { return mask("ip", m) })
	}
	if pol.MaskPII {
		// Email first (its domain must not survive into the hostname pass);
		// MAC before phone (a '-'-separated MAC must not half-match a
		// separator-structured phone shape).
		s = reEmail.ReplaceAllStringFunc(s, func(m string) string { return mask("email", m) })
		s = reMAC.ReplaceAllStringFunc(s, func(m string) string { return mask("mac", m) })
		s = rePhone.ReplaceAllStringFunc(s, func(m string) string { return mask("phone", m) })
	}
	if pol.MaskHostnames {
		s = reHostname.ReplaceAllStringFunc(s, func(m string) string { return mask("host", m) })
	}
	for _, re := range pol.CustomPatterns {
		if re == nil {
			continue
		}
		s = re.ReplaceAllStringFunc(s, func(m string) string { return mask("custom", m) })
	}
	return s
}

// CompileCustomPatterns parses the operator's custom redaction patterns
// (";;"-separated regexes — regexes routinely contain commas). It fails
// closed: one bad pattern refuses the whole config rather than silently
// redacting less than the operator asked for.
func CompileCustomPatterns(spec string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, part := range strings.Split(spec, ";;") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		re, err := regexp.Compile(part)
		if err != nil {
			return nil, fmt.Errorf("ai: bad custom redaction pattern %q: %w", part, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// lastSlashPart returns what follows the final '/' (the CIDR suffix), or ""
// when there is none.
func lastSlashPart(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// mask renders a stable token for value: same value, same token — correlation
// survives, the value does not.
func mask(class, value string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("[%s:%08x]", class, h.Sum32())
}

// redactSynthesisInput deep-copies the input with the policy applied to the
// question and every evidence title/summary. The caller's evidence is never
// mutated (the local pipeline keeps the raw values for citation display).
func redactSynthesisInput(in SynthesisInput, pol RedactionPolicy) SynthesisInput {
	out := SynthesisInput{Question: redactText(in.Question, pol)}
	out.Evidence = make([]Evidence, len(in.Evidence))
	for i, e := range in.Evidence {
		e.Title = redactText(e.Title, pol)
		e.Summary = redactText(e.Summary, pol)
		out.Evidence[i] = e
	}
	return out
}
