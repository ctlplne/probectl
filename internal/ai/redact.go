// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/redactpat"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Pre-egress redaction (U-013, C8): before a prompt leaves the network to a
// REMOTE model, IPs (configurable), hostnames (per policy) and obvious
// secrets/tokens (always) are masked. Masking is deterministic for the same
// tenant + secret + value, so the model can still correlate evidence without
// ever seeing the value. The local paths (builtin model, loopback Ollama/vLLM)
// are never redacted.

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
	// load, fail-closed on a bad pattern) masked as [custom:<token>] — for
	// org-specific identifiers (employee IDs, ticket numbers, internal
	// naming) no generic pattern can know.
	CustomPatterns []*regexp.Regexp
	// TokenKey is a 32-byte deployment secret used to derive tenant-scoped
	// redaction HMAC keys. If absent, probectl falls back to a process-local
	// random key: still not dictionary-reversible by a remote model, but tokens
	// rotate on restart.
	TokenKey []byte
}

// DefaultRedaction is the remote-model default. The hostname decision is
// DELIBERATE (S-e5e1b903): hostnames are masked.
//
// probectl's central promise is that telemetry does not leave the operator's
// network. An FQDN is not incidental context — internal naming conventions
// leak service inventories, environments, tenant names and topology to a
// third-party provider verbatim, and the remote path is exactly the boundary
// that promise is about. Masking is tenant-scoped and STABLE, so a model can
// still reason about "the same host appears in both signals" without learning
// which host it is; that keeps RCA useful while the identifier stays inside.
//
// An operator who judges the tradeoff differently can set
// PROBECTL_AI_REDACT_HOSTNAMES=false — the decision is theirs to reverse
// explicitly, which is not the same as it silently defaulting open.
var DefaultRedaction = RedactionPolicy{MaskIPs: true, MaskHostnames: true, MaskPII: true}

var (
	// The shapes are defined ONCE in internal/redactpat and shared with the
	// governance/support path (S-e5e1b903): two engines carrying parallel
	// regexes is how a masking fix lands in one and the other keeps leaking.
	// Secrets and IPs are applied through redactpat helpers (recognition);
	// this package still owns the STRATEGY (tenant-scoped keyed tokens).
	reHostname = redactpat.Hostname

	// Free-text PII (AIRCA-002). Email masking runs before the hostname
	// pass, so the domain part is consumed as part of the address. Phone
	// patterns are deliberately conservative (international +prefix, or
	// separator-structured shapes) — telemetry is full of digit runs, and
	// the IP pass has already consumed dotted quads.
	reEmail = redactpat.Email
	rePhone = regexp.MustCompile(`\+\d{1,3}[ .-]?\(?\d{1,4}\)?(?:[ .-]\d{2,4}){1,3}\b|\(\d{3}\)\s?\d{3}[-.]\d{4}\b|\b\d{3}[-.]\d{3}[-.]\d{4}\b`)
	reMAC   = redactpat.MAC
)

var processRedactionKey = mustProcessRedactionKey()

func mustProcessRedactionKey() []byte {
	key, err := crypto.Random(crypto.KeySize)
	if err != nil {
		panic(fmt.Sprintf("ai: redaction token key: %v", err))
	}
	return key
}

// redactText applies the policy to one string.
func redactText(s string, pol RedactionPolicy) string {
	return redactTextForTenant(s, pol, "")
}

// redactTextForTenant applies the policy to one string using tenant-scoped,
// keyed tokens. Tenant scope prevents one tenant's low-entropy token dictionary
// from matching another tenant's values.
func redactTextForTenant(s string, pol RedactionPolicy, tenantID string) string {
	// Secrets first (always), so an IP inside a token is gone either way. The
	// SHAPES come from redactpat.Secrets() — this path never keeps its own
	// list, so a shape added there is masked here without an edit.
	s = redactpat.MaskSecrets(s, func(_ redactpat.SecretShape, m string) string {
		return mask("secret", m, pol, tenantID)
	})

	if pol.MaskIPs {
		// Recognition (regex + parse + standalone-token check) is shared;
		// the token strategy stays here.
		s = redactpat.MaskIPv6(s, func(m string) string { return mask("ip", m, pol, tenantID) })
		s = redactpat.MaskIPv4(s, func(m string) string { return mask("ip", m, pol, tenantID) })
	}
	if pol.MaskPII {
		// Email first (its domain must not survive into the hostname pass);
		// MAC before phone (a '-'-separated MAC must not half-match a
		// separator-structured phone shape).
		s = reEmail.ReplaceAllStringFunc(s, func(m string) string { return mask("email", m, pol, tenantID) })
		s = reMAC.ReplaceAllStringFunc(s, func(m string) string { return mask("mac", m, pol, tenantID) })
		s = rePhone.ReplaceAllStringFunc(s, func(m string) string { return mask("phone", m, pol, tenantID) })
	}
	if pol.MaskHostnames {
		s = reHostname.ReplaceAllStringFunc(s, func(m string) string { return mask("host", m, pol, tenantID) })
	}
	for _, re := range pol.CustomPatterns {
		if re == nil {
			continue
		}
		s = re.ReplaceAllStringFunc(s, func(m string) string { return mask("custom", m, pol, tenantID) })
	}
	return s
}

// RedactTextForTenant masks one operator-supplied string for durable storage or
// remote egress using the same tenant-scoped tokenization as the AI egress path.
func RedactTextForTenant(s string, pol RedactionPolicy, tenantID string) string {
	return redactTextForTenant(s, pol, tenantID)
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

// mask renders a stable, non-reversible token for value. It deliberately uses
// internal/crypto instead of importing crypto primitives here: redaction is a
// security boundary, and probectl's crypto boundary stays FIPS-swappable.
func mask(class, value string, pol RedactionPolicy, tenantID string) string {
	key := pol.TokenKey
	if len(key) != crypto.KeySize {
		key = processRedactionKey
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "unknown"
	}
	tenantKey := crypto.Sign(key, []byte("probectl.ai.redaction.tenant.v1\x00"+tenantID))
	mac := crypto.Sign(tenantKey, []byte(class+"\x00"+value))
	return fmt.Sprintf("[%s:%s]", class, hex.EncodeToString(mac[:16]))
}

func redactionTenantFromContext(ctx context.Context) string {
	if p := auth.PrincipalFrom(ctx); p != nil && p.TenantID != "" {
		return p.TenantID
	}
	if tid, ok := tenancy.FromContext(ctx); ok {
		return tid.String()
	}
	return ""
}

// redactSynthesisInput deep-copies the input with the policy applied to the
// question and every evidence title/summary. The caller's evidence is never
// mutated (the local pipeline keeps the raw values for citation display).
func redactSynthesisInput(in SynthesisInput, pol RedactionPolicy) SynthesisInput {
	return redactSynthesisInputForTenant(in, pol, "")
}

func redactSynthesisInputForTenant(in SynthesisInput, pol RedactionPolicy, tenantID string) SynthesisInput {
	out := SynthesisInput{Question: redactTextForTenant(in.Question, pol, tenantID)}
	out.Evidence = make([]Evidence, len(in.Evidence))
	for i, e := range in.Evidence {
		e.Title = redactTextForTenant(e.Title, pol, tenantID)
		e.Summary = redactTextForTenant(e.Summary, pol, tenantID)
		out.Evidence[i] = e
	}
	return out
}

// RedactAnswerForPersistence deep-copies an RCA answer before it is written to
// durable storage. The live HTTP response remains full fidelity; only the
// at-rest artifact is minimized so optional answer persistence does not become a
// searchable archive of raw prompts, IPs, users, tickets, or credentials.
func RedactAnswerForPersistence(ans Answer, pol RedactionPolicy, tenantID string) Answer {
	out := ans
	out.Question = redactTextForTenant(out.Question, pol, tenantID)
	out.RootCause = redactTextForTenant(out.RootCause, pol, tenantID)

	if len(ans.RootCauseCitations) > 0 {
		out.RootCauseCitations = append([]Citation(nil), ans.RootCauseCitations...)
	}
	if len(ans.Findings) > 0 {
		out.Findings = make([]Finding, len(ans.Findings))
		for i, f := range ans.Findings {
			f.Statement = redactTextForTenant(f.Statement, pol, tenantID)
			if len(f.Citations) > 0 {
				f.Citations = append([]Citation(nil), f.Citations...)
			}
			out.Findings[i] = f
		}
	}
	if len(ans.Evidence) > 0 {
		out.Evidence = make([]Evidence, len(ans.Evidence))
		for i, e := range ans.Evidence {
			e.Title = redactTextForTenant(e.Title, pol, tenantID)
			e.Summary = redactTextForTenant(e.Summary, pol, tenantID)
			e.Ref = redactTextForTenant(e.Ref, pol, tenantID)
			e.Fields = redactValueForTenant(e.Fields, pol, tenantID).(Row)
			out.Evidence[i] = e
		}
	}
	return out
}

func redactValueForTenant(v any, pol RedactionPolicy, tenantID string) any {
	switch x := v.(type) {
	case string:
		return redactTextForTenant(x, pol, tenantID)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = redactTextForTenant(s, pol, tenantID)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = redactValueForTenant(v, pol, tenantID)
		}
		return out
	case Row:
		out := make(Row, len(x))
		for k, v := range x {
			out[k] = redactValueForTenant(v, pol, tenantID)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = redactValueForTenant(v, pol, tenantID)
		}
		return out
	default:
		return v
	}
}
