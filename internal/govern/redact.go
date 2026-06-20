// SPDX-License-Identifier: LicenseRef-probectl-TBD

package govern

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Strategy is how a classified value is masked.
type Strategy string

const (
	// StrategyNone leaves the value as-is (not redacted).
	StrategyNone Strategy = "none"
	// StrategyPartial keeps a useful, non-identifying prefix (IP → network,
	// email → first char + domain, MAC → OUI) — the default.
	StrategyPartial Strategy = "partial"
	// StrategyHash replaces the value with a stable salted-free SHA-256 prefix
	// (pseudonymization: correlatable, not reversible).
	StrategyHash Strategy = "hash"
	// StrategyDrop removes the value entirely.
	StrategyDrop Strategy = "drop"
)

const telemetryRedacted = "[redacted]"

var (
	telemetryKeyNormalizer = strings.NewReplacer(".", "_", "-", "_")

	telemetryBearerHeaderRE = regexp.MustCompile(`(?i)\b(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	telemetryBearerRE       = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)
	telemetryCredentialKVRE = regexp.MustCompile(`(?i)\b((?:api[_\-.]?key|access[_\-.]?key|secret|token|password|passwd|pwd)\s*[=:]\s*)[^\s"'&]+`)
	telemetryEmailRE        = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	telemetryMACRE          = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)
	telemetryIPv4RE         = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	telemetryIPv6RE         = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}\b`)
	telemetryURLRE          = regexp.MustCompile(`https?://[^\s"'<>()]+`)
	telemetryPathIDRE       = regexp.MustCompile(`(?i)^(?:[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9]{6,})$`)
)

// Redact masks one value of a category under a strategy. It is idempotent for
// already-masked inputs where it can tell, and never panics on malformed input
// (it falls back to a generic mask). All hashing routes through internal/crypto
// (FIPS, guardrail 3).
func Redact(cat Category, value string, strategy Strategy) string {
	if strategy == StrategyNone || value == "" {
		return value
	}
	if strategy == StrategyDrop {
		return ""
	}
	if strategy == StrategyHash {
		sum := crypto.Hash([]byte(value))
		return "sha256:" + hex.EncodeToString(sum)[:16]
	}
	// StrategyPartial: category-aware masking.
	switch cat {
	case CatIPAddress:
		return redactIP(value)
	case CatEmail:
		return redactEmail(value)
	case CatMAC:
		return redactMAC(value)
	default:
		return redactGeneric(value)
	}
}

// redactIP truncates an IP to its network: IPv4 → /24 (last octet zeroed),
// IPv6 → /48. The network prefix keeps coarse locality for analytics while
// dropping the host identity (IPs-as-PII).
func redactIP(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return redactGeneric(value)
	}
	if v4 := ip.To4(); v4 != nil {
		masked := v4.Mask(net.CIDRMask(24, 32))
		return masked.String() + "/24"
	}
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

// redactEmail keeps the first character of the local part + the domain.
func redactEmail(value string) string {
	at := strings.LastIndexByte(value, '@')
	if at <= 0 {
		return redactGeneric(value)
	}
	local, domain := value[:at], value[at+1:]
	first := local[:1]
	return first + "***@" + domain
}

// redactMAC keeps the OUI (first 3 octets, the vendor) and masks the device.
func redactMAC(value string) string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return redactGeneric(value)
	}
	return strings.Join(parts[:3], ":") + ":xx:xx:xx"
}

// redactGeneric keeps the first two characters and masks the rest — enough to
// disambiguate in a UI without revealing the value.
func redactGeneric(value string) string {
	if len(value) <= 2 {
		return "**"
	}
	return value[:2] + strings.Repeat("*", min(len(value)-2, 6))
}

// TelemetryPIIPolicy resolves the tenant policy used for untrusted telemetry
// ingest. It honors tenant strategies/stricter classification, but never falls
// below the built-in PII floor: OTLP logs/traces are receipts for correlation,
// not a raw personal-data warehouse.
func TelemetryPIIPolicy(ctx context.Context, tenantID string) Policy {
	pol := PolicyFor(ctx, tenantID)
	if pol.RedactFrom == ClassUnset || pol.RedactFrom > ClassPII {
		pol.RedactFrom = ClassPII
	}
	if pol.Strategies != nil && pol.Strategies[ClassPII] == StrategyNone {
		cp := make(map[Class]Strategy, len(pol.Strategies))
		for cls, strategy := range pol.Strategies {
			cp[cls] = strategy
		}
		cp[ClassPII] = StrategyPartial
		pol.Strategies = cp
	}
	return pol
}

// RedactTelemetryText masks common PII/secret shapes in unstructured telemetry
// text, such as log bodies and span names. It is intentionally pattern-based:
// the receiver treats inbound OTLP as untrusted and redacts before persistence.
func RedactTelemetryText(pol Policy, value string) string {
	if value == "" {
		return value
	}
	out := telemetryBearerHeaderRE.ReplaceAllString(value, "${1}"+telemetryRedacted)
	out = telemetryBearerRE.ReplaceAllString(out, "${1}"+telemetryRedacted)
	out = telemetryCredentialKVRE.ReplaceAllString(out, "${1}"+telemetryRedacted)
	out = telemetryURLRE.ReplaceAllStringFunc(out, func(raw string) string {
		return redactTelemetryURL(pol, raw)
	})
	out = telemetryEmailRE.ReplaceAllStringFunc(out, func(match string) string {
		return redactTelemetryInline(pol, CatEmail, match)
	})
	out = telemetryMACRE.ReplaceAllStringFunc(out, func(match string) string {
		return redactTelemetryInline(pol, CatMAC, match)
	})
	out = telemetryIPv4RE.ReplaceAllStringFunc(out, func(match string) string {
		ip := net.ParseIP(match)
		if ip == nil || ip.To4() == nil {
			return match
		}
		return redactTelemetryInline(pol, CatIPAddress, match)
	})
	out = telemetryIPv6RE.ReplaceAllStringFunc(out, func(match string) string {
		ip := net.ParseIP(match)
		if ip == nil || ip.To4() != nil {
			return match
		}
		return redactTelemetryInline(pol, CatIPAddress, match)
	})
	return out
}

// RedactTelemetryAttribute masks an OTLP resource/span/log attribute value
// using its key first, then scans the result as free text. Key-based redaction
// catches values like enduser.id that are identifying even when the value has no
// obvious pattern.
func RedactTelemetryAttribute(pol Policy, key, value string) string {
	if value == "" {
		return value
	}
	if cat, ok := CategoryForKey(key); ok {
		if redacted := redactTelemetryInline(pol, cat, value); redacted != value {
			return redacted
		}
	}
	return RedactTelemetryText(pol, value)
}

// CategoryForKey classifies storage columns and telemetry attribute keys. It is
// conservative: known identity, address, and credential names are sensitive by
// default, while unrecognized keys are left to free-text scanning.
func CategoryForKey(key string) (Category, bool) {
	return columnCategory(key)
}

func redactTelemetryInline(pol Policy, cat Category, value string) string {
	strategy := telemetryStrategyFor(pol, cat)
	if strategy == StrategyNone {
		return value
	}
	if strategy == StrategyDrop {
		return telemetryRedacted
	}
	return Redact(cat, value, strategy)
}

func telemetryStrategyFor(pol Policy, cat Category) Strategy {
	if strategy := pol.StrategyFor(cat); strategy != StrategyNone {
		return strategy
	}
	// Built-in PII/restricted categories stay redacted even if a tenant override
	// accidentally weakens the category. That is the fail-closed ingest floor.
	if cls, ok := defaultClass[cat]; ok && cls >= ClassPII {
		if cls == ClassRestricted {
			return StrategyDrop
		}
		return StrategyPartial
	}
	return StrategyNone
}

func redactTelemetryURL(pol Policy, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	if host := u.Hostname(); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			// A CIDR string is not a legal URL host, so use an explicit marker in
			// URLs. Standalone IP attributes/text retain /24 or /48 precision.
			if port := u.Port(); port != "" {
				u.Host = "redacted-ip.invalid:" + port
			} else {
				u.Host = "redacted-ip.invalid"
			}
		}
	}
	if u.Path != "" {
		parts := strings.Split(u.Path, "/")
		for i, part := range parts {
			if part == "" {
				continue
			}
			switch {
			case telemetryPathIDRE.MatchString(part):
				parts[i] = telemetryRedacted
			case telemetryEmailRE.MatchString(part):
				parts[i] = telemetryEmailRE.ReplaceAllStringFunc(part, func(match string) string {
					return redactTelemetryInline(pol, CatEmail, match)
				})
			case net.ParseIP(part) != nil || telemetryMACRE.MatchString(part):
				parts[i] = telemetryRedacted
			default:
				parts[i] = telemetryCredentialKVRE.ReplaceAllString(part, "${1}"+telemetryRedacted)
			}
		}
		u.Path = strings.Join(parts, "/")
	}
	return u.String()
}

// columnCategory maps a Postgres column name to a category, so the redacted
// export knows which values are sensitive. The mapping is heuristic by design
// (substring match on well-known network field names) and documented as such;
// per-tenant overrides re-classify the resulting CATEGORY, not the column.
// Returns ("", false) for columns with no sensitive category.
func columnCategory(column string) (Category, bool) {
	c := telemetryKeyNormalizer.Replace(strings.ToLower(column))
	switch {
	case c == "secret" || c == "wrapped_kek" || c == "byok_ref" ||
		strings.Contains(c, "password") || strings.Contains(c, "token") ||
		strings.HasSuffix(c, "_secret") || strings.Contains(c, "private_key") ||
		// GOVERN-001: API/secret-key columns were unclassified and leaked in
		// cleartext through "redacted" exports. Treat key columns as credentials
		// by default (fail closed); a tenant may re-classify via Policy.Overrides.
		strings.Contains(c, "api_key") || strings.Contains(c, "apikey") ||
		strings.HasSuffix(c, "_key") || c == "key" || c == "authorization" ||
		strings.HasSuffix(c, "_authorization"):
		return CatCredential, true
	case c == "email" || strings.HasSuffix(c, "_email"):
		return CatEmail, true
	case c == "user_id" || c == "enduser_id" || c == "username" ||
		c == "user_name" || c == "account_id" || c == "session_id" ||
		c == "sid" || strings.HasSuffix(c, "_user_id") ||
		strings.HasSuffix(c, "_account_id") || strings.HasSuffix(c, "_session_id"):
		return CatSubjectID, true
	// GOVERN-001: MAC columns (mac_addr, mac_address, *_mac) must be caught here,
	// BEFORE the IP "_addr" net below — otherwise "mac_addr" ends with "_addr"
	// and is misclassified as an IP (wrong category + wrong redaction strategy).
	case strings.Contains(c, "mac_addr") || c == "mac" || strings.HasSuffix(c, "_mac"):
		return CatMAC, true
	case strings.Contains(c, "user_agent"):
		return CatUserAgent, true
	case c == "asn" || strings.HasSuffix(c, "_asn"):
		return CatASN, true
	case c == "city" || c == "region" || c == "country" || c == "latitude" || c == "longitude" || strings.Contains(c, "geo"):
		return CatGeo, true
	case c == "hostname" || strings.HasSuffix(c, "_hostname") || c == "host":
		return CatHostname, true
	// IP addresses: the broadest net — *address, *_addr, *_ip, source/dest,
	// exporter, next_hop, target (probe targets are frequently IPs).
	case strings.Contains(c, "address") || strings.HasSuffix(c, "_addr") ||
		strings.HasSuffix(c, "_ip") || c == "ip" || c == "exporter" ||
		c == "next_hop" || c == "target":
		return CatIPAddress, true
	default:
		return "", false
	}
}

// RedactRow masks the sensitive columns of a decoded row in place under the
// policy. Only string values are masked (numbers/bools are not categorized);
// a column classified below the policy's RedactFrom is left untouched.
func RedactRow(pol Policy, row map[string]any) {
	for col, v := range row {
		cat, ok := columnCategory(col)
		if !ok {
			continue
		}
		strategy := pol.StrategyFor(cat)
		if strategy == StrategyNone {
			continue
		}
		s, ok := v.(string)
		if !ok {
			// Non-string sensitive value (e.g. a numeric ASN): drop/keep per
			// strategy without category-specific masking.
			if strategy == StrategyDrop {
				row[col] = nil
			}
			continue
		}
		row[col] = Redact(cat, s, strategy)
	}
}

// RedactJSONL redacts a buffer of newline-delimited JSON objects (one row per
// line) under the policy, returning the redacted buffer. Lines that do not
// parse as a JSON object pass through unchanged (the export stays well-formed).
func RedactJSONL(pol Policy, in []byte) []byte {
	if len(in) == 0 {
		return in
	}
	lines := strings.Split(strings.TrimRight(string(in), "\n"), "\n")
	var b strings.Builder
	b.Grow(len(in))
	for _, line := range lines {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		RedactRow(pol, row)
		out, err := json.Marshal(row)
		if err != nil {
			b.WriteString(line)
		} else {
			b.Write(out)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
