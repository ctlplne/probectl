package siem

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// product identity stamped into every formatted record.
const (
	vendor         = "probectl"
	product        = "probectl"
	productVersion = "1.0"
	sdID           = "probectl@32473" // RFC 5424 structured-data id (private enterprise number placeholder)
)

// Formatter renders a canonical Event into one SIEM-format record.
type Formatter interface {
	// Name is the format identifier (syslog|cef|ecs|otlp).
	Name() string
	// ContentType is the HTTP content type a sender should use.
	ContentType() string
	// Format renders one event.
	Format(Event) []byte
}

// NewFormatter returns the formatter for a format name (ok=false if unknown).
func NewFormatter(name string) (Formatter, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "syslog":
		return syslogFormatter{}, true
	case "cef":
		return cefFormatter{}, true
	case "ecs":
		return ecsFormatter{}, true
	case "otlp":
		return otlpFormatter{}, true
	default:
		return nil, false
	}
}

// sortedKeys returns the attribute keys in a stable order (deterministic output).
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// --- RFC 5424 syslog ---

type syslogFormatter struct{}

func (syslogFormatter) Name() string        { return "syslog" }
func (syslogFormatter) ContentType() string { return "text/plain; charset=utf-8" }

func (syslogFormatter) Format(e Event) []byte {
	const facility = 13 // security/audit
	pri := facility*8 + e.Severity.syslog()
	ts := e.time().Format(time.RFC3339Nano)
	msgID := orDash(sanitizeSD(e.Action))

	var sd strings.Builder
	sd.WriteString("[" + sdID)
	writeSDParam(&sd, "tenant", e.TenantID)
	writeSDParam(&sd, "category", string(e.Category))
	writeSDParam(&sd, "actor", e.Actor)
	writeSDParam(&sd, "target", e.Target)
	if e.Outcome != "" {
		writeSDParam(&sd, "outcome", e.Outcome)
	}
	for _, k := range sortedKeys(e.Attributes) {
		writeSDParam(&sd, sanitizeSDName(k), e.Attributes[k])
	}
	sd.WriteString("]")

	line := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s", pri, ts, product, vendor, msgID, sd.String(), e.message())
	return []byte(line)
}

func writeSDParam(b *strings.Builder, name, value string) {
	b.WriteString(" " + name + "=\"" + escapeSDValue(value) + "\"")
}

// escapeSDValue escapes the RFC 5424 SD-PARAM value specials: '"', '\', ']'.
func escapeSDValue(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(s)
}

func sanitizeSDName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '=' || r == ' ' || r == ']' || r == '"' {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "k"
	}
	return s
}

func sanitizeSD(s string) string { return strings.ReplaceAll(s, " ", "_") }

// --- ArcSight CEF ---

type cefFormatter struct{}

func (cefFormatter) Name() string        { return "cef" }
func (cefFormatter) ContentType() string { return "text/plain; charset=utf-8" }

func (cefFormatter) Format(e Event) []byte {
	header := strings.Join([]string{
		"CEF:0",
		cefEscapeHeader(vendor),
		cefEscapeHeader(product),
		cefEscapeHeader(productVersion),
		cefEscapeHeader(orDash(e.Action)),
		cefEscapeHeader(e.message()),
		strconv.Itoa(e.Severity.cef()),
	}, "|")

	var ext strings.Builder
	writeCEF(&ext, "rt", strconv.FormatInt(e.time().UnixMilli(), 10))
	writeCEF(&ext, "cat", string(e.Category))
	writeCEF(&ext, "suser", e.Actor)
	writeCEF(&ext, "act", e.Action)
	writeCEF(&ext, "dst", e.Target)
	writeCEF(&ext, "outcome", e.Outcome)
	writeCEF(&ext, "dvchost", product)
	writeCEF(&ext, "cs1Label", "tenant")
	writeCEF(&ext, "cs1", e.TenantID)
	for _, k := range sortedKeys(e.Attributes) {
		writeCEF(&ext, cefExtKey(k), e.Attributes[k])
	}
	return []byte(header + "|" + strings.TrimSpace(ext.String()))
}

func writeCEF(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(key + "=" + cefEscapeExt(value) + " ")
}

// cefEscapeHeader escapes '\' and '|' in CEF header fields.
func cefEscapeHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s)
}

// cefEscapeExt escapes '\', '=', and newlines in CEF extension values.
func cefEscapeExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

func cefExtKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '=' || r == ' ' {
			return '_'
		}
		return r
	}, s)
}

// --- Elastic Common Schema (ECS) JSON ---

type ecsFormatter struct{}

func (ecsFormatter) Name() string        { return "ecs" }
func (ecsFormatter) ContentType() string { return "application/json" }

func (ecsFormatter) Format(e Event) []byte {
	doc := map[string]any{
		"@timestamp": e.time().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": "8.11.0"},
		"message":    e.message(),
		"event": map[string]any{
			"kind":     ecsKind(e.Category),
			"category": ecsCategories(e.Category),
			"action":   e.Action,
			"severity": e.Severity.cef(),
		},
		"observer":     map[string]any{"vendor": vendor, "product": product},
		"organization": map[string]any{"id": e.TenantID},
	}
	ev := doc["event"].(map[string]any)
	if e.Outcome != "" {
		ev["outcome"] = e.Outcome
	}
	if e.Actor != "" {
		doc["user"] = map[string]any{"name": e.Actor}
	}
	labels := map[string]string{}
	if e.Target != "" {
		labels["target"] = e.Target
	}
	for k, v := range e.Attributes {
		labels[ecsLabelKey(k)] = v
	}
	if len(labels) > 0 {
		doc["labels"] = labels
	}
	b, _ := json.Marshal(doc)
	return b
}

func ecsKind(c Category) string {
	if c == CategoryThreat {
		return "alert"
	}
	return "event"
}

func ecsCategories(c Category) []string {
	switch c {
	case CategoryThreat:
		return []string{"threat"}
	default:
		return []string{"configuration"}
	}
}

// ecsLabelKey replaces '.' (ECS labels must not contain dots).
func ecsLabelKey(s string) string { return strings.ReplaceAll(s, ".", "_") }

// --- OTLP logs (OTLP/HTTP JSON) ---

type otlpFormatter struct{}

func (otlpFormatter) Name() string        { return "otlp" }
func (otlpFormatter) ContentType() string { return "application/json" }

func (otlpFormatter) Format(e Event) []byte {
	attrs := []map[string]any{
		kv("event.action", e.Action),
		kv("event.category", string(e.Category)),
	}
	if e.Actor != "" {
		attrs = append(attrs, kv("user.name", e.Actor))
	}
	if e.Target != "" {
		attrs = append(attrs, kv("target", e.Target))
	}
	if e.Outcome != "" {
		attrs = append(attrs, kv("event.outcome", e.Outcome))
	}
	for _, k := range sortedKeys(e.Attributes) {
		attrs = append(attrs, kv(k, e.Attributes[k]))
	}
	rec := map[string]any{
		"timeUnixNano":   strconv.FormatInt(e.time().UnixNano(), 10),
		"severityNumber": e.Severity.otlpNumber(),
		"severityText":   strings.ToUpper(string(e.Severity)),
		"body":           map[string]any{"stringValue": e.message()},
		"attributes":     attrs,
	}
	doc := map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{
				kv("service.name", product), kv("probectl.tenant_id", e.TenantID),
			}},
			"scopeLogs": []any{map[string]any{
				"scope":      map[string]any{"name": "probectl.siem"},
				"logRecords": []any{rec},
			}},
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func kv(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
