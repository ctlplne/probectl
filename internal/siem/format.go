// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"bytes"
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
	// FormatBatch renders several events into ONE payload using the format's
	// native multi-record framing — newline-delimited records for the
	// line/NDJSON formats, a single ExportLogsServiceRequest for OTLP — so one
	// HTTPS POST carries a whole batch instead of a single event (AUD-16: serial
	// one-per-POST export collapsed under SIEM latency). The caller batches a
	// SINGLE tenant's events (per-tenant draining), so a batch never mixes
	// tenants; OTLP additionally groups records by resource/tenant, keeping the
	// no-cross-tenant-mixing invariant local to the framing too (docs/guardrails.md
	// G7-N tenant isolation).
	FormatBatch(events []Event) []byte
}

// joinRecords renders each event with one and joins the records with a newline
// — the multi-record framing the single-line (syslog/CEF) and NDJSON (ECS)
// formats share, which Splunk HEC, syslog collectors and the Elastic/OpenSearch
// bulk ingest all accept.
func joinRecords(events []Event, one func(Event) []byte) []byte {
	if len(events) == 0 {
		return nil
	}
	parts := make([][]byte, 0, len(events))
	for _, e := range events {
		parts = append(parts, one(e))
	}
	return bytes.Join(parts, []byte("\n"))
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

// lineBreakReplacer escapes the structural whitespace control characters (LF,
// CR, HT) to their printable backslash forms. The single-line syslog and CEF
// formatters MUST neutralize these in every tenant-controlled field: a raw CR
// or LF would otherwise split the record and let one tenant forge an event
// attributed to another tenant in the shared SIEM stream (docs/guardrails.md
// G7-N; detection is a signal, never trusted input).
var lineBreakReplacer = strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`)

// isControl reports whether r is a C0/C1 control character (incl. DEL) or a
// Unicode line/paragraph separator - anything a line-oriented SIEM parser might
// treat as a record boundary.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '\u2028' || r == '\u2029'
}

// dropControls removes every control character from s (used for field tokens,
// e.g. SD-NAME / CEF keys / MSGID, where an escaped backslash sequence is not a
// legal character).
func dropControls(s string) string {
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

// oneLine makes an arbitrary free-text field safe to interpolate into a
// single-line record: LF/CR/HT become printable escapes and every other
// control character is dropped, so the rendered field can never contain a raw
// line break. Applied to all free-text fields (message, SD values, CEF header
// and extension values), including nested Attributes map values.
func oneLine(s string) string {
	return dropControls(lineBreakReplacer.Replace(s))
}

// --- RFC 5424 syslog ---

type syslogFormatter struct{}

func (syslogFormatter) Name() string        { return "syslog" }
func (syslogFormatter) ContentType() string { return "text/plain; charset=utf-8" }

func (f syslogFormatter) FormatBatch(events []Event) []byte { return joinRecords(events, f.Format) }

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

	line := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s", pri, ts, product, vendor, msgID, sd.String(), oneLine(e.message()))
	return []byte(line)
}

func writeSDParam(b *strings.Builder, name, value string) {
	// oneLine neutralizes CR/LF (and other controls) so a tenant-controlled
	// value cannot split the record; escapeSDValue then quotes the SD specials.
	b.WriteString(" " + name + "=\"" + escapeSDValue(oneLine(value)) + "\"")
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
		if isControl(r) { // drop CR/LF/controls so a key cannot split the record
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "k"
	}
	return s
}

func sanitizeSD(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' {
			return '_'
		}
		if isControl(r) { // MSGID is a single printable token; drop controls
			return -1
		}
		return r
	}, s)
}

// --- ArcSight CEF ---

type cefFormatter struct{}

func (cefFormatter) Name() string        { return "cef" }
func (cefFormatter) ContentType() string { return "text/plain; charset=utf-8" }

func (f cefFormatter) FormatBatch(events []Event) []byte { return joinRecords(events, f.Format) }

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

// cefEscapeHeader escapes '\' and '|' in CEF header fields and neutralizes
// CR/LF (and other control chars) so a tenant-controlled header field cannot
// split the single-line record (docs/guardrails.md G7-N).
func cefEscapeHeader(s string) string {
	return dropControls(strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s))
}

// cefEscapeExt escapes '\', '=', and whitespace controls in CEF extension
// values, and drops any remaining control chars, so a value (including a nested
// Attributes value) renders on exactly one line (docs/guardrails.md G7-N).
func cefEscapeExt(s string) string {
	return dropControls(strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s))
}

func cefExtKey(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '=' || r == ' ' {
			return '_'
		}
		if isControl(r) { // drop CR/LF/controls so a key cannot split the record
			return -1
		}
		return r
	}, s)
}

// --- Elastic Common Schema (ECS) JSON ---

type ecsFormatter struct{}

func (ecsFormatter) Name() string        { return "ecs" }
func (ecsFormatter) ContentType() string { return "application/json" }

// FormatBatch emits newline-delimited JSON (NDJSON) — the shape the
// Elastic/OpenSearch bulk ingest and most JSON log pipelines accept for many
// documents in one request.
func (f ecsFormatter) FormatBatch(events []Event) []byte { return joinRecords(events, f.Format) }

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

// otlpRecord builds one OTLP logRecord for an event.
func otlpRecord(e Event) map[string]any {
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
	return map[string]any{
		"timeUnixNano":   strconv.FormatInt(e.time().UnixNano(), 10),
		"severityNumber": e.Severity.otlpNumber(),
		"severityText":   strings.ToUpper(string(e.Severity)),
		"body":           map[string]any{"stringValue": e.message()},
		"attributes":     attrs,
	}
}

// otlpResourceLogs wraps records for one tenant in a resourceLogs entry whose
// resource attributes carry that tenant id.
func otlpResourceLogs(tenantID string, records []any) map[string]any {
	return map[string]any{
		"resource": map[string]any{"attributes": []any{
			kv("service.name", product), kv("probectl.tenant_id", tenantID),
		}},
		"scopeLogs": []any{map[string]any{
			"scope":      map[string]any{"name": "probectl.siem"},
			"logRecords": records,
		}},
	}
}

func (otlpFormatter) Format(e Event) []byte {
	doc := map[string]any{
		"resourceLogs": []any{otlpResourceLogs(e.TenantID, []any{otlpRecord(e)})},
	}
	b, _ := json.Marshal(doc)
	return b
}

// FormatBatch emits ONE ExportLogsServiceRequest. Records are grouped by
// resource/tenant: a per-tenant batch yields a single resourceLogs entry, and
// the grouping keeps records from different tenants in separate resources even
// if a caller ever mixed them (docs/guardrails.md G7-N tenant isolation).
func (otlpFormatter) FormatBatch(events []Event) []byte {
	if len(events) == 0 {
		return nil
	}
	order := make([]string, 0, len(events))
	byTenant := map[string][]any{}
	for _, e := range events {
		if _, seen := byTenant[e.TenantID]; !seen {
			order = append(order, e.TenantID)
		}
		byTenant[e.TenantID] = append(byTenant[e.TenantID], otlpRecord(e))
	}
	resourceLogs := make([]any, 0, len(order))
	for _, tid := range order {
		resourceLogs = append(resourceLogs, otlpResourceLogs(tid, byTenant[tid]))
	}
	b, _ := json.Marshal(map[string]any{"resourceLogs": resourceLogs})
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
