// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"fmt"
	"strings"
	"time"
)

// Evidence is one normalized, citable signal gathered for a question — the unit
// of grounding. ID is stable within an answer ("E1", "E2", …) so a Finding can
// cite it and a reader can trace the claim back to the underlying signal. Fields
// is the row from the tenant-and-RBAC-scoped query layer, reduced to the
// per-domain allow-list before the answer is serialized (U-092); Ref is a
// stable pointer back to the source signal for the UI to link.
type Evidence struct {
	ID         string    `json:"id"`
	Domain     Domain    `json:"domain"`
	Plane      string    `json:"plane,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	Title      string    `json:"title,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	OccurredAt time.Time `json:"occurred_at,omitempty"`
	Fields     Row       `json:"fields,omitempty"`
}

// evidenceFieldAllowList is the per-domain set of row keys that may appear in
// Evidence.Fields on an API response (U-092). Sources hand the engine raw rows;
// the model may use them in-process, but the serialized answer carries only
// these vetted keys — a new source (or a future column) cannot silently leak
// raw row data to API clients. Keys are the union of what today's sources emit
// on purpose; extend the list deliberately when a source adds a field.
var evidenceFieldAllowList = map[Domain]map[string]bool{
	DomainMetrics:  setOf("metric", "value", "unit", "target", "prefix", "node", "service", "agent_id", "instance", "job", "plane", "severity", "title", "summary", "occurred_at", "timestamp", "at", "time"),
	DomainEvents:   setOf("id", "kind", "plane", "source", "change_kind", "title", "summary", "target", "prefix", "actor", "ref", "occurred_at", "bytes", "packets", "flows", "detail"),
	DomainEntities: setOf("id", "kind", "plane", "severity", "title", "summary", "target", "prefix", "occurred_at"),
	DomainTopology: setOf("hop", "node", "neighbor", "kind", "label", "plane", "title"),
}

// universalEvidenceFields applies to any domain without its own allow-list —
// only the cross-domain display keys survive (fail closed for unknown domains).
var universalEvidenceFields = setOf("id", "kind", "plane", "severity", "title", "summary", "target", "occurred_at")

func setOf(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// sanitizeEvidenceFields strips every non-allow-listed key from each
// Evidence.Fields in place (U-092), immediately before answer assembly.
func sanitizeEvidenceFields(evs []Evidence) {
	for i := range evs {
		if evs[i].Fields == nil {
			continue
		}
		allowed, ok := evidenceFieldAllowList[evs[i].Domain]
		if !ok {
			allowed = universalEvidenceFields
		}
		clean := make(Row, len(evs[i].Fields))
		for k, v := range evs[i].Fields {
			if allowed[k] {
				clean[k] = v
			}
		}
		evs[i].Fields = clean
	}
}

// sanitizeRowFields returns a copy of a raw query row reduced to the per-domain
// allow-list (AIRCA-002), mirroring sanitizeEvidenceFields but for the raw Row
// shape that Engine.Correlate emits. The cross-domain "_domain" provenance
// marker is always preserved. Fail closed: unknown domains fall back to the
// universal allow-list, so a future source/column cannot leak raw row data.
func sanitizeRowFields(domain Domain, row Row) Row {
	allowed, ok := evidenceFieldAllowList[domain]
	if !ok {
		allowed = universalEvidenceFields
	}
	clean := make(Row, len(row))
	for k, v := range row {
		if k == "_domain" || allowed[k] {
			clean[k] = v
		}
	}
	return clean
}

// collectEvidence turns query rows from one domain into citable Evidence,
// deriving the well-known display/correlation fields from each row when present.
// nextID is the running evidence counter so IDs are unique across domains;
// idPrefix is the per-session random nonce (U-037) — IDs are NON-SEQUENTIAL
// across sessions, so telemetry-embedded text cannot guess a citable ID.
func collectEvidence(domain Domain, rows []Row, idPrefix string, nextID *int) []Evidence {
	out := make([]Evidence, 0, len(rows))
	for _, row := range rows {
		*nextID++
		e := Evidence{
			ID:       fmt.Sprintf("E%s-%d", idPrefix, *nextID),
			Domain:   domain,
			Plane:    strField(row, "plane"),
			Severity: strField(row, "severity"),
			Title:    firstField(row, "title", "name", "kind", "node", "metric"),
			Summary:  strField(row, "summary"),
			Fields:   row,
		}
		if e.Plane == "" {
			e.Plane = string(domain)
		}
		if e.Title == "" {
			e.Title = string(domain) + " signal"
		}
		e.OccurredAt = timeField(row, "occurred_at", "timestamp", "at", "time")
		e.Ref = evidenceRef(domain, row)
		out = append(out, e)
	}
	return out
}

// evidenceRef builds a stable, link-friendly pointer to the source signal.
func evidenceRef(domain Domain, row Row) string {
	switch domain {
	case DomainEntities:
		if id := strField(row, "id"); id != "" {
			if k := strField(row, "kind"); k != "" {
				return k + ":" + id
			}
			return "incident:" + id
		}
	case DomainTopology:
		if n := strField(row, "node"); n != "" {
			return "node:" + n
		}
		if n := strField(row, "neighbor"); n != "" {
			return "node:" + n
		}
	case DomainEvents:
		if id := strField(row, "id"); id != "" {
			return "event:" + id
		}
		if k := strField(row, "kind"); k != "" {
			return "event:" + k
		}
	case DomainMetrics:
		if m := strField(row, "metric"); m != "" {
			return "metric:" + m
		}
	}
	return string(domain)
}

func strField(row Row, key string) string {
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}

func firstField(row Row, keys ...string) string {
	for _, k := range keys {
		if s := strField(row, k); s != "" {
			return s
		}
	}
	return ""
}

func timeField(row Row, keys ...string) time.Time {
	for _, k := range keys {
		v, ok := row[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case time.Time:
			return t
		case string:
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
				if parsed, err := time.Parse(layout, strings.TrimSpace(t)); err == nil {
					return parsed
				}
			}
		}
	}
	return time.Time{}
}
