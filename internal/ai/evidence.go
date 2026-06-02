package ai

import (
	"fmt"
	"strings"
	"time"
)

// Evidence is one normalized, citable signal gathered for a question — the unit
// of grounding. ID is stable within an answer ("E1", "E2", …) so a Finding can
// cite it and a reader can trace the claim back to the underlying signal. Fields
// is the raw row from the tenant-and-RBAC-scoped query layer; Ref is a stable
// pointer back to the source signal for the UI to link.
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

// collectEvidence turns query rows from one domain into citable Evidence,
// deriving the well-known display/correlation fields from each row when present.
// nextID is the running evidence counter so IDs are unique across domains.
func collectEvidence(domain Domain, rows []Row, nextID *int) []Evidence {
	out := make([]Evidence, 0, len(rows))
	for _, row := range rows {
		*nextID++
		e := Evidence{
			ID:       fmt.Sprintf("E%d", *nextID),
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
