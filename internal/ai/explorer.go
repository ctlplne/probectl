// SPDX-License-Identifier: MPL-2.0

package ai

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ExplorerSource is a bounded, operator-facing telemetry source. It is not a
// datastore name: control maps each value to an existing tenant-first store.
type ExplorerSource string

const (
	ExplorerFlow      ExplorerSource = "flow"
	ExplorerChanges   ExplorerSource = "changes"
	ExplorerPath      ExplorerSource = "path"
	ExplorerTopology  ExplorerSource = "topology"
	ExplorerEndpoints ExplorerSource = "endpoints"
	ExplorerTLS       ExplorerSource = "tls"
	ExplorerCost      ExplorerSource = "cost"
	ExplorerSLO       ExplorerSource = "slo"
)

// ExplorerQuery is the shared structured grammar used by the API and web UI.
// Tenant is deliberately absent: authentication is the only source of scope.
type ExplorerQuery struct {
	Template      string            `json:"template,omitempty"`
	Question      string            `json:"question"`
	Source        ExplorerSource    `json:"source"`
	From          time.Time         `json:"from"`
	To            time.Time         `json:"to"`
	Dimensions    []string          `json:"dimensions"`
	Filters       map[string]string `json:"filters"`
	Groupings     []string          `json:"groupings"`
	Measures      []string          `json:"measures"`
	Visualization string            `json:"visualization"`
	Limit         int               `json:"limit"`
}

// ExplorerTemplate is a discoverable recipe for a canonical operator question.
type ExplorerTemplate struct {
	ID            string         `json:"id"`
	Question      string         `json:"question"`
	Source        ExplorerSource `json:"source"`
	Dimensions    []string       `json:"dimensions"`
	Groupings     []string       `json:"groupings"`
	Measures      []string       `json:"measures"`
	Visualization string         `json:"visualization"`
	EvidencePath  string         `json:"evidence_path"`
}

// ExplorerTemplates is the product's taught query vocabulary. The ten recipes
// mirror UX journey J3; selecting one fully populates the structured grammar.
func ExplorerTemplates() []ExplorerTemplate {
	return []ExplorerTemplate{
		{ID: "top-talkers-site", Question: "Show top talkers by site", Source: ExplorerFlow, Dimensions: []string{"site", "interface"}, Groupings: []string{"site"}, Measures: []string{"bps", "pps"}, Visualization: "bar", EvidencePath: "/planes/flow"},
		{ID: "asn-before-incident", Question: "Which ASN change preceded this incident?", Source: ExplorerChanges, Dimensions: []string{"source", "prefix", "target"}, Groupings: []string{"source"}, Measures: []string{"events"}, Visualization: "timeline", EvidencePath: "/incidents"},
		{ID: "loss-by-hop", Question: "Show loss by hop for this test", Source: ExplorerPath, Dimensions: []string{"target", "hop", "node"}, Groupings: []string{"hop"}, Measures: []string{"loss_ratio", "rtt_avg_ms"}, Visualization: "line", EvidencePath: "/path"},
		{ID: "service-dependencies", Question: "Show service dependencies", Source: ExplorerTopology, Dimensions: []string{"from", "to", "kind"}, Groupings: []string{"kind"}, Measures: []string{"edges"}, Visualization: "topology", EvidencePath: "/topology"},
		{ID: "saturated-interface", Question: "Which device interface is saturated?", Source: ExplorerFlow, Dimensions: []string{"site", "interface"}, Groupings: []string{"site", "interface"}, Measures: []string{"bps", "pps"}, Visualization: "line", EvidencePath: "/planes/device"},
		{ID: "outage-endpoints", Question: "Which endpoints are affected by this outage?", Source: ExplorerEndpoints, Dimensions: []string{"endpoint", "cause", "summary"}, Groupings: []string{"cause"}, Measures: []string{"affected_endpoints"}, Visualization: "table", EvidencePath: "/endpoints"},
		{ID: "certificates-expiring", Question: "Which certificates expire in the next 30 days?", Source: ExplorerTLS, Dimensions: []string{"target", "subject", "issuer"}, Groupings: []string{"issuer"}, Measures: []string{"days_remaining"}, Visualization: "table", EvidencePath: "/security"},
		{ID: "cross-az-cost", Question: "Show cross-AZ network cost", Source: ExplorerCost, Dimensions: []string{"from_zone", "to_zone", "service"}, Groupings: []string{"from_zone", "to_zone"}, Measures: []string{"bytes", "usd"}, Visualization: "bar", EvidencePath: "/cost"},
		{ID: "slo-budget-burn", Question: "Which SLO error budgets are burning?", Source: ExplorerSLO, Dimensions: []string{"slo", "service", "team"}, Groupings: []string{"service"}, Measures: []string{"burn_rate", "budget_remaining"}, Visualization: "bar", EvidencePath: "/slos"},
		{ID: "deployments-before-incident", Question: "Which deployments immediately preceded this incident?", Source: ExplorerChanges, Dimensions: []string{"source", "actor", "target"}, Groupings: []string{"source"}, Measures: []string{"events"}, Visualization: "timeline", EvidencePath: "/incidents"},
	}
}

// NormalizeExplorerQuery validates and bounds an untrusted query. Fields are
// allow-listed per source, so the Explorer cannot become an arbitrary query DSL.
func NormalizeExplorerQuery(q ExplorerQuery, now time.Time) (ExplorerQuery, error) {
	q.Template = strings.TrimSpace(q.Template)
	q.Question = strings.TrimSpace(q.Question)
	if q.Question == "" || len(q.Question) > 500 {
		return ExplorerQuery{}, errors.New("explorer question is required (1-500 characters)")
	}
	allowed, ok := explorerFields[q.Source]
	if !ok {
		return ExplorerQuery{}, fmt.Errorf("unsupported explorer source %q", q.Source)
	}
	if q.To.IsZero() {
		q.To = now.UTC()
	} else {
		q.To = q.To.UTC()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-time.Hour)
	} else {
		q.From = q.From.UTC()
	}
	if q.From.After(q.To) || q.To.Sub(q.From) > 90*24*time.Hour {
		return ExplorerQuery{}, errors.New("explorer time range must be ordered and no longer than 90 days")
	}
	var err error
	if q.Dimensions, err = cleanExplorerFields(q.Dimensions, allowed.dimensions, 8, "dimension"); err != nil {
		return ExplorerQuery{}, err
	}
	if q.Groupings, err = cleanExplorerFields(q.Groupings, allowed.dimensions, 4, "grouping"); err != nil {
		return ExplorerQuery{}, err
	}
	if q.Measures, err = cleanExplorerFields(q.Measures, allowed.measures, 6, "measure"); err != nil {
		return ExplorerQuery{}, err
	}
	if q.Visualization == "" {
		q.Visualization = "table"
	}
	if !contains([]string{"table", "bar", "line", "timeline", "topology"}, q.Visualization) {
		return ExplorerQuery{}, fmt.Errorf("unsupported explorer visualization %q", q.Visualization)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	if len(q.Filters) > 12 {
		return ExplorerQuery{}, errors.New("explorer supports at most 12 filters")
	}
	cleanFilters := make(map[string]string, len(q.Filters))
	for key, value := range q.Filters {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if isTenantSelector(key) {
			return ExplorerQuery{}, errors.New("tenant scope comes from authentication and cannot be filtered")
		}
		if !contains(allowed.dimensions, key) {
			return ExplorerQuery{}, fmt.Errorf("unsupported %s filter %q", q.Source, key)
		}
		if len(value) > 200 {
			return ExplorerQuery{}, fmt.Errorf("explorer filter %q is too long", key)
		}
		if value != "" {
			cleanFilters[key] = value
		}
	}
	q.Filters = cleanFilters
	return q, nil
}

// ExplorerPreview renders a readable, stable receipt of the effective query.
func ExplorerPreview(q ExplorerQuery) string {
	filters := make([]string, 0, len(q.Filters))
	for key, value := range q.Filters {
		filters = append(filters, key+"="+value)
	}
	sort.Strings(filters)
	preview := fmt.Sprintf("FROM %s | TIME %s .. %s", q.Source, q.From.Format(time.RFC3339), q.To.Format(time.RFC3339))
	if len(filters) > 0 {
		preview += " | WHERE " + strings.Join(filters, ", ")
	}
	if len(q.Groupings) > 0 {
		preview += " | GROUP BY " + strings.Join(q.Groupings, ", ")
	}
	if len(q.Measures) > 0 {
		preview += " | MEASURE " + strings.Join(q.Measures, ", ")
	}
	return preview + " | VIEW " + q.Visualization
}

type explorerFieldSet struct {
	dimensions []string
	measures   []string
}

var explorerFields = map[ExplorerSource]explorerFieldSet{
	ExplorerFlow:      {dimensions: []string{"site", "interface", "direction"}, measures: []string{"bps", "pps"}},
	ExplorerChanges:   {dimensions: []string{"source", "actor", "target", "prefix", "kind", "incident_id"}, measures: []string{"events"}},
	ExplorerPath:      {dimensions: []string{"target", "hop", "node"}, measures: []string{"loss_ratio", "rtt_avg_ms"}},
	ExplorerTopology:  {dimensions: []string{"from", "to", "kind"}, measures: []string{"edges"}},
	ExplorerEndpoints: {dimensions: []string{"endpoint", "cause", "summary"}, measures: []string{"affected_endpoints"}},
	ExplorerTLS:       {dimensions: []string{"target", "subject", "issuer"}, measures: []string{"days_remaining"}},
	ExplorerCost:      {dimensions: []string{"from_zone", "to_zone", "service"}, measures: []string{"bytes", "usd"}},
	ExplorerSLO:       {dimensions: []string{"slo", "service", "team"}, measures: []string{"burn_rate", "budget_remaining"}},
}

func cleanExplorerFields(in, allowed []string, maxFields int, kind string) ([]string, error) {
	if len(in) > maxFields {
		return nil, fmt.Errorf("explorer supports at most %d %ss", maxFields, kind)
	}
	out := make([]string, 0, len(in))
	for _, field := range in {
		field = strings.ToLower(strings.TrimSpace(field))
		if !contains(allowed, field) {
			return nil, fmt.Errorf("unsupported explorer %s %q", kind, field)
		}
		if !contains(out, field) {
			out = append(out, field)
		}
	}
	return out, nil
}

func isTenantSelector(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(key)
	return normalized == "tenant" || normalized == "tenantid" || strings.HasPrefix(normalized, "tenant")
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
