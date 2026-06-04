package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// basicAuth builds a Basic Authorization header from a "user:token" secret.
func basicAuth(secret string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(secret))}
}

// --- ServiceNow (Table API: incident) ---

// serviceNow opens + resolves a ServiceNow incident via the Table API. The
// endpoint is the table URL (e.g. https://acme.service-now.com/api/now/table/incident);
// the secret is "user:password" (Basic auth).
type serviceNow struct {
	endpoint string
	secret   string
	client   Doer
}

func newServiceNow(endpoint, secret string, client Doer) *serviceNow {
	return &serviceNow{endpoint: strings.TrimRight(endpoint, "/"), secret: secret, client: clientOr(client)}
}

func (*serviceNow) Name() string           { return "servicenow" }
func (*serviceNow) Capability() Capability { return CapabilityTicket }

func (s *serviceNow) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	payload := map[string]any{
		"short_description": inc.Title,
		"description":       fmt.Sprintf("probectl incident %s (target %s)", inc.ID, displayTarget(inc)),
		"urgency":           serviceNowUrgency(inc.Severity),
		"correlation_id":    inc.ID, // probectl's id, for the operator's reference
	}
	body, err := doJSON(ctx, s.client, "POST", s.endpoint, basicAuth(s.secret), payload)
	if err != nil {
		return Delivery{}, err
	}
	var r struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Result.SysID == "" {
		return Delivery{}, fmt.Errorf("servicenow: unexpected create response")
	}
	return Delivery{ExternalRef: r.Result.SysID, Status: r.Result.Number}, nil
}

func (s *serviceNow) Resolve(ctx context.Context, _ incident.Incident, ref string) error {
	patch := map[string]any{
		"state":       "6", // Resolved
		"close_code":  "Solved (Permanently)",
		"close_notes": "resolved by probectl",
	}
	_, err := doJSON(ctx, s.client, "PATCH", s.endpoint+"/"+url.PathEscape(ref), basicAuth(s.secret), patch)
	return err
}

func serviceNowUrgency(sev incident.Severity) string {
	switch sev {
	case incident.SeverityCritical:
		return "1"
	case incident.SeverityWarning:
		return "2"
	default:
		return "3"
	}
}

// --- Jira (REST v2: issue) ---

// jira opens + resolves a Jira issue. The endpoint is the create-issue URL with
// the project (and optional resolve transition) as query params, e.g.
// https://jira.example/rest/api/2/issue?project=OPS&resolve_transition=31.
// The secret is "email:api_token" (Basic auth).
type jira struct {
	createURL  string
	project    string
	transition string
	secret     string
	client     Doer
}

func newJira(endpoint, secret string, client Doer) *jira {
	j := &jira{secret: secret, client: clientOr(client), transition: "31"}
	u, err := url.Parse(endpoint)
	if err != nil {
		j.createURL = endpoint
		return j
	}
	q := u.Query()
	j.project = q.Get("project")
	if t := q.Get("resolve_transition"); t != "" {
		j.transition = t
	}
	u.RawQuery = "" // the create POST takes no query
	j.createURL = strings.TrimRight(u.String(), "/")
	return j
}

func (*jira) Name() string           { return "jira" }
func (*jira) Capability() Capability { return CapabilityTicket }

func (j *jira) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]any{"key": j.project},
			"summary":     inc.Title,
			"description": fmt.Sprintf("probectl incident %s (severity %s, target %s)", inc.ID, inc.Severity, displayTarget(inc)),
			"issuetype":   map[string]any{"name": "Task"},
		},
	}
	body, err := doJSON(ctx, j.client, "POST", j.createURL, basicAuth(j.secret), payload)
	if err != nil {
		return Delivery{}, err
	}
	var r struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Key == "" {
		return Delivery{}, fmt.Errorf("jira: unexpected create response")
	}
	return Delivery{ExternalRef: r.Key, Status: "open"}, nil
}

func (j *jira) Resolve(ctx context.Context, _ incident.Incident, ref string) error {
	// POST {createURL}/{key}/transitions {"transition":{"id":"<id>"}}
	transitionURL := j.createURL + "/" + url.PathEscape(ref) + "/transitions"
	payload := map[string]any{"transition": map[string]any{"id": j.transition}}
	_, err := doJSON(ctx, j.client, "POST", transitionURL, basicAuth(j.secret), payload)
	return err
}
