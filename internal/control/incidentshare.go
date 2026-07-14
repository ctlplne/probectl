// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const (
	defaultIncidentShareTTL = 7 * 24 * time.Hour
	maxShareFilters         = 24
	maxShareValueLength     = 512
)

var (
	shareFilterKeyRE      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$`)
	shareTenantKeyStripRE = regexp.MustCompile(`[^a-z0-9]`)
	shareSecretAttrKeyRE  = regexp.MustCompile(`(?i)(authorization|credential|password|passwd|passphrase|token|secret|api[_-]?key|private[_-]?key)`)
)

type incidentShareSelection struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type incidentShareContext struct {
	From      time.Time               `json:"from"`
	To        time.Time               `json:"to"`
	Filters   map[string]string       `json:"filters"`
	Selection *incidentShareSelection `json:"selection,omitempty"`
}

type createIncidentShareRequest struct {
	Context incidentShareContext `json:"context"`
}

type incidentSharePayload struct {
	Incident incident.Incident    `json:"incident"`
	Context  incidentShareContext `json:"context"`
	Answer   ai.Answer            `json:"answer"`
}

type incidentShareResponse struct {
	ID        string               `json:"id"`
	Incident  incident.Incident    `json:"incident"`
	Context   incidentShareContext `json:"context"`
	Answer    ai.Answer            `json:"answer"`
	CreatedAt time.Time            `json:"created_at"`
	ExpiresAt time.Time            `json:"expires_at"`
}

func (s *Server) handleCreateIncidentShare(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("incident sharing is unavailable")
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil || p.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	// The route middleware already requires incident.read. The snapshot also
	// performs RCA, so require ai.query before any evidence gathering.
	if !p.Has(permAIQuery) {
		return apierror.Forbidden("AI query permission is required to share cited incident evidence")
	}

	var req createIncidentShareRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	incidentID := r.PathValue("id")
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		inc, err = (store.Incidents{}).Get(ctx, sc, incidentID)
		return err
	}); err != nil {
		return err
	}

	ctx, err := validatedShareContext(req.Context, *inc, redactionPolicy(s.cfg), p.TenantID)
	if err != nil {
		return err
	}
	answer, err := s.analyzer.Analyze(r.Context(), p, ai.Question{
		Text: fmt.Sprintf("What caused incident %s affecting %s? Correlate routing, path, flow, device, host, and change evidence.",
			inc.ID, firstNonEmpty(inc.Target, inc.Prefix, inc.Title)),
		Subject: map[string]string{
			"incident_id": inc.ID,
			"target":      inc.Target,
			"prefix":      inc.Prefix,
		},
		Range: ai.TimeRange{Start: ctx.From, End: ctx.To},
	})
	if err != nil {
		if errors.Is(err, ai.ErrEgressDenied) {
			return apierror.Forbidden("remote AI model egress is disabled for this tenant; use the air-gapped builtin/local model or record tenant consent")
		}
		if errors.Is(err, ai.ErrBusy) {
			return apierror.RateLimited("the AI assistant is at capacity — retry shortly")
		}
		return apierror.Unavailable("the cited incident snapshot could not be created")
	}
	ctx.Selection = authorizedShareSelection(ctx.Selection, *inc, answer)

	pol := redactionPolicy(s.cfg)
	answer = redactAnswerForShare(answer, pol, p.TenantID)
	answer.Tenant = "" // tenant scope belongs to auth/storage, never the artifact body or URL
	payload := incidentSharePayload{
		Incident: redactIncidentForShare(*inc, pol, p.TenantID),
		Context:  ctx,
		Answer:   answer,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return apierror.Internal("incident share encoding failed").Wrap(err)
	}
	shareID, err := newIncidentShareID()
	if err != nil {
		return apierror.Internal("incident share ID generation failed").Wrap(err)
	}
	expiresAt, err := s.incidentShareExpiry(r.Context(), p.TenantID)
	if err != nil {
		return err
	}

	var created *store.IncidentShareArtifact
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var createErr error
		created, createErr = (store.IncidentShares{}).Create(ctx, sc, store.IncidentShareInput{
			ID: shareID, IncidentID: inc.ID, Payload: payloadJSON, CreatedBy: p.UserID, ExpiresAt: expiresAt,
		})
		if createErr != nil {
			return createErr
		}
		if _, pruneErr := (store.IncidentShares{}).Prune(ctx, sc); pruneErr != nil {
			s.log.Warn("incident share prune failed", "tenant_id", p.TenantID, "error", pruneErr)
		}
		return s.recordAudit(ctx, sc, r, "incident.share_create", shareID, map[string]any{
			"incident_id": inc.ID, "expires_at": expiresAt,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, shareResponse(created, payload))
	return nil
}

func (s *Server) handleGetIncidentShare(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("incident sharing is unavailable")
	}
	shareID := r.PathValue("id")
	var artifact *store.IncidentShareArtifact
	var payload incidentSharePayload
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		artifact, err = (store.IncidentShares{}).Get(ctx, sc, shareID)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(artifact.Payload, &payload); err != nil {
			return apierror.Internal("incident share artifact is unreadable").Wrap(err)
		}
		return s.recordAudit(ctx, sc, r, "incident.share_read", shareID, map[string]any{
			"incident_id": artifact.IncidentID,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, shareResponse(artifact, payload))
	return nil
}

func shareResponse(row *store.IncidentShareArtifact, payload incidentSharePayload) incidentShareResponse {
	return incidentShareResponse{
		ID: row.ID, Incident: payload.Incident, Context: payload.Context, Answer: payload.Answer,
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
	}
}

func (s *Server) incidentShareExpiry(ctx context.Context, tenantID string) (time.Time, error) {
	ttl := defaultIncidentShareTTL
	if s.tenantLife != nil {
		policy, err := s.tenantLife.RetentionFor(ctx, tenantID)
		if err != nil {
			return time.Time{}, apierror.Unavailable("tenant retention policy could not be verified; share creation failed closed").Wrap(err)
		}
		if policy.ObjectRetentionDays != nil {
			retentionTTL := time.Duration(*policy.ObjectRetentionDays) * 24 * time.Hour
			if retentionTTL < ttl {
				ttl = retentionTTL
			}
		}
	}
	return time.Now().UTC().Add(ttl), nil
}

func validatedShareContext(in incidentShareContext, inc incident.Incident, pol ai.RedactionPolicy, tenantID string) (incidentShareContext, error) {
	out := incidentShareContext{From: in.From, To: in.To, Filters: map[string]string{}}
	if out.From.IsZero() {
		out.From = inc.StartedAt
	}
	if out.To.IsZero() {
		out.To = inc.LastSeenAt
	}
	if out.From.After(out.To) {
		return incidentShareContext{}, apierror.Validation("share context requires from <= to")
	}
	if len(in.Filters) > maxShareFilters {
		return incidentShareContext{}, apierror.Validation("share context has too many filters")
	}
	for key, value := range in.Filters {
		if !shareFilterKeyRE.MatchString(key) || isTenantSelector(key) || len(value) > maxShareValueLength {
			return incidentShareContext{}, apierror.Validation("share context contains an invalid or tenant-scoped filter")
		}
		out.Filters[key] = ai.RedactTextForTenant(value, pol, tenantID)
	}
	if in.Selection != nil {
		if (in.Selection.Kind != "evidence" && in.Selection.Kind != "entity") ||
			strings.TrimSpace(in.Selection.ID) == "" || len(in.Selection.ID) > 256 {
			return incidentShareContext{}, apierror.Validation("share context contains an invalid selection")
		}
		selectionCopy := *in.Selection
		out.Selection = &selectionCopy
	}
	return out, nil
}

func authorizedShareSelection(selection *incidentShareSelection, inc incident.Incident, answer ai.Answer) *incidentShareSelection {
	if selection == nil {
		return nil
	}
	allowed := map[string]bool{inc.ID: true}
	for i := range inc.Signals {
		allowed[fmt.Sprintf("%s:%d", inc.ID, i)] = true
	}
	for _, evidence := range answer.Evidence {
		allowed[evidence.ID] = true
		if sourceID, ok := evidence.Fields["id"].(string); ok {
			allowed[sourceID] = true
		}
	}
	if !allowed[selection.ID] {
		return nil
	}
	selectionCopy := *selection
	return &selectionCopy
}

func redactIncidentForShare(in incident.Incident, pol ai.RedactionPolicy, tenantID string) incident.Incident {
	out := in
	out.TenantID = ""
	out.Title = ai.RedactTextForTenant(in.Title, pol, tenantID)
	out.Target = ai.RedactTextForTenant(in.Target, pol, tenantID)
	out.Prefix = ai.RedactTextForTenant(in.Prefix, pol, tenantID)
	out.Signals = make([]incident.Signal, len(in.Signals))
	for i, signal := range in.Signals {
		signal.TenantID = ""
		signal.Title = ai.RedactTextForTenant(signal.Title, pol, tenantID)
		signal.Summary = ai.RedactTextForTenant(signal.Summary, pol, tenantID)
		signal.Target = ai.RedactTextForTenant(signal.Target, pol, tenantID)
		signal.Prefix = ai.RedactTextForTenant(signal.Prefix, pol, tenantID)
		attrs := make(map[string]string, len(signal.Attributes))
		for key, value := range signal.Attributes {
			attrs[key] = redactShareAttribute(key, value, pol, tenantID)
		}
		signal.Attributes = attrs
		out.Signals[i] = signal
	}
	return out
}

func redactAnswerForShare(in ai.Answer, pol ai.RedactionPolicy, tenantID string) ai.Answer {
	out := ai.RedactAnswerForPersistence(in, pol, tenantID)
	for i := range out.InvestigationPlan {
		step := &out.InvestigationPlan[i]
		step.Goal = ai.RedactTextForTenant(step.Goal, pol, tenantID)
		step.NodeID = ai.RedactTextForTenant(step.NodeID, pol, tenantID)
		step.Reason = ai.RedactTextForTenant(step.Reason, pol, tenantID)
		selector := make(map[string]string, len(step.Selector))
		for key, value := range step.Selector {
			selector[key] = redactShareAttribute(key, value, pol, tenantID)
		}
		step.Selector = selector
	}
	for i := range out.Evidence {
		fields := make(ai.Row, len(out.Evidence[i].Fields))
		for key, value := range out.Evidence[i].Fields {
			fields[key] = redactShareAnswerValue(key, value, pol, tenantID)
		}
		out.Evidence[i].Fields = fields
	}
	return out
}

func redactShareAnswerValue(key string, value any, pol ai.RedactionPolicy, tenantID string) any {
	if isTenantSelector(key) {
		return "[tenant]"
	}
	if shareSecretAttrKeyRE.MatchString(key) {
		if text, ok := value.(string); ok {
			return redactShareAttribute(key, text, pol, tenantID)
		}
		return "[secret]"
	}
	switch typed := value.(type) {
	case string:
		return ai.RedactTextForTenant(typed, pol, tenantID)
	case ai.Row:
		out := make(ai.Row, len(typed))
		for childKey, child := range typed {
			out[childKey] = redactShareAnswerValue(childKey, child, pol, tenantID)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for childKey, child := range typed {
			out[childKey] = redactShareAnswerValue(childKey, child, pol, tenantID)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(typed))
		for childKey, child := range typed {
			redacted := redactShareAnswerValue(childKey, child, pol, tenantID)
			out[childKey], _ = redacted.(string)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = redactShareAnswerValue("", child, pol, tenantID)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for i, child := range typed {
			out[i] = ai.RedactTextForTenant(child, pol, tenantID)
		}
		return out
	default:
		return value
	}
}

func redactShareAttribute(key, value string, pol ai.RedactionPolicy, tenantID string) string {
	if isTenantSelector(key) {
		return "[tenant]"
	}
	if !shareSecretAttrKeyRE.MatchString(key) {
		return ai.RedactTextForTenant(value, pol, tenantID)
	}
	return "[secret]"
}

func newIncidentShareID() (string, error) {
	random, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return "share_" + hex.EncodeToString(random), nil
}

func isTenantSelector(key string) bool {
	normalized := strings.ToLower(shareTenantKeyStripRE.ReplaceAllString(key, ""))
	return normalized == "tenant" || normalized == "tenantid"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "the incident scope"
}
