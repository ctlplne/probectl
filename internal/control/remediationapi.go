package control

import (
	"errors"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/remediation"
)

// Guarded agentic remediation (S-EE5, F44 — guardrail-critical, ee-backed via
// `remediation`). The AI PROPOSES; a human APPROVES; probectl NEVER executes.
// Approval here is a recorded, audited, human-only sign-off — there is no
// executor. Hidden (404) when the feature is unlicensed.

// WithRemediation attaches the remediation Service (the ee attach seam). nil =
// the feature is not licensed and the surface 404s (hidden-unlicensed).
func (s *Server) WithRemediation(svc remediation.Service) *Server {
	if svc != nil {
		s.remediation = svc
	}
	return s
}

// RemediationService returns the installed remediation service (or nil) — the
// MCP server reads it to wire the proposal-only tool.
func (s *Server) RemediationService() remediation.Service { return s.remediation }

func (s *Server) remediationSvc() (remediation.Service, error) {
	if s.remediation == nil {
		return nil, apierror.NotFound("not found") // hidden-unlicensed
	}
	return s.remediation, nil
}

func (s *Server) handleRemediationList(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	items, err := svc.List(r.Context(), tid)
	if err != nil {
		return apierror.Internal("list remediations").Wrap(err)
	}
	if items == nil {
		items = []remediation.Proposal{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "approvals_enabled": svc.ApprovalsEnabled()})
	return nil
}

func (s *Server) handleRemediationGet(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	p, err := svc.Get(r.Context(), tid, r.PathValue("id"))
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, p)
	return nil
}

// handleRemediationPropose files a PROPOSED proposal. Even via this
// authenticated API, the result is always state=proposed awaiting a human
// decision — there is no path that approves on creation.
func (s *Server) handleRemediationPropose(w http.ResponseWriter, r *http.Request) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	var in struct {
		Kind       string `json:"kind"`
		Title      string `json:"title"`
		Rationale  string `json:"rationale"`
		Target     string `json:"target"`
		IncidentID string `json:"incident_id"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	out, err := svc.Propose(r.Context(), tid, "user:"+p.Email, remediation.ProposeInput{
		Kind: remediation.Kind(in.Kind), Title: in.Title, Rationale: in.Rationale,
		Target: in.Target, IncidentID: in.IncidentID,
	})
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

// handleRemediationApprove records a human's authorization. This is the ONLY
// path that can move a proposal to approved, and it requires the
// authenticated caller to hold remediation.approve (enforced by the route
// table) — ingested data can never reach it. probectl executes NOTHING.
func (s *Server) handleRemediationApprove(w http.ResponseWriter, r *http.Request) error {
	return s.decideRemediation(w, r, true)
}

func (s *Server) handleRemediationReject(w http.ResponseWriter, r *http.Request) error {
	return s.decideRemediation(w, r, false)
}

func (s *Server) decideRemediation(w http.ResponseWriter, r *http.Request, approve bool) error {
	svc, err := s.remediationSvc()
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	var in struct {
		Note string `json:"note"`
	}
	_ = decodeJSON(r, &in) // note is optional
	id := r.PathValue("id")
	var out remediation.Proposal
	if approve {
		out, err = svc.Approve(r.Context(), tid, "user:"+p.Email, id, in.Note)
	} else {
		out, err = svc.Reject(r.Context(), tid, "user:"+p.Email, id, in.Note)
	}
	if err != nil {
		return mapRemediationErr(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// mapRemediationErr maps the domain errors to HTTP statuses. The fail-closed
// approval errors (disabled / over-limit / unknown radius) are 409 Conflict —
// the request was well-formed but the state/policy forbids it.
func mapRemediationErr(err error) error {
	var re remediation.Error
	if errors.As(err, &re) {
		switch re.Code {
		case "not_found":
			return apierror.NotFound(re.Message)
		case "validation":
			return apierror.Validation(re.Message)
		case "approvals_disabled", "blast_radius_exceeded", "blast_radius_unknown", "not_proposed":
			return apierror.Conflict(re.Message).WithCode(re.Code)
		}
		return apierror.BadRequest(re.Message).WithCode(re.Code)
	}
	return apierror.Internal("remediation").Wrap(err)
}
