// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	defaultIncidentJournalTTL = 90 * 24 * time.Hour
	maxIncidentJournalRunes   = 4000
	maxIncidentJournalBytes   = 16000
)

type incidentJournalCitationRequest struct {
	ShareID    string `json:"share_id"`
	EvidenceID string `json:"evidence_id"`
}

type appendIncidentJournalRequest struct {
	Kind     string                          `json:"kind"`
	Body     string                          `json:"body"`
	Citation *incidentJournalCitationRequest `json:"citation,omitempty"`
}

type incidentJournalCitation struct {
	ShareID    string     `json:"share_id"`
	EvidenceID string     `json:"evidence_id"`
	State      string     `json:"state"`
	Domain     string     `json:"domain,omitempty"`
	Plane      string     `json:"plane,omitempty"`
	Title      string     `json:"title,omitempty"`
	Summary    string     `json:"summary,omitempty"`
	OccurredAt *time.Time `json:"occurred_at,omitempty"`
	Ref        string     `json:"ref,omitempty"`
}

type incidentJournalEntryResponse struct {
	ID         string                   `json:"id"`
	IncidentID string                   `json:"incident_id"`
	Kind       string                   `json:"kind"`
	Format     string                   `json:"format"`
	Body       string                   `json:"body"`
	Citation   *incidentJournalCitation `json:"citation,omitempty"`
	CreatedBy  string                   `json:"created_by"`
	CreatedAt  time.Time                `json:"created_at"`
	ExpiresAt  time.Time                `json:"expires_at"`
}

func (s *Server) handleListIncidentJournal(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("incident investigation journal is unavailable")
	}
	incidentID := r.PathValue("id")
	items := []incidentJournalEntryResponse{}
	truncated := false
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Incidents{}).Get(ctx, sc, incidentID); err != nil {
			return err
		}
		rows, wasTruncated, err := (store.IncidentJournals{}).List(ctx, sc, incidentID)
		if err != nil {
			return err
		}
		truncated = wasTruncated
		items = make([]incidentJournalEntryResponse, 0, len(rows))
		for i := range rows {
			response, err := s.incidentJournalResponse(ctx, sc, rows[i])
			if err != nil {
				return err
			}
			items = append(items, response)
		}
		return nil
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "truncated": truncated, "limit": store.MaxIncidentJournalEntries,
	})
	return nil
}

func (s *Server) handleAppendIncidentJournal(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("incident investigation journal is unavailable")
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil || p.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	var req appendIncidentJournalRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if err := validateIncidentJournalRequest(&req); err != nil {
		return err
	}
	expiresAt, err := s.incidentJournalExpiry(r.Context(), p.TenantID)
	if err != nil {
		return err
	}
	entryID, err := newIncidentJournalEntryID()
	if err != nil {
		return apierror.Internal("incident journal entry ID generation failed").Wrap(err)
	}

	incidentID := r.PathValue("id")
	var response incidentJournalEntryResponse
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Incidents{}).Get(ctx, sc, incidentID); err != nil {
			return err
		}
		var shareID, evidenceID *string
		var citation *incidentJournalCitation
		if req.Citation != nil {
			resolved, err := s.resolveIncidentJournalCitation(ctx, sc, incidentID, *req.Citation)
			if err != nil {
				return err
			}
			citation = resolved
			shareID = &req.Citation.ShareID
			evidenceID = &req.Citation.EvidenceID
		}
		created, err := (store.IncidentJournals{}).Append(ctx, sc, store.IncidentJournalInput{
			ID: entryID, IncidentID: incidentID, Kind: req.Kind, Body: req.Body,
			CitationShareID: shareID, CitationEvidenceID: evidenceID,
			CreatedBy: p.UserID, ExpiresAt: expiresAt,
		})
		if err != nil {
			return err
		}
		if _, pruneErr := (store.IncidentJournals{}).Prune(ctx, sc); pruneErr != nil {
			s.log.Warn("incident journal prune failed", "tenant_id", p.TenantID, "error", pruneErr)
		}
		response = journalEntryResponse(*created, citation)
		return s.recordAudit(ctx, sc, r, "incident.journal_append", entryID, map[string]any{
			"incident_id": incidentID,
			"kind":        req.Kind,
			"cited":       citation != nil,
		})
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, response)
	return nil
}

func validateIncidentJournalRequest(req *appendIncidentJournalRequest) error {
	req.Kind = strings.TrimSpace(req.Kind)
	req.Body = strings.TrimSpace(req.Body)
	if req.Kind != "note" && req.Kind != "checkpoint" {
		return apierror.Validation("journal kind must be note or checkpoint")
	}
	if req.Body == "" {
		return apierror.Validation("journal body is required")
	}
	if !utf8.ValidString(req.Body) || utf8.RuneCountInString(req.Body) > maxIncidentJournalRunes ||
		len(req.Body) > maxIncidentJournalBytes {
		return apierror.Validation("journal body exceeds the 4000-character limit")
	}
	if req.Kind == "note" && req.Citation != nil {
		return apierror.Validation("plain journal notes cannot carry a citation")
	}
	if req.Kind == "checkpoint" && req.Citation == nil {
		return apierror.Validation("journal checkpoints require a cited share and evidence ID")
	}
	if req.Citation != nil {
		req.Citation.ShareID = strings.TrimSpace(req.Citation.ShareID)
		req.Citation.EvidenceID = strings.TrimSpace(req.Citation.EvidenceID)
		if req.Citation.ShareID == "" || req.Citation.EvidenceID == "" ||
			len(req.Citation.ShareID) > 128 || len(req.Citation.EvidenceID) > 256 {
			return apierror.Validation("journal checkpoint citation is invalid")
		}
	}
	return nil
}

func (s *Server) incidentJournalResponse(ctx context.Context, sc tenancy.Scope, entry store.IncidentJournalEntry) (incidentJournalEntryResponse, error) {
	var citation *incidentJournalCitation
	if entry.CitationShareID != nil && entry.CitationEvidenceID != nil {
		request := incidentJournalCitationRequest{
			ShareID: *entry.CitationShareID, EvidenceID: *entry.CitationEvidenceID,
		}
		resolved, err := s.resolveIncidentJournalCitation(ctx, sc, entry.IncidentID, request)
		if err != nil {
			if isNotFoundAPIError(err) {
				citation = &incidentJournalCitation{
					ShareID: request.ShareID, EvidenceID: request.EvidenceID, State: "unavailable",
				}
			} else {
				return incidentJournalEntryResponse{}, err
			}
		} else {
			citation = resolved
		}
	}
	return journalEntryResponse(entry, citation), nil
}

func journalEntryResponse(entry store.IncidentJournalEntry, citation *incidentJournalCitation) incidentJournalEntryResponse {
	return incidentJournalEntryResponse{
		ID: entry.ID, IncidentID: entry.IncidentID, Kind: entry.Kind, Format: "plain_text",
		Body: entry.Body, Citation: citation, CreatedBy: entry.CreatedBy,
		CreatedAt: entry.CreatedAt, ExpiresAt: entry.ExpiresAt,
	}
}

func (s *Server) resolveIncidentJournalCitation(ctx context.Context, sc tenancy.Scope, incidentID string, request incidentJournalCitationRequest) (*incidentJournalCitation, error) {
	artifact, err := (store.IncidentShares{}).Get(ctx, sc, request.ShareID)
	if err != nil {
		if isNotFoundAPIError(err) {
			return nil, apierror.NotFound("cited incident evidence not found")
		}
		return nil, err
	}
	if artifact.IncidentID != incidentID {
		return nil, apierror.NotFound("cited incident evidence not found")
	}
	var payload incidentSharePayload
	if err := json.Unmarshal(artifact.Payload, &payload); err != nil {
		return nil, apierror.Internal("cited incident evidence is unreadable").Wrap(err)
	}
	if payload.Incident.ID != incidentID {
		return nil, apierror.NotFound("cited incident evidence not found")
	}
	for _, evidence := range payload.Answer.Evidence {
		if evidence.ID != request.EvidenceID {
			continue
		}
		occurredAt := evidence.OccurredAt
		return &incidentJournalCitation{
			ShareID: request.ShareID, EvidenceID: request.EvidenceID, State: "available",
			Domain: string(evidence.Domain), Plane: evidence.Plane, Title: evidence.Title,
			Summary: evidence.Summary, OccurredAt: &occurredAt, Ref: evidence.Ref,
		}, nil
	}
	return nil, apierror.NotFound("cited incident evidence not found")
}

func (s *Server) incidentJournalExpiry(ctx context.Context, tenantID string) (time.Time, error) {
	ttl := defaultIncidentJournalTTL
	if s.tenantLife != nil {
		policy, err := s.tenantLife.RetentionFor(ctx, tenantID)
		if err != nil {
			return time.Time{}, apierror.Unavailable("tenant retention policy could not be verified; journal append failed closed").Wrap(err)
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

func isNotFoundAPIError(err error) bool {
	var apiErr *apierror.Error
	return errors.As(err, &apiErr) && apiErr.Kind == apierror.KindNotFound
}

func newIncidentJournalEntryID() (string, error) {
	random, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return "journal_" + hex.EncodeToString(random), nil
}
