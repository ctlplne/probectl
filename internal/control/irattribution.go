// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	irRevealRoutePattern       = "/v1/audit/ir/{event_ref}/reveal"
	irRevealMaxBody            = 4 << 10
	irRevealMaxReason          = 512
	irRevealResultAuditTimeout = 5 * time.Second
	irRequestValidationReason  = "request rejected before investigation reason was accepted"
)

// IRAttemptOutcome is the closed set of provider-stream investigation
// receipts. Raw dependency errors never enter this vocabulary.
type IRAttemptOutcome string

const (
	IRAttemptDenied     IRAttemptOutcome = "denied"
	IRAttemptIntent     IRAttemptOutcome = "intent"
	IRAttemptOpenFailed IRAttemptOutcome = "open_failed"
	IRAttemptSucceeded  IRAttemptOutcome = "succeeded"
)

// IRInvestigationReceipt is the bounded projection persisted in the separate
// provider/break-glass stream.
type IRInvestigationReceipt struct {
	TenantID   string
	Actor      string
	EventRef   string
	Reason     string
	Outcome    IRAttemptOutcome
	ErrorClass string
}

// IRAttribution is the one decrypted record returned to an authorized
// investigator.
type IRAttribution struct {
	Operator string    `json:"operator"`
	TenantID string    `json:"tenant_id"`
	Grant    string    `json:"grant"`
	Surface  string    `json:"surface"`
	Consent  string    `json:"consent"`
	Outcome  string    `json:"outcome"`
	Reason   string    `json:"reason"`
	EventRef string    `json:"event_ref"`
	TS       time.Time `json:"ts"`
}

// IRInvestigator is the narrow runtime seam. RecordAttempt writes only to the
// protected provider stream; Reveal repeats tenant scope in durable storage.
type IRInvestigator interface {
	RecordAttempt(context.Context, IRInvestigationReceipt) error
	Reveal(context.Context, string, string) (IRAttribution, error)
}

var (
	// ErrIRAttributionNotFound intentionally covers missing and other-tenant
	// references to avoid an existence oracle.
	ErrIRAttributionNotFound = errors.New("IR attribution not found")
	// ErrIRKeyUnavailable means the offline investigation opener is unmounted.
	ErrIRKeyUnavailable = errors.New("IR investigation key unavailable")
)

// WithIRInvestigator attaches the licensed investigation capability.
func (s *Server) WithIRInvestigator(investigator IRInvestigator) *Server {
	if investigator != nil {
		s.irInvestigator = investigator
	}
	return s
}

// requireIRInvestigator performs tenant-first lifecycle, mandatory MFA, RBAC,
// then tenant-resource ABAC. It is separate from generic middleware so every
// authenticated denial can be written to the provider stream.
func (s *Server) requireIRInvestigator(next apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		setIRNoStoreHeaders(w)
		if s.irInvestigator == nil {
			return apierror.NotFound("resource not found")
		}
		p := auth.PrincipalFrom(r.Context())
		if p == nil || strings.TrimSpace(p.TenantID) == "" {
			return apierror.Unauthorized("authentication required")
		}
		if err := s.checkTenantLifecycle(r, p.TenantID); err != nil {
			return err
		}
		if !p.MFASatisfied {
			return apierror.Forbidden("multi-factor authentication required")
		}
		if !p.Has(permIRInvestigate) {
			return apierror.Forbidden(
				"missing permission: " + permIRInvestigate,
			)
		}
		resource := map[string]string{auth.ResourceTenantKey: p.TenantID}
		denied, err := s.abacDenies(
			r.Context(),
			p,
			permIRInvestigate,
			resource,
		)
		if err != nil {
			return err
		}
		if denied {
			return apierror.Forbidden(
				"denied by an attribute policy: " + permIRInvestigate,
			)
		}
		if !s.irRevealLimiter.allow(p.TenantID) {
			w.Header().Set("Retry-After", "20")
			return apierror.RateLimited(
				"IR investigation attempt rate exceeded",
			)
		}
		return next(w, r)
	}
}

func (s *Server) handleRevealIRAttribution(
	w http.ResponseWriter,
	r *http.Request,
) error {
	eventRef := r.PathValue("event_ref")
	if !validIREventRef(eventRef) {
		return s.rejectIRReveal(
			r,
			"",
			"",
			"invalid_event_ref",
			apierror.BadRequest(
				"event_ref must be exactly 64 lowercase hexadecimal characters",
			),
		)
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONLimit(r, irRevealMaxBody, &request); err != nil {
		return s.rejectIRReveal(r, eventRef, "", "invalid_request", err)
	}
	reason := strings.TrimSpace(request.Reason)
	switch {
	case reason == "":
		return s.rejectIRReveal(
			r,
			eventRef,
			"",
			"reason_required",
			apierror.Validation("reason is required"),
		)
	case len(reason) > irRevealMaxReason:
		return s.rejectIRReveal(
			r,
			eventRef,
			"",
			"reason_too_long",
			apierror.Validation("reason must be at most 512 bytes"),
		)
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil || strings.TrimSpace(p.TenantID) == "" {
		return apierror.Unauthorized("authentication required")
	}
	if err := s.irInvestigator.RecordAttempt(
		r.Context(),
		s.irReceipt(r, eventRef, reason, IRAttemptIntent, ""),
	); err != nil {
		return apierror.Unavailable("IR investigation audit is unavailable")
	}

	attribution, err := s.irInvestigator.Reveal(
		r.Context(),
		p.TenantID,
		eventRef,
	)
	defer clearIRAttribution(&attribution)
	if err != nil {
		if receiptErr := s.recordIRPostOpen(
			r,
			s.irReceipt(
				r,
				eventRef,
				reason,
				IRAttemptOpenFailed,
				irRevealErrorClass(err),
			),
		); receiptErr != nil {
			return apierror.Unavailable("IR investigation audit is unavailable")
		}
		return irRevealError(err)
	}
	if err := validateIRAttributionResponse(
		attribution,
		p.TenantID,
		eventRef,
	); err != nil {
		if receiptErr := s.recordIRPostOpen(
			r,
			s.irReceipt(
				r,
				eventRef,
				reason,
				IRAttemptOpenFailed,
				"scope_or_shape_mismatch",
			),
		); receiptErr != nil {
			return apierror.Unavailable("IR investigation audit is unavailable")
		}
		return apierror.NotFound("IR attribution record not found")
	}

	// Buffer, then commit the success receipt before a plaintext byte leaves.
	payload, err := json.Marshal(attribution)
	if err != nil {
		return apierror.Internal("IR attribution response could not be encoded")
	}
	payload = append(payload, '\n')
	clearIRAttribution(&attribution)
	defer crypto.Zeroize(payload)
	if err := s.recordIRPostOpen(
		r,
		s.irReceipt(r, eventRef, reason, IRAttemptSucceeded, ""),
	); err != nil {
		return apierror.Unavailable("IR investigation audit is unavailable")
	}
	setIRNoStoreHeaders(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
	return nil
}

func (s *Server) recordIRPostOpen(
	r *http.Request,
	receipt IRInvestigationReceipt,
) error {
	// An unseal attempt happened even if the caller disconnected. Preserve
	// request values while replacing client cancellation with a strict bound so
	// its result receipt has a deterministic opportunity to commit before any
	// plaintext response.
	ctx, cancel := context.WithTimeout(
		context.WithoutCancel(r.Context()),
		irRevealResultAuditTimeout,
	)
	defer cancel()
	return s.irInvestigator.RecordAttempt(ctx, receipt)
}

func (s *Server) rejectIRReveal(
	r *http.Request,
	eventRef, reason, errorClass string,
	responseErr error,
) error {
	if reason == "" {
		reason = irRequestValidationReason
	}
	if err := s.irInvestigator.RecordAttempt(
		r.Context(),
		s.irReceipt(r, eventRef, reason, IRAttemptDenied, errorClass),
	); err != nil {
		return apierror.Unavailable("IR investigation audit is unavailable")
	}
	return responseErr
}

func (s *Server) irReceipt(
	r *http.Request,
	eventRef, reason string,
	outcome IRAttemptOutcome,
	errorClass string,
) IRInvestigationReceipt {
	p := auth.PrincipalFrom(r.Context())
	tenantID := ""
	if p != nil {
		tenantID = p.TenantID
	}
	return IRInvestigationReceipt{
		TenantID: tenantID, Actor: auditActor(r), EventRef: eventRef,
		Reason: reason, Outcome: outcome, ErrorClass: errorClass,
	}
}

func setIRNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func validIREventRef(eventRef string) bool {
	if len(eventRef) != 64 {
		return false
	}
	for _, ch := range eventRef {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func validateIRAttributionResponse(
	attribution IRAttribution,
	tenantID, eventRef string,
) error {
	if attribution.TenantID != tenantID ||
		attribution.EventRef != eventRef ||
		attribution.TS.IsZero() {
		return ErrIRAttributionNotFound
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{attribution.Operator, 512},
		{attribution.TenantID, 128},
		{attribution.Grant, 512},
		{attribution.Surface, 512},
		{attribution.Consent, 2048},
		{attribution.Outcome, 512},
		{attribution.Reason, 2048},
		{attribution.EventRef, 64},
	} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > field.max {
			return errors.New("IR attribution field has an invalid response shape")
		}
	}
	return nil
}

func irRevealErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrIRAttributionNotFound):
		return "not_found"
	case errors.Is(err, ErrIRKeyUnavailable):
		return "key_unavailable"
	default:
		return "open_failed"
	}
}

func irRevealError(err error) error {
	switch {
	case errors.Is(err, ErrIRAttributionNotFound):
		return apierror.NotFound("IR attribution record not found")
	case errors.Is(err, ErrIRKeyUnavailable):
		return apierror.Unavailable("IR investigation key is unavailable")
	default:
		return apierror.Unavailable("IR attribution reveal failed")
	}
}

func clearIRAttribution(attribution *IRAttribution) {
	if attribution == nil {
		return
	}
	*attribution = IRAttribution{}
}
