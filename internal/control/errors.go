// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// errorBody is the JSON envelope returned for every error response.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// httpStatus maps a transport-agnostic domain Kind to an HTTP status code.
func httpStatus(kind apierror.Kind) int {
	switch kind {
	case apierror.KindBadRequest:
		return http.StatusBadRequest // 400
	case apierror.KindUnauthorized:
		return http.StatusUnauthorized // 401
	case apierror.KindForbidden:
		return http.StatusForbidden // 403
	case apierror.KindNotFound:
		return http.StatusNotFound // 404
	case apierror.KindConflict:
		return http.StatusConflict // 409
	case apierror.KindValidation:
		return http.StatusUnprocessableEntity // 422
	case apierror.KindRateLimited:
		return http.StatusTooManyRequests // 429
	case apierror.KindTooLarge:
		return http.StatusRequestEntityTooLarge // 413
	case apierror.KindUnsupportedMediaType:
		return http.StatusUnsupportedMediaType // 415
	case apierror.KindUnavailable:
		return http.StatusServiceUnavailable // 503
	case apierror.KindInternal:
		return http.StatusInternalServerError // 500
	default:
		return http.StatusInternalServerError // 500
	}
}

// apiHandler is an HTTP handler that returns a domain error instead of writing
// status codes itself. The adapter maps any returned error to a status + JSON
// envelope, keeping handlers thin (CONTRIBUTING.md).
type apiHandler func(http.ResponseWriter, *http.Request) error

func (h apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		writeError(w, r, err)
	}
}

// writeError maps err to an HTTP status and JSON envelope. A non-domain error is
// treated as 500 and its detail is logged but never returned to the client.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	log := logging.FromContext(r.Context())
	domain, ok := apierror.As(err)
	if qerr, quarantined := quarantineAPIError(err); quarantined {
		// D-62: a quarantined tenant's refusal wins over any wrapping domain
		// error, so the actionable message reaches the client on every route.
		domain, ok = qerr, true
	}
	if !ok {
		// WEB-20: a malformed id or other syntactically invalid value reaches
		// Postgres as 22P02 (invalid_text_representation) — e.g. a non-UUID on a
		// /v1/<resource>/{id} route. That is bad client input, not a server
		// fault, so map it to 400 rather than a 500: scanners and broken clients
		// stop generating ERROR-level 500s (noisy alerting / misleading SLO
		// burn), and the raw SQLSTATE detail is never returned or logged at
		// ERROR. The client message is fixed, so no query text leaks.
		var pgErr *pgconn.PgError
		switch {
		case errors.As(err, &pgErr) && pgErr.Code == "55000" &&
			(pgErr.Message == "tenant audit writes are fenced for lifecycle erasure" ||
				pgErr.Message == "tenant writes are fenced for lifecycle erasure"):
			// The durable lifecycle fence can win a race with the cached API
			// status check. Preserve the refusal and report the same lifecycle
			// denial as the early gate; never defer this audit or serve the read.
			// Match both SQLSTATE and the dedicated trigger messages: unrelated
			// object-state failures must retain their ordinary error handling.
			domain = apierror.Forbidden("tenant is offboarded").WithCode("tenant_offboarded")
		case errors.As(err, &pgErr) && pgErr.Code == "22P02":
			domain = apierror.BadRequest("malformed id or request parameter")
		default:
			domain = apierror.Internal("internal error")
		}
	}
	status := httpStatus(domain.Kind)
	if status >= http.StatusInternalServerError {
		// Server-side failures are logged with full detail; readiness/unavailable
		// is expected and transient, so it stays at debug to avoid probe spam.
		level := slog.LevelError
		if domain.Kind == apierror.KindUnavailable {
			level = slog.LevelDebug
		}
		log.Log(r.Context(), level, "request error",
			"code", domain.Code, "status", status, "error", err.Error())
	}
	reqID, _ := logging.RequestIDFromContext(r.Context())
	if writeQuarantineLoginPage(w, r, domain, reqID) {
		return
	}
	writeJSON(w, status, errorBody{Error: errorDetail{
		Code:      domain.Code,
		Message:   domain.Message,
		RequestID: reqID,
	}})
}

// quarantineAPIError maps a quarantined tenant's routing refusal (D-62) to the
// stable tenant_quarantined 503: which precondition failed on which plane, and
// that the operator fixes it. The operator-side cause never reaches the tenant.
func quarantineAPIError(err error) (*apierror.Error, bool) {
	var q *tenancy.QuarantinedError
	if !errors.As(err, &q) {
		return nil, false
	}
	return apierror.Unavailable(q.TenantMessage()).WithCode(string(apierror.CodeTenantQuarantined)), true
}
