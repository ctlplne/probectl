package control

import (
	"log/slog"
	"net/http"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/logging"
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
// envelope, keeping handlers thin (CLAUDE.md §6).
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
	if !ok {
		domain = apierror.Internal("internal error")
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
	writeJSON(w, status, errorBody{Error: errorDetail{
		Code:      domain.Code,
		Message:   domain.Message,
		RequestID: reqID,
	}})
}
