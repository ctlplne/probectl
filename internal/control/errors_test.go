package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
)

func TestHTTPStatusMapping(t *testing.T) {
	cases := []struct {
		kind apierror.Kind
		want int
	}{
		{apierror.KindBadRequest, http.StatusBadRequest},
		{apierror.KindUnauthorized, http.StatusUnauthorized},
		{apierror.KindForbidden, http.StatusForbidden},
		{apierror.KindNotFound, http.StatusNotFound},
		{apierror.KindConflict, http.StatusConflict},
		{apierror.KindValidation, http.StatusUnprocessableEntity},
		{apierror.KindInternal, http.StatusInternalServerError},
		{apierror.KindUnavailable, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		if got := httpStatus(c.kind); got != c.want {
			t.Errorf("httpStatus(%v) = %d, want %d", c.kind, got, c.want)
		}
	}
}

func TestAPIHandlerMapsErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"not_found", apierror.NotFound("nope"), http.StatusNotFound, "not_found"},
		{"validation", apierror.Validation("bad"), http.StatusUnprocessableEntity, "validation"},
		{"conflict", apierror.Conflict("dup"), http.StatusConflict, "conflict"},
		{"unauthorized", apierror.Unauthorized("no"), http.StatusUnauthorized, "unauthorized"},
		{"forbidden", apierror.Forbidden("no"), http.StatusForbidden, "forbidden"},
		{"internal", apierror.Internal("boom"), http.StatusInternalServerError, "internal"},
		{"plain", errors.New("leaky internal detail"), http.StatusInternalServerError, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := apiHandler(func(http.ResponseWriter, *http.Request) error { return c.err })
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			var body errorBody
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Error.Code != c.wantCode {
				t.Errorf("code = %q, want %q", body.Error.Code, c.wantCode)
			}
			// A non-domain error must not leak its internal detail to the client.
			if c.name == "plain" && body.Error.Message != "internal error" {
				t.Errorf("plain error leaked detail to client: %q", body.Error.Message)
			}
		})
	}
}
