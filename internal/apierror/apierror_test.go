package apierror

import (
	"errors"
	"fmt"
	"testing"
)

func TestConstructorsSetKindAndCode(t *testing.T) {
	cases := []struct {
		e    *Error
		kind Kind
		code string
	}{
		{Internal("x"), KindInternal, "internal"},
		{BadRequest("x"), KindBadRequest, "bad_request"},
		{Validation("x"), KindValidation, "validation"},
		{Unauthorized("x"), KindUnauthorized, "unauthorized"},
		{Forbidden("x"), KindForbidden, "forbidden"},
		{NotFound("x"), KindNotFound, "not_found"},
		{Conflict("x"), KindConflict, "conflict"},
		{Unavailable("x"), KindUnavailable, "unavailable"},
	}
	for _, c := range cases {
		if c.e.Kind != c.kind {
			t.Errorf("%q: kind = %v, want %v", c.e.Code, c.e.Kind, c.kind)
		}
		if c.e.Code != c.code {
			t.Errorf("code = %q, want %q", c.e.Code, c.code)
		}
	}
}

func TestWrapUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := NotFound("missing").Wrap(cause)
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause")
	}
}

func TestAs(t *testing.T) {
	wrapped := fmt.Errorf("service: %w", Conflict("dup"))
	got, ok := As(wrapped)
	if !ok || got.Kind != KindConflict {
		t.Errorf("As(wrapped) = (%v, %v), want a KindConflict error", got, ok)
	}
	if _, ok := As(errors.New("plain")); ok {
		t.Error("As(plain error) should be false")
	}
}

func TestWithCode(t *testing.T) {
	e := Validation("bad").WithCode("field_required")
	if e.Code != "field_required" {
		t.Errorf("Code = %q, want field_required", e.Code)
	}
}
