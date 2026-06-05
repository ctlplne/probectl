// Package apierror defines probectl's transport-agnostic domain errors. Services
// return these; the transport layer (internal/control) maps each Kind to an HTTP
// status and a JSON envelope (CLAUDE.md §6). Keeping the category here, separate
// from any HTTP specifics, lets non-HTTP callers (gRPC, MCP) reuse the same
// classification.
package apierror

import (
	"errors"
	"fmt"
)

// Kind is a coarse, transport-agnostic error category.
type Kind int

const (
	KindInternal     Kind = iota // unexpected failure
	KindBadRequest               // malformed / syntactically invalid request
	KindValidation               // well-formed but semantically invalid
	KindUnauthorized             // authentication required or failed
	KindForbidden                // authenticated but not permitted
	KindNotFound                 // resource does not exist
	KindConflict                 // state conflict (duplicate, version, ...)
	KindUnavailable              // a dependency is not ready
	KindRateLimited              // the caller exceeded a rate/fairness bound
)

// Error is a domain error carrying a Kind, a stable machine-readable Code, a
// human-readable Message, and an optional wrapped cause.
type Error struct {
	Kind    Kind
	Code    string
	Message string
	err     error
}

func (e *Error) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the wrapped cause for errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.err }

// Wrap attaches a cause and returns the same *Error for chaining.
func (e *Error) Wrap(cause error) *Error {
	e.err = cause
	return e
}

// WithCode overrides the default machine-readable code and returns e.
func (e *Error) WithCode(code string) *Error {
	e.Code = code
	return e
}

func newError(kind Kind, code, message string) *Error {
	return &Error{Kind: kind, Code: code, Message: message}
}

// Constructors with sensible default codes.
func Internal(message string) *Error     { return newError(KindInternal, "internal", message) }
func BadRequest(message string) *Error   { return newError(KindBadRequest, "bad_request", message) }
func Validation(message string) *Error   { return newError(KindValidation, "validation", message) }
func Unauthorized(message string) *Error { return newError(KindUnauthorized, "unauthorized", message) }
func Forbidden(message string) *Error    { return newError(KindForbidden, "forbidden", message) }
func NotFound(message string) *Error     { return newError(KindNotFound, "not_found", message) }
func Conflict(message string) *Error     { return newError(KindConflict, "conflict", message) }
func Unavailable(message string) *Error  { return newError(KindUnavailable, "unavailable", message) }
func RateLimited(message string) *Error  { return newError(KindRateLimited, "rate_limited", message) }

// As returns the *Error in err's chain, or (nil, false) if there is none. The
// transport layer treats a plain (non-domain) error as KindInternal.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
