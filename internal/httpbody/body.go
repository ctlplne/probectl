// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package httpbody provides shared fail-closed HTTP request body readers.
package httpbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var (
	// ErrTooLarge means the request body exceeded the configured cap.
	ErrTooLarge = errors.New("httpbody: request body too large")
	// ErrTrailingJSON means a JSON body contained more than one top-level value.
	ErrTrailingJSON = errors.New("httpbody: trailing JSON value")
)

// ReadLimited reads at most max bytes from r. It reads max+1 bytes internally
// so an oversized body is rejected with ErrTooLarge rather than silently
// truncated to a prefix.
func ReadLimited(r io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("httpbody: negative limit %d", max)
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// DecodeJSON reads a bounded JSON body and decodes exactly one top-level value.
// Trailing whitespace is allowed; trailing garbage or a second JSON value is
// rejected.
func DecodeJSON(r io.Reader, max int64, dst any) error {
	body, err := ReadLimited(r, max)
	if err != nil {
		return err
	}
	return decodeOneJSON(bytes.NewReader(body), dst, false)
}

// DecodeJSONStrict is DecodeJSON plus unknown-field rejection for
// probectl-owned REST schemas. Use DecodeJSON for third-party/extensible
// schemas such as SCIM and vendor webhooks.
func DecodeJSONStrict(r io.Reader, max int64, dst any) error {
	body, err := ReadLimited(r, max)
	if err != nil {
		return err
	}
	return decodeOneJSON(bytes.NewReader(body), dst, true)
}

// DecodeHTTPJSON decodes one HTTP JSON body with http.MaxBytesReader. It keeps
// unknown fields for compatibility with extensible third-party schemas.
func DecodeHTTPJSON(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	if max < 0 {
		return fmt.Errorf("httpbody: negative limit %d", max)
	}
	return decodeOneJSON(http.MaxBytesReader(w, r.Body, max), dst, false)
}

// DecodeHTTPJSONStrict is DecodeHTTPJSON plus unknown-field rejection for
// probectl-owned REST request schemas.
func DecodeHTTPJSONStrict(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	if max < 0 {
		return fmt.Errorf("httpbody: negative limit %d", max)
	}
	return decodeOneJSON(http.MaxBytesReader(w, r.Body, max), dst, true)
}

func decodeOneJSON(r io.Reader, dst any, strict bool) error {
	dec := json.NewDecoder(r)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		return normalizeDecodeError(err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != nil {
		if err == io.EOF {
			return nil
		}
		if errors.Is(normalizeDecodeError(err), ErrTooLarge) {
			return ErrTooLarge
		}
		return ErrTrailingJSON
	}
	return ErrTrailingJSON
}

func normalizeDecodeError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return ErrTooLarge
	}
	return err
}
