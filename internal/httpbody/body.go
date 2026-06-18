// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package httpbody provides shared fail-closed HTTP request body readers.
package httpbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err == io.EOF {
		return nil
	}
	return ErrTrailingJSON
}
