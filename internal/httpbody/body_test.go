// SPDX-License-Identifier: LicenseRef-probectl-TBD

package httpbody

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadLimitedRejectsOversizeWithoutTruncation(t *testing.T) {
	body, err := ReadLimited(strings.NewReader("12345"), 5)
	if err != nil {
		t.Fatalf("exact limit should pass: %v", err)
	}
	if string(body) != "12345" {
		t.Fatalf("body = %q", body)
	}
	if _, err := ReadLimited(strings.NewReader("123456"), 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized body must return ErrTooLarge, got %v", err)
	}
}

func TestDecodeJSONRejectsTrailingValues(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := DecodeJSON(strings.NewReader(`{"name":"ok"}   `), 64, &dst); err != nil {
		t.Fatalf("single value with whitespace should pass: %v", err)
	}
	if dst.Name != "ok" {
		t.Fatalf("name = %q", dst.Name)
	}
	if err := DecodeJSON(strings.NewReader(`{"name":"ok"} {"name":"extra"}`), 64, &dst); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("second JSON value must return ErrTrailingJSON, got %v", err)
	}
	if err := DecodeJSON(strings.NewReader(`{"name":"ok"} garbage`), 64, &dst); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("trailing garbage must return ErrTrailingJSON, got %v", err)
	}
}

func TestDecodeJSONRejectsOversize(t *testing.T) {
	var dst map[string]string
	if err := DecodeJSON(strings.NewReader(`{"x":"`+strings.Repeat("a", 32)+`"}`), 16, &dst); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized JSON must return ErrTooLarge, got %v", err)
	}
}

func TestDecodeJSONStrictRejectsUnknownFields(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	if err := DecodeJSONStrict(strings.NewReader(`{"name":"ok","extra":true}`), 64, &dst); err == nil {
		t.Fatal("strict JSON must reject unknown fields")
	}
	if err := DecodeJSON(strings.NewReader(`{"name":"ok","extra":true}`), 64, &dst); err != nil {
		t.Fatalf("compat JSON should allow unknown fields: %v", err)
	}
}

func TestDecodeHTTPJSONStrictUsesMaxBytesReader(t *testing.T) {
	var dst map[string]string
	req := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(`{"x":"`+strings.Repeat("a", 32)+`"}`))
	if err := DecodeHTTPJSONStrict(httptest.NewRecorder(), req, 16, &dst); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized HTTP JSON must return ErrTooLarge, got %v", err)
	}
}
