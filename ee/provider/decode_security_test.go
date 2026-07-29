// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProviderDecodeRejectsTrailingJSON(t *testing.T) {
	const valid = `{"email":"ops@example.com","password":"pw","totp":"123456"}`
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{name: "object", suffix: ` {}`},
		{name: "array", suffix: ` []`},
		{name: "scalar", suffix: ` 7`},
		{name: "garbage", suffix: ` not-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/login", strings.NewReader(valid+tc.suffix))
			if err := decode(req, &providerLoginInput{}); err == nil {
				t.Fatal("request with a trailing top-level value must be rejected")
			} else {
				var bad errBadJSON
				if !errors.As(err, &bad) {
					t.Fatalf("error = %T %v, want errBadJSON", err, err)
				}
			}
		})
	}
}

func TestProviderDecodePreservesStrictnessLimitsAndWhitespace(t *testing.T) {
	t.Run("trailing whitespace", func(t *testing.T) {
		var got providerLoginInput
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/login", strings.NewReader(
			`{"email":"ops@example.com","password":"pw","totp":"123456"}  `+"\n\t",
		))
		if err := decode(req, &got); err != nil {
			t.Fatalf("trailing whitespace should be accepted: %v", err)
		}
		if got.Email != "ops@example.com" {
			t.Fatalf("decoded email = %q", got.Email)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/login", strings.NewReader(
			`{"email":"ops@example.com","password":"pw","totp":"123456","extra":true}`,
		))
		if err := decode(req, &providerLoginInput{}); err == nil {
			t.Fatal("unknown field must remain rejected")
		}
	})

	t.Run("body limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/auth/login", strings.NewReader(
			`{"email":"`+strings.Repeat("x", 1<<20)+`"}`,
		))
		if err := decode(req, &providerLoginInput{}); err == nil {
			t.Fatal("body over 1 MiB must remain rejected")
		}
	})
}
