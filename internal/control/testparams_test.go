// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
)

// U-002: private-target overrides remain deny-by-default. CRYPTO-c46e93d2:
// certificate verification cannot be disabled by any principal, including one
// holding the historical test.insecure_tls permission.
func TestGuardPrivilegedTestParams(t *testing.T) {
	s := &Server{}
	withPerms := func(perms ...string) *http.Request {
		m := map[string]bool{}
		for _, p := range perms {
			m[p] = true
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/tests", nil)
		return r.WithContext(auth.WithPrincipal(r.Context(),
			&auth.Principal{TenantID: "t", UserID: "u", Permissions: m}))
	}
	anon := httptest.NewRequest(http.MethodPost, "/v1/tests", nil)

	cases := []struct {
		name     string
		r        *http.Request
		params   map[string]string
		wantKind apierror.Kind
	}{
		{"insecure_skip_verify rejected without permission",
			withPerms(permTestWrite), map[string]string{"insecure_skip_verify": "true"}, apierror.KindValidation},
		{"insecure_skip_verify denied for anonymous",
			anon, map[string]string{"insecure_skip_verify": "true"}, apierror.KindValidation},
		{"insecure_skip_verify rejected with historical test.insecure_tls",
			withPerms(permTestWrite, permTestInsecureTLS), map[string]string{"insecure_skip_verify": "true"}, apierror.KindValidation},
		{"allow_private_targets denied without permission (U-002)",
			withPerms(permTestWrite), map[string]string{"allow_private_targets": "true"}, apierror.KindForbidden},
		{"allow_private_targets allowed with test.allow_private",
			withPerms(permTestAllowPrivate), map[string]string{"allow_private_targets": "true"}, 0},
		{"forbidden TLS param cannot be combined with a permitted private target",
			withPerms(permTestAllowPrivate, permTestInsecureTLS), map[string]string{"allow_private_targets": "true", "insecure_skip_verify": "true"}, apierror.KindValidation},
		{"unprivileged params never gate",
			anon, map[string]string{"method": "POST", "insecure_skip_verify": "false"}, 0},
		{"no params never gate",
			anon, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.guardAllowPrivate(tc.r, tc.params)
			if tc.wantKind != 0 {
				de, ok := apierror.As(err)
				if !ok || de.Kind != tc.wantKind {
					t.Fatalf("want error kind %v, got %v", tc.wantKind, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
		})
	}
}
