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

// U-002/U-040: the privileged test params are deny-by-default — a principal
// without the matching admin-seeded permission is refused, one holding it
// passes, and unprivileged params never consult the gate.
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
		name   string
		r      *http.Request
		params map[string]string
		deny   bool
	}{
		{"insecure_skip_verify denied without permission (U-040)",
			withPerms(permTestWrite), map[string]string{"insecure_skip_verify": "true"}, true},
		{"insecure_skip_verify denied for anonymous",
			anon, map[string]string{"insecure_skip_verify": "true"}, true},
		{"insecure_skip_verify allowed with test.insecure_tls",
			withPerms(permTestWrite, permTestInsecureTLS), map[string]string{"insecure_skip_verify": "true"}, false},
		{"allow_private_targets denied without permission (U-002)",
			withPerms(permTestWrite), map[string]string{"allow_private_targets": "true"}, true},
		{"allow_private_targets allowed with test.allow_private",
			withPerms(permTestAllowPrivate), map[string]string{"allow_private_targets": "true"}, false},
		{"both params need both permissions",
			withPerms(permTestAllowPrivate), map[string]string{"allow_private_targets": "true", "insecure_skip_verify": "true"}, true},
		{"unprivileged params never gate",
			anon, map[string]string{"method": "POST", "insecure_skip_verify": "false"}, false},
		{"no params never gate",
			anon, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.guardAllowPrivate(tc.r, tc.params)
			if tc.deny {
				de, ok := apierror.As(err)
				if !ok || de.Kind != apierror.KindForbidden {
					t.Fatalf("want 403, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
		})
	}
}
