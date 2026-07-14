// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package auth

import "testing"

// SEC-005: MFA is derived from the ID token's amr/acr. A single password is
// NOT MFA; an explicit "mfa" or any strong second factor (otp/hwk/sms/...) is,
// as is an acr naming mfa / aal2+ / loa2+.
func TestMFAFromAuthContext(t *testing.T) {
	cases := []struct {
		name string
		amr  []string
		acr  string
		want bool
	}{
		{"password only", []string{"pwd"}, "", false},
		{"explicit mfa", []string{"pwd", "mfa"}, "", true},
		{"otp second factor", []string{"pwd", "otp"}, "", true},
		{"hardware key", []string{"hwk"}, "", true},
		{"sms", []string{"pwd", "sms"}, "", true},
		{"pin only is not mfa", []string{"pin"}, "", false},
		{"kba only is not mfa", []string{"kba"}, "", false},
		{"case-insensitive", []string{"OTP"}, "", true},
		{"acr aal2", nil, "urn:example:aal2", true},
		{"acr loa3", nil, "loa3", true},
		{"acr names mfa", nil, "http://schemas.example/claims/mfa", true},
		{"acr level 0", nil, "0", false},
		{"nothing", nil, "", false},
	}
	for _, tc := range cases {
		if got := mfaFromAuthContext(tc.amr, tc.acr); got != tc.want {
			t.Errorf("%s: mfaFromAuthContext(%v, %q) = %v, want %v", tc.name, tc.amr, tc.acr, got, tc.want)
		}
	}
}
