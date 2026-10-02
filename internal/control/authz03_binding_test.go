// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
)

// TestDecideSSOBinding is the AUTHZ-03 regression at the unit level: the SSO
// binding policy must key on the ID token's stable (issuer, subject) pair, not
// the mutable email claim, and must refuse an IdP-unverified email. It is a
// pure function, so this runs in plain `go test` with no database.
func TestDecideSSOBinding(t *testing.T) {
	boolp := func(b bool) *bool { return &b }
	const (
		iss  = "https://idp.example"
		subA = "subject-A"
		subB = "subject-B"
		mail = "user@example.com"
	)
	// A pre-provisioned (SCIM) account: an email row with no (iss, sub) yet.
	preProvisioned := &store.User{ID: "u-pre", Email: mail}
	// The same account after it has linked to subject A.
	boundToA := &store.User{ID: "u-pre", Email: mail, OIDCIssuer: iss, OIDCSubject: subA}

	tests := []struct {
		name       string
		ident      auth.Identity
		bySub      *store.User
		byEmail    *store.User
		wantAction ssoAction
		wantUser   string // user ID the policy proceeds with ("" when none)
	}{
		{
			// (a) email_verified=false -> deny, regardless of any match.
			name:       "unverified_email_denied",
			ident:      auth.Identity{Issuer: iss, Subject: subA, Email: mail, EmailVerified: boolp(false)},
			byEmail:    preProvisioned,
			wantAction: ssoDeny,
		},
		{
			// (c) pre-created account, first verified OIDC login -> link once.
			name:       "first_login_links_pre_provisioned",
			ident:      auth.Identity{Issuer: iss, Subject: subA, Email: mail, EmailVerified: boolp(true)},
			byEmail:    preProvisioned,
			wantAction: ssoLink,
			wantUser:   "u-pre",
		},
		{
			// Linking by email is refused when the IdP did not VERIFY the email,
			// even if it merely omitted the claim — closes the takeover vector.
			name:       "link_refused_without_verified_email",
			ident:      auth.Identity{Issuer: iss, Subject: subA, Email: mail},
			byEmail:    preProvisioned,
			wantAction: ssoDeny,
		},
		{
			// (c) once bound, the same (iss, sub) is the authoritative match.
			name:       "bound_subject_matches",
			ident:      auth.Identity{Issuer: iss, Subject: subA, Email: mail, EmailVerified: boolp(true)},
			bySub:      boundToA,
			byEmail:    boundToA,
			wantAction: ssoLogin,
			wantUser:   "u-pre",
		},
		{
			// (b) a DIFFERENT subject presenting the same email is refused — the
			// account is already bound to subject A (bySub is nil for subject B).
			name:       "second_subject_same_email_denied",
			ident:      auth.Identity{Issuer: iss, Subject: subB, Email: mail, EmailVerified: boolp(true)},
			bySub:      nil,
			byEmail:    boundToA,
			wantAction: ssoDeny,
		},
		{
			// A brand-new verified identity with no existing row -> provision.
			name:       "new_identity_provisions",
			ident:      auth.Identity{Issuer: iss, Subject: subA, Email: mail, EmailVerified: boolp(true)},
			wantAction: ssoProvision,
		},
		{
			// Back-compat: a non-OIDC provider (no issuer) keeps the historical
			// email match so the existing session/RBAC harness is unaffected.
			name:       "legacy_no_issuer_email_match",
			ident:      auth.Identity{Subject: subA, Email: mail},
			byEmail:    preProvisioned,
			wantAction: ssoLogin,
			wantUser:   "u-pre",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAction, gotUser := decideSSOBinding(tc.ident, tc.bySub, tc.byEmail)
			if gotAction != tc.wantAction {
				t.Fatalf("action = %d, want %d", gotAction, tc.wantAction)
			}
			gotID := ""
			if gotUser != nil {
				gotID = gotUser.ID
			}
			if gotID != tc.wantUser {
				t.Fatalf("user = %q, want %q", gotID, tc.wantUser)
			}
		})
	}
}
