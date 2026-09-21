// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import "encoding/base64"

// NewPKCEVerifier returns an RFC 7636 verifier with 256 bits of entropy. Raw
// base64url encodes 32 random bytes as 43 unreserved characters, satisfying the
// RFC's 43..128 character verifier requirement without padding.
func NewPKCEVerifier() (string, error) {
	raw, err := Random(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// PKCEChallengeS256 derives the RFC 7636 S256 code challenge through the
// configured crypto Provider (FIPS-swappable SHA-256), then raw-base64url
// encodes it for the authorization request.
func PKCEChallengeS256(verifier string) string {
	return base64.RawURLEncoding.EncodeToString(Hash([]byte(verifier)))
}
