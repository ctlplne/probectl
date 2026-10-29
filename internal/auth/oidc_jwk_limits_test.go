// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// OIDC's upstream JWK parser must reject an oversized modulus before expensive
// RSA validation (GHSA-mgcc-cww5-fp2q). Synthetic public integers avoid key
// generation and never exercise the advisory's CPU-exhausting private inputs.
func TestOIDCJWKParsingBoundsRSAModulus(t *testing.T) {
	for _, bits := range []int{2048, 4096, 4097} {
		modulus := make([]byte, (bits+7)/8)
		modulus[0] = byte(1 << ((bits - 1) % 8))
		modulus[len(modulus)-1] = 1
		raw, err := json.Marshal(map[string]string{
			"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(modulus), "e": "AQAB",
		})
		if err != nil {
			t.Fatal(err)
		}
		var key jose.JSONWebKey
		err = json.Unmarshal(raw, &key)
		if bits <= 4096 && err != nil {
			t.Fatalf("supported %d-bit public JWK refused: %v", bits, err)
		}
		if bits > 4096 && err == nil {
			t.Fatal("oversized RSA JWK accepted by the OIDC dependency")
		}
	}
}
