// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import "testing"

func TestCanonicalHTTPOriginPreservesOnlyExplicitTupleAuthority(t *testing.T) {
	for input, want := range map[string]string{"HTTPS://Allowed.Example:443": "https://allowed.example", "http://localhost:80": "http://localhost", "https://allowed.example:08443": "https://allowed.example:8443", "https://[0:0:0:0:0:0:0:1]:443": "https://[::1]", "http://127.0.0.1:18448": "http://127.0.0.1:18448", "https://xn--bcher-kva.example": "https://xn--bcher-kva.example", "http://localhost:0": "http://localhost:0"} {
		actual, err := CanonicalHTTPOrigin(input)
		if err != nil || actual != want {
			t.Fatal("origin tuple changed", input, actual, err)
		}
		if next, err := CanonicalHTTPOrigin(actual); err != nil || next != actual {
			t.Fatal("canonical origin is not idempotent")
		}
	}
	for _, input := range []string{"", "null", "*", "https://*.example", "https://user:secret@allowed.example", "https://allowed.example/", "https://allowed.example/path", "https://allowed.example?", "https://allowed.example#", "https://allowed.example#fragment", "https://allowed.example https://evil.example", "https://allowed.example,https://evil.example", "https://allowed.example:\n443", " https://allowed.example", "https://allowed.example:", "https://allowed.example:65536", "https://[v1.bad]", "https://[fe80::1%25en0]", "https://bücher.example", "file:///tmp/client", "javascript:private"} {
		if _, err := CanonicalHTTPOrigin(input); err == nil {
			t.Fatal("unsafe or opaque origin accepted", input)
		}
	}
}
