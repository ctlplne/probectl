// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package secrets

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type azureRTFunc func(*http.Request) (*http.Response, error)

func (f azureRTFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestAzureVaultNameRejectsSSRF is the CRY-04 regression. The Key Vault host is
// derived by concatenating the vault name into
// "https://<vault>.vault.azure.net". A name containing '?', '#', '/', '@' or
// '.' redirects the dialed host — and the AAD bearer token scoped to
// vault.azure.net — off *.vault.azure.net (e.g. "evil.com#x" dials evil.com).
// The guard must reject a non-conforming name with an invalid-name error before
// any request is dialed; a conforming name must still reach a *.vault.azure.net
// host.
//
// The stub transport captures the dialed host and returns a secret, so on the
// UNGUARDED code a crafted name returns the secret with no error (and a non-
// vault host) — the red state — rather than erroring for an unrelated reason.
func TestAzureVaultNameRejectsSSRF(t *testing.T) {
	ctx := context.Background()
	newSrc := func() (*AzureSource, *string) {
		var host string
		s := &AzureSource{
			tok:    "cached", // skip the AAD token dial
			tokExp: time.Now().Add(time.Hour),
			client: &http.Client{Transport: azureRTFunc(func(r *http.Request) (*http.Response, error) {
				host = r.URL.Host
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"value":"sekret"}`)),
					Header:     make(http.Header),
				}, nil
			})},
		}
		return s, &host
	}

	for _, bad := range []string{
		"evil.com#x",     // '#': host becomes evil.com
		"evil.com?x",     // '?': host becomes evil.com
		"evil.com",       // '.': non-conforming
		"user@evil",      // '@': userinfo
		"vault.internal", // '.'
		"ab",             // too short (<3)
		"",               // empty
	} {
		s, host := newSrc()
		_, err := s.Fetch(ctx, Ref{Path: bad + "/secret"})
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("CRY-04: vault name %q must be rejected with an invalid-name error before dialing; got err=%v, dialed host=%q", bad, err, *host)
		}
	}

	// A conforming name still reaches a *.vault.azure.net host.
	s, host := newSrc()
	val, err := s.Fetch(ctx, Ref{Path: "my-valid-vault/secret"})
	if err != nil {
		t.Fatalf("CRY-04: a valid vault name was rejected: %v", err)
	}
	if val != "sekret" {
		t.Fatalf("value = %q, want sekret", val)
	}
	if !strings.HasSuffix(*host, ".vault.azure.net") {
		t.Fatalf("CRY-04: valid name dialed host %q, want a *.vault.azure.net host", *host)
	}
}
