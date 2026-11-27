// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPSenderErrorsDoNotExposeDestinationCredentials(t *testing.T) {
	const raw = "https://siem.example/fixture-key-in-path?channel=fixture-key-in-query"
	transport := elasticProtocolDoer(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: errors.New("fixture transport refused")}
	})
	for _, tc := range []struct {
		name, endpoint, want string
		preset               Preset
		client               Doer
	}{
		{"status", raw, "HTTP 503", PresetSplunk, &fakeDoer{status: http.StatusServiceUnavailable}},
		{"transport", raw, "transport failed", PresetSplunk, transport},
		{"request", raw + "\x00", "invalid delivery URL", PresetSplunk, transport},
		{"bulk parse", raw + "\x00", "invalid delivery URL", PresetElastic, transport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := NewHTTPSender(tc.preset, tc.endpoint, "fixture-auth-key", AuthSchemeDefault, "application/json", tc.client)
			err := sender.Send(t.Context(), []byte("fixture payload"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected sanitized %s failure", tc.name)
			}
			if msg := err.Error(); strings.Contains(msg, "fixture-key") || strings.Contains(msg, "fixture-auth-key") ||
				strings.Contains(msg, "siem.example") {
				t.Fatal("delivery error exposed destination credentials")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sender := NewHTTPSender(PresetSplunk, raw, "", AuthSchemeDefault, "application/json", transport)
	if err := sender.Send(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("delivery lost caller cancellation")
	}
}

// TestTheAuthSchemeCanBePinnedForTheTargetYouActuallyRun (DPR-115): the elastic
// preset always sent "ApiKey", which Elasticsearch understands and OpenSearch
// does not — so the shipped preset could not authenticate to the self-hosted
// Elastic-compatible SIEM most operators run, and the docs' own unblock step
// for this lab named exactly that target.
func TestTheAuthSchemeCanBePinnedForTheTargetYouActuallyRun(t *testing.T) {
	for _, tc := range []struct {
		name, scheme, want string
		preset             Preset
	}{
		{"elastic default stays ApiKey", AuthSchemeDefault, "ApiKey tok", PresetElastic},
		{"opensearch takes basic", AuthSchemeBasic, "Basic YWRtaW46c2VjcmV0", PresetElastic},
		{"splunk default", AuthSchemeDefault, "Splunk tok", PresetSplunk},
		{"generic default is bearer", AuthSchemeDefault, "Bearer tok", PresetGeneric},
		{"a preset can be overridden to bearer", AuthSchemeBearer, "Bearer tok", PresetElastic},
		{"none sends no header at all", AuthSchemeNone, "", PresetElastic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := "tok"
			if tc.scheme == AuthSchemeBasic {
				token = "admin:secret"
			}
			name, value := tc.preset.authHeader(token, tc.scheme)
			if tc.want == "" {
				if name != "" || value != "" {
					t.Fatalf("expected no Authorization header, got %q: %q", name, value)
				}
				return
			}
			if name != "Authorization" || value != tc.want {
				t.Fatalf("got %q: %q, want Authorization: %q", name, value, tc.want)
			}
		})
	}
	// An empty token never produces a header, whatever the scheme.
	if n, v := PresetElastic.authHeader("", AuthSchemeBasic); n != "" || v != "" {
		t.Errorf("an empty token must not produce a header, got %q: %q", n, v)
	}
}
