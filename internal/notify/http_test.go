// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type deliveryFailureDoer func(*http.Request) (*http.Response, error)

func (f deliveryFailureDoer) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestDeliveryErrorsExcludeWebhookCredentials(t *testing.T) {
	const endpoint = "https://webhook.example.test/hook/fixture-path?sig=fixture-signature"
	for _, tc := range []struct {
		name, endpoint, want string
		do                   deliveryFailureDoer
	}{
		{"invalid request", endpoint + "\n", "notify: invalid delivery request", nil},
		{"transport failure", endpoint, "notify: delivery transport failed", func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: errors.New("connection failed at fixture-signature")}
		}},
		{"provider rejection", endpoint, "notify: POST returned HTTP 503", func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := doJSONBytes(t.Context(), tc.do, http.MethodPost, tc.endpoint, nil, []byte(`{}`))
			if err == nil || strings.Contains(err.Error(), "fixture-") || err.Error() != tc.want {
				t.Fatal("delivery error must describe the failure without a credential-bearing URL")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client := deliveryFailureDoer(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: req.Context().Err()}
	})
	if _, err := doJSONBytes(ctx, client, http.MethodPost, endpoint, nil, nil); !errors.Is(err, context.Canceled) || err != context.Canceled {
		t.Fatal("request cancellation should retain only the context error")
	}
}
