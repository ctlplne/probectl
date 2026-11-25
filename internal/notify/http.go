// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const userAgent = "probectl-oncall"

// maxRespBody bounds a provider response read (untrusted input).
const maxRespBody = 1 << 16

type httpStatusError struct {
	method string
	status int
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("notify: %s returned HTTP %d", e.method, e.status)
}

// defaultClient is the hardened (certificate-validating) HTTP client a connector
// uses when none is injected — outbound TLS is never disabled (guardrail 12).
func defaultClient() Doer { return crypto.HardenedHTTPClient(15 * time.Second) }

// doJSON sends a JSON body to url and returns the 2xx response body. headers are
// applied after the defaults (Content-Type/User-Agent), e.g. for provider auth.
func doJSON(ctx context.Context, client Doer, method, url string, headers map[string]string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return doJSONBytes(ctx, client, method, url, headers, body)
}

// doJSONBytes sends already-canonical JSON bytes. Signed connectors use this so
// the receiver verifies exactly the bytes covered by the HMAC.
func doJSONBytes(ctx context.Context, client Doer, method, endpoint string, headers map[string]string, body []byte) ([]byte, error) {
	// Endpoint paths and query values can themselves authorize delivery. Both
	// request parsing and HTTP transport errors can include the entire URL.
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("notify: invalid delivery request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("notify: delivery transport failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRespBody))
		return nil, httpStatusError{method: method, status: resp.StatusCode}
	}
	out, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	return out, nil
}

// clientOr returns the injected client or the hardened default.
func clientOr(c Doer) Doer {
	if c != nil {
		return c
	}
	return defaultClient()
}

func psaHTTPSURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return nil, errors.New("notify: expected an HTTPS URL without credentials, query or fragment")
	}
	return parsed, nil
}

// clientWithoutRedirects keeps API keys, bearer tokens and OAuth form bodies
// on their configured endpoints. Redirects can replay a form even when no
// credential header is present.
func clientWithoutRedirects(injected Doer) Doer {
	client := clientOr(injected)
	if transport, ok := client.(*http.Client); ok {
		strict := *transport
		strict.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &strict
	}
	return client
}

// ticketCreateError identifies a vendor response that definitely rejected the create.
func ticketCreateError(err error) error {
	var status httpStatusError
	if errors.As(err, &status) {
		switch status.status {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity:
			return fmt.Errorf("%w: %w", errTicketCreateRejected, err)
		}
	}
	return err
}
