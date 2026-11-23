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
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const userAgent = "probectl-oncall"

// maxRespBody bounds a provider response read (untrusted input).
const maxRespBody = 1 << 16

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
		return nil, fmt.Errorf("notify: %s returned HTTP %d", method, resp.StatusCode)
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
