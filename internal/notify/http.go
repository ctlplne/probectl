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
func doJSONBytes(ctx context.Context, client Doer, method, url string, headers map[string]string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("notify: %s %s status %d", method, url, resp.StatusCode)
	}
	return out, nil
}

// clientOr returns the injected client or the hardened default.
func clientOr(c Doer) Doer {
	if c != nil {
		return c
	}
	return defaultClient()
}
