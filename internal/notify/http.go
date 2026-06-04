package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
