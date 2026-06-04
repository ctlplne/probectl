package threat

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// CTChecker correlates a leaf certificate against Certificate Transparency logs
// for issuance anomalies. Implementations MUST fetch over TLS (cert-validated),
// respect the source's AUP / rate limits, and DEGRADE GRACEFULLY — a down or
// rate-limited CT source returns ok=false, never an error that breaks posture
// (CLAUDE.md §7 guardrail 10).
type CTChecker interface {
	Check(ctx context.Context, leaf *x509.Certificate) (Finding, bool)
}

// CrtSh queries crt.sh's JSON API for a certificate's serial. It is OFF by default
// (external fetch — sovereignty / no-phone-home, and crt.sh AUP / rate limits);
// operators opt in. A serial unknown to CT surfaces a low-severity
// ct_not_logged anomaly; any error or a logged cert yields no finding.
type CrtSh struct {
	endpoint string
	client   *http.Client
}

// NewCrtSh builds a crt.sh checker. endpoint defaults to https://crt.sh.
func NewCrtSh(endpoint string, timeout time.Duration) *CrtSh {
	if endpoint == "" {
		endpoint = "https://crt.sh"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &CrtSh{endpoint: strings.TrimRight(endpoint, "/"), client: crypto.HardenedHTTPClient(timeout)}
}

// Check queries crt.sh by the cert's serial number.
func (c *CrtSh) Check(ctx context.Context, leaf *x509.Certificate) (Finding, bool) {
	serial := fmt.Sprintf("%x", leaf.SerialNumber)
	endpoint := c.endpoint + "/?serial=" + url.QueryEscape(serial) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Finding{}, false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Finding{}, false // CT down / unreachable → graceful no-op
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Finding{}, false // rate-limited / error → graceful no-op
	}
	var entries []map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&entries); err != nil {
		return Finding{}, false
	}
	if len(entries) == 0 {
		return Finding{
			Kind:     FindingCTNotLogged,
			Severity: SeverityInfo,
			Message:  "certificate serial not found in Certificate Transparency logs",
		}, true
	}
	return Finding{}, false // present in CT → no anomaly
}
