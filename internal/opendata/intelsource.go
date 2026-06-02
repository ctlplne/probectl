package opendata

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
)

// KindThreatIntel classifies threat-intel feeds.
const KindThreatIntel Kind = "threat_intel"

// ThreatIntelSource is a threat-intel feed adapter (S28): it fetches a public feed
// and normalizes it into IOCs, with per-source AUP / provenance. SEVERAL feeds
// restrict commercial redistribution — tracked in the Descriptor's AUP (relevant
// to MSP resale, NOT to single-tenant OSS use — CLAUDE.md §2/§10).
type ThreatIntelSource interface {
	Descriptor() Descriptor
	Fetch(ctx context.Context) ([]IOC, error)
}

// lineFeed is a generic line-based feed: it GETs a URL and parses each
// non-comment line into an IOC. The fetch is over hardened TLS (certificate
// validation on — guardrail 12) and treats the body as untrusted input; a failed
// fetch returns an error (the refresher keeps the prior IOCs — graceful
// degradation, guardrail 10).
type lineFeed struct {
	desc   Descriptor
	url    string
	client Doer
	parse  func(line string) (IOC, bool)
}

func (f *lineFeed) Descriptor() Descriptor { return f.desc }

func (f *lineFeed) Fetch(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatintel %s: %w", f.desc.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatintel %s: status %d", f.desc.Name, resp.StatusCode)
	}
	return parseFeed(io.LimitReader(resp.Body, 32<<20), f.parse), nil
}

// parseFeed applies a per-line parser over a feed body, skipping blank/comment
// lines. Exported-shape logic kept testable: the per-feed parsers are pure.
func parseFeed(r io.Reader, parse func(string) (IOC, bool)) []IOC {
	var out []IOC
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if ioc, ok := parse(line); ok {
			out = append(out, ioc)
		}
	}
	return out
}

func defaultIntelClient() Doer { return crypto.HardenedHTTPClient(15 * time.Second) }
