// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const slackHuddlesGoldenDocument = `<!doctype html><html><body><article>
<h1>Slack huddles network configuration</h1>
<h3><br><strong>Huddles network paths</strong></h3><ul>
<li>Approve <strong>*.chime.aws</strong> or IP range <strong>192.0.2.0/24</strong>, <strong>2001:db8:a::/48</strong></li>
<li>Allow UDP/3478 or UDP/22466 and TCP/443</li></ul>
<h2>Unrelated example</h2><p>Do not use 198.51.100.0/24 as a network path.</p>
</article></body></html>` + "\n"

func TestSlackHuddlesCompleteBulkKeepsScopedOriginalAndSharedNetworkUnknown(t *testing.T) {
	mode := "ok"
	requests := 0
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodGet || req.URL.String() != "https://slack.com/help/articles/36284146785427-Guide-to-network-and-system-configuration-for-Slack-huddles" || req.Header.Get("Authorization") != "" || req.Header.Get("X-Probectl-Tenant") != "" || len(req.Cookies()) != 0 {
			t.Fatal("Slack public bulk request carried private context or left fixed publisher")
		}
		body := slackHuddlesGoldenDocument
		switch mode {
		case "incomplete":
			body = strings.TrimSuffix(body, "</article></body></html>\n")
		case "missing-scope":
			body = strings.Replace(body, "Huddles network paths", "Different section", 1)
		case "malformed-prefix":
			body = strings.Replace(body, "192.0.2.0/24", "192.0.2.0/999", 1)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Age": []string{"3600"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	path := filepath.Join(t.TempDir(), "slack.json")
	if err := FetchServiceRangeCache(t.Context(), path, []string{"slack"}, 24*time.Hour, 16<<20, client); err != nil {
		t.Fatal("complete scoped Slack source refused", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope serviceRangeEnvelope
	if json.Unmarshal(original, &envelope) != nil || len(envelope.Sources) != 1 || string(envelope.Sources[0].Data) != slackHuddlesGoldenDocument || time.Since(envelope.Sources[0].FetchedAt) < 59*time.Minute {
		t.Fatal("Slack original HTML body or fetch age changed")
	}
	at := time.Now().UTC()
	source, err := LoadServiceRanges(t.Context(), path, 24*time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(crypto.Hash([]byte(slackHuddlesGoldenDocument)))
	for _, address := range []string{"192.0.2.7", "2001:db8:a::7"} {
		status := source.lookup(netip.MustParseAddr(address), at, true)[0]
		if status.Publisher != "slack_huddles" || status.Status != "matched" || status.Digest != digest || status.Version != "sha256:"+digest || !status.PublishedAt.IsZero() || len(status.Matches) != 1 || status.Matches[0].Service != "Slack Huddles network dependency" || status.Matches[0].Region != "" {
			t.Fatal("Slack native scope or original identity changed", status)
		}
		value := ClassifyServiceRanges([]ServiceRangeStatus{status}, at)
		if value.Status != "unknown" || value.Service != "" || len(value.Sources) != 1 {
			t.Fatal("shared Chime dependency falsely proved Slack application traffic", value)
		}
	}
	if status := source.lookup(netip.MustParseAddr("198.51.100.7"), at, true)[0]; len(status.Matches) != 0 {
		t.Fatal("unrelated article example became a published Slack path", status)
	}
	if status := source.lookup(netip.MustParseAddr("192.0.2.7"), at.Add(24*time.Hour), true)[0]; status.Status != "stale" || len(status.Matches) != 0 {
		t.Fatal("old source retained current labels", status)
	}
	for _, failure := range []string{"incomplete", "missing-scope", "malformed-prefix"} {
		mode = failure
		if err := FetchServiceRangeCache(t.Context(), path, []string{"slack_huddles"}, 24*time.Hour, 16<<20, client); err == nil {
			t.Fatal("incomplete Slack source reported success", failure)
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, original) {
			t.Fatal("bad source replaced prior complete original", failure, err)
		}
	}
	if requests != 4 {
		t.Fatal("source retried unexpectedly", requests)
	}
}
