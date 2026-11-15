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
	"fmt"
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

func TestServiceRangeCachePreservesCompleteOriginalBytesAcrossRestart(t *testing.T) {
	at := time.Now().UTC()
	body := fmt.Sprintf("\r\n  {\n  \"syncToken\": \"original-version\", \"createDate\": %q,\n  \"prefixes\": [{\"ip_prefix\":\"192.0.2.0/24\",\"service\":\"S3\",\"region\":\"us-east-1\"}],\n  \"ipv6_prefixes\": []\n}\r\n\t", at.Add(-4*time.Hour).Format("2006-01-02-15-04-05"))
	client := serviceRangeDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Age": []string{"7200"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	path := filepath.Join(t.TempDir(), "ranges.json")
	if err := FetchServiceRangeCache(t.Context(), path, []string{"aws"}, 24*time.Hour, 16<<20, client); err != nil {
		t.Fatal(err)
	}
	source, err := LoadServiceRanges(t.Context(), path, 24*time.Hour, 16<<20, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status := source.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true)[0]
	if status.Digest != hex.EncodeToString(crypto.Hash([]byte(body))) {
		t.Fatal("cache digest does not identify the complete original HTTP body")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope serviceRangeEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Version != 2 || len(envelope.Sources) != 1 || !bytes.Equal(envelope.Sources[0].Data, []byte(body)) {
		t.Fatal("offline cache cannot reconstruct original whitespace and bytes", err)
	}
	copyPath := filepath.Join(t.TempDir(), "offline-copy.json")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadServiceRanges(t.Context(), copyPath, 24*time.Hour, 16<<20, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	copyStatus := restarted.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true)[0]
	if copyStatus.Digest != status.Digest || !copyStatus.FetchedAt.Equal(status.FetchedAt) || !copyStatus.ValidUntil.Equal(status.ValidUntil) {
		t.Fatal("offline copy/restart changed original bytes or renewed age", copyStatus)
	}
	// Existing version-one operator files remain readable. Their data is the
	// embedded JSON value; whitespace outside that value was never retained.
	legacy := fmt.Sprintf(`{"version":1,"sources":[{"publisher":"aws","fetched_at":%q,"complete":true,"data":%s}]}`, envelope.Sources[0].FetchedAt.Format(time.RFC3339Nano), body)
	previous, err := LoadServiceRanges(t.Context(), serviceRangeFile(t, legacy), 24*time.Hour, 16<<20, time.Now())
	if err != nil || previous == nil || previous.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true)[0].Status != "matched" {
		t.Fatal("legacy complete input stopped working", err)
	}
	// Duplicate keys hidden inside a quoted source are still untrusted JSON,
	// and a document must use the encoding its envelope declares.
	for _, invalid := range []string{
		strings.Replace(string(raw), `"version":2`, `"version":1`, 1),
		strings.Replace(legacy, `"version":1`, `"version":2`, 1),
		strings.Replace(string(raw), `\"syncToken\": \"original-version\"`, `\"syncToken\": \"one\",\"syncToken\": \"two\"`, 1),
	} {
		value, err := LoadServiceRanges(t.Context(), serviceRangeFile(t, invalid), 24*time.Hour, 16<<20, time.Now())
		if err == nil || value != nil {
			t.Fatal("quoted-source duplicate keys or mismatched document encoding admitted")
		}
	}
}
