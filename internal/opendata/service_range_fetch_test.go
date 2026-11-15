// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type serviceRangeDoerFunc func(*http.Request) (*http.Response, error)

func (f serviceRangeDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// Actual HTTPS download and durable local replacement. Publisher contents are
// QA-authored golden values; no public feed or tenant telemetry leaves the test.
func TestPublishedServiceRangeBulkFetchKeepsOriginalsTLSAndAtomicFailure(t *testing.T) {
	at := time.Now().UTC().Add(-time.Hour)
	aws := fmt.Sprintf("{\n  \"syncToken\": \"qa-aws-original\", \"createDate\": %q,\n  \"prefixes\": [{\"ip_prefix\":\"192.0.2.0/24\",\"service\":\"S3\",\"region\":\"us-east-1\"}],\n  \"ipv6_prefixes\": []\n}", at.Format("2006-01-02-15-04-05"))
	google := fmt.Sprintf(`{"syncToken":"qa-google-original","creationTime":%q,"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`, at.Format(time.RFC3339Nano))
	cloud := fmt.Sprintf(`{"syncToken":"qa-cloud-original","creationTime":%q,"prefixes":[{"ipv6Prefix":"2001:db8::/32","service":"Google Cloud","scope":"europe-west1"}]}`, at.Format(time.RFC3339Nano))
	var mu sync.Mutex
	mode, requests := "ok", 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Probectl-Tenant") != "" || len(r.Cookies()) != 0 {
			t.Error("bulk request carried private selectors or credentials")
		}
		if mode == "down" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if mode == "malformed" && r.URL.Path == "/ipranges/goog.json" {
			_, _ = w.Write([]byte(`{"prefixes":[]}`))
			return
		}
		if mode == "aged" {
			w.Header().Set("Age", "7200")
		}
		if mode == "bad age" {
			w.Header().Set("Age", "-1")
		}
		switch r.URL.Path {
		case "/ip-ranges.json":
			_, _ = w.Write([]byte(aws))
		case "/ipranges/goog.json":
			_, _ = w.Write([]byte(google))
		case "/ipranges/cloud.json":
			_, _ = w.Write([]byte(cloud))
		default:
			t.Error("unexpected publisher path", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || req.URL.RawQuery != "" || (req.URL.Host != "ip-ranges.amazonaws.com" && req.URL.Host != "www.gstatic.com") {
			t.Fatal("bulk fetch escaped fixed public endpoints", req.URL)
		}
		forward := req.Clone(req.Context())
		address := *req.URL
		address.Scheme, address.Host = base.Scheme, base.Host
		forward.URL = &address
		forward.Host = ""
		return server.Client().Do(forward)
	})
	path := filepath.Join(t.TempDir(), "ranges.json")
	publishers := []string{"aws", "google", "google_cloud"}
	if err := FetchServiceRangeCache(t.Context(), path, publishers, 24*time.Hour, 16<<20, client); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(original, []byte(aws)) {
		t.Fatal("bulk cache rewrote or lost original vendor JSON", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("cache is not owner-only", err)
	}
	source, err := LoadServiceRanges(t.Context(), path, 24*time.Hour, 16<<20, time.Now())
	if err != nil {
		t.Fatal("durable cache cannot be imported offline", err)
	}
	status := source.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true)[0]
	if status.Digest != hex.EncodeToString(crypto.Hash([]byte(aws))) || status.Status != "matched" || len(status.Matches) != 1 || status.Matches[0].Service != "S3" {
		t.Fatal("cache lost original digest or complete attribution", status)
	}
	for _, failure := range []string{"malformed", "down", "bad age"} {
		mu.Lock()
		mode = failure
		mu.Unlock()
		if err := FetchServiceRangeCache(t.Context(), path, publishers, 24*time.Hour, 16<<20, client); err == nil {
			t.Fatal("failed source replaced the complete cache", failure)
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, original) {
			t.Fatal("failed bulk refresh renewed or changed the prior cache", failure, err)
		}
	}
	mu.Lock()
	mode = "ok"
	before := requests
	mu.Unlock()
	if err := FetchServiceRangeCache(t.Context(), path, []string{"aws", "unapproved"}, 24*time.Hour, 16<<20, client); err == nil {
		t.Fatal("unapproved source accepted")
	}
	mu.Lock()
	after := requests
	mu.Unlock()
	if before != after {
		t.Fatal("invalid publisher selection performed network IO")
	}
	if err := FetchServiceRangeCache(t.Context(), path, publishers, 24*time.Hour, 4096, client); !errors.Is(err, ErrServiceRangeBudget) {
		t.Fatal("bounded download admitted a partial body", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("over-budget source changed prior cache", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := FetchServiceRangeCache(ctx, path, publishers, 24*time.Hour, 16<<20, client); err == nil {
		t.Fatal("canceled operation changed cache")
	}
	// Without trusting the issued test CA, HTTPS must fail and retain the cache.
	untrusted := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		forward := req.Clone(req.Context())
		address := *req.URL
		address.Scheme, address.Host = base.Scheme, base.Host
		forward.URL = &address
		forward.Host = ""
		return crypto.HardenedHTTPClient(time.Second).Do(forward)
	})
	if err := FetchServiceRangeCache(t.Context(), path, publishers, 24*time.Hour, 16<<20, untrusted); err == nil {
		t.Fatal("untrusted TLS source was accepted")
	}
	current, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatal("untrusted TLS changed cache", err)
	}
	if err := writeServiceRangeCache(ctx, path, []byte("partial")); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled publication reached cache writer", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "ranges.json" {
		t.Fatal("temporary cache leaked after failure", entries, err)
	}
}

func TestPublishedServiceRangeBulkFetchPreservesHTTPAge(t *testing.T) {
	at := time.Now().UTC().Add(-4 * time.Hour)
	raw := fmt.Sprintf(`{"syncToken":"qa-aged","createDate":%q,"prefixes":[],"ipv6_prefixes":[]}`, at.Format("2006-01-02-15-04-05"))
	client := serviceRangeDoerFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Age": []string{"7200"}}, Body: io.NopCloser(strings.NewReader(raw))}, nil
	})
	path := filepath.Join(t.TempDir(), "ranges.json")
	if err := FetchServiceRangeCache(t.Context(), path, []string{"aws"}, time.Hour, 16<<20, client); err != nil {
		t.Fatal(err)
	}
	source, err := LoadServiceRanges(t.Context(), path, time.Hour, 16<<20, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status := source.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true)[0]
	if status.Status != "stale" || len(status.Matches) != 0 || time.Since(status.FetchedAt) < 2*time.Hour {
		t.Fatal("HTTP cache hit renewed source freshness", status)
	}
}
