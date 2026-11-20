// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPublicMRTArchiveUsesOnlySourceCollectorAndClock(t *testing.T) {
	ref := PublicMRTArchiveRef{Source: "routeviews", Collector: "route-views.eqix", Kind: PublicMRTBaseline,
		At: time.Date(2026, 10, 1, 5, 30, 0, 0, time.FixedZone("+05:30", 19800))}
	got, err := PublicMRTRequest(ref)
	if err != nil || got.URL != "https://archive.routeviews.org/route-views.eqix/bgpdata/2026.10/RIBS/rib.20261001.0000.bz2" ||
		got.Ref.At.Location() != time.UTC || got.Cadence != 2*time.Hour || got.Attribution == "" {
		t.Fatal("baseline URL or public source metadata differs", got, err)
	}
	ref.Kind = PublicMRTUpdates
	ref.Collector = "route-views2"
	ref.At = ref.At.Add(15 * time.Minute)
	got, err = PublicMRTRequest(ref)
	if err != nil || got.URL != "https://archive.routeviews.org/bgpdata/2026.10/UPDATES/updates.20261001.0015.bz2" ||
		got.Cadence != 15*time.Minute {
		t.Fatal("update URL or cadence differs", got, err)
	}
	for _, invalid := range []PublicMRTArchiveRef{
		{Source: "https://private.example", Collector: ref.Collector, Kind: ref.Kind, At: ref.At},
		{Source: ref.Source, Collector: "route-views2/../198.51.100.0?prefix=", Kind: ref.Kind, At: ref.At},
		{Source: ref.Source, Collector: ref.Collector, Kind: ref.Kind, At: ref.At.Add(time.Minute)},
	} {
		if request, err := PublicMRTRequest(invalid); !errors.Is(err, ErrPublicMRTArchive) || request.URL != "" {
			t.Fatal("invalid source had an egress URL", request, err)
		}
	}
}

func TestPublicMRTCacheReusesCompleteArchiveAndRefusesShortDownload(t *testing.T) {
	ref := PublicMRTArchiveRef{Source: "routeviews", Collector: "route-views.eqix", Kind: PublicMRTUpdates,
		At: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	status, expected, requests := http.StatusOK, int64(3), 0
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "archive.routeviews.org" ||
			req.URL.RawQuery != "" || req.URL.User != nil || req.URL.Fragment != "" || req.Body != nil ||
			req.Header.Get("Accept-Encoding") != "identity" || len(req.Header) != 1 {
			t.Fatal("archive request carried a private selector, credential or payload")
		}
		return &http.Response{StatusCode: status, ContentLength: expected, Body: io.NopCloser(strings.NewReader("abc"))}, nil
	})
	cache, err := NewPublicMRTCache(t.TempDir(), 9, client)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := cache.Fetch(t.Context(), ref)
	if err != nil || receipt.Bytes != 3 || receipt.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("original source was not captured exactly", receipt, err)
	}
	second, err := cache.Fetch(t.Context(), ref)
	if err != nil || second != receipt || requests != 1 {
		t.Fatal("immutable archive was downloaded or dated again", second, err, requests)
	}
	readback, original, err := cache.Open(t.Context(), ref)
	if err != nil || readback != receipt {
		t.Fatal("archive cannot be reused offline", readback, err)
	}
	raw, err := io.ReadAll(original)
	original.Close()
	if err != nil || string(raw) != "abc" || requests != 1 {
		t.Fatal("offline read changed original bytes or requested upstream", err, requests)
	}
	ref.At = ref.At.Add(15 * time.Minute)
	for _, malformed := range []struct {
		code int
		size int64
	}{{http.StatusOK, 4}, {http.StatusOK, 2}, {http.StatusPartialContent, 3}, {http.StatusOK, 10}} {
		status, expected = malformed.code, malformed.size
		if got, err := cache.Fetch(t.Context(), ref); !errors.Is(err, ErrPublicMRTArchive) || got != (PublicMRTReceipt{}) {
			t.Fatal("a non-complete source acquired a receipt", got, err)
		}
		if got, file, err := cache.Open(t.Context(), ref); !errors.Is(err, os.ErrNotExist) || file != nil || got != (PublicMRTReceipt{}) {
			t.Fatal("a non-complete source became readable", got, err)
		}
	}
}
