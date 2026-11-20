// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type PublicMRTArchiveKind string

const (
	PublicMRTBaseline PublicMRTArchiveKind = "baseline"
	PublicMRTUpdates  PublicMRTArchiveKind = "updates"
)

type PublicMRTArchiveRef struct {
	Source    string
	Collector string
	Kind      PublicMRTArchiveKind
	At        time.Time
}

type PublicMRTArchiveRequest struct {
	Ref         PublicMRTArchiveRef
	URL         string
	Compression string
	Cadence     time.Duration
	Attribution string
}

var ErrPublicMRTArchive = errors.New("public MRT archive is unavailable or invalid")

// PublicMRTRequest selects one original collector-wide archive from its
// provider, collector and UTC archive clock. Its input has no tenant scope
// or watched prefix and its URL carries no query or credential.
func PublicMRTRequest(ref PublicMRTArchiveRef) (PublicMRTArchiveRequest, error) {
	ref.At = ref.At.UTC()
	if ref.At.IsZero() || ref.At.Year() < 1996 || ref.At.Year() > 9999 ||
		!ref.At.Equal(ref.At.Truncate(time.Minute)) ||
		ref.Kind != PublicMRTBaseline && ref.Kind != PublicMRTUpdates {
		return PublicMRTArchiveRequest{}, ErrPublicMRTArchive
	}
	if ref.Source != "routeviews" {
		return PublicMRTArchiveRequest{}, ErrPublicMRTArchive
	}
	result := PublicMRTArchiveRequest{Ref: ref}
	if err := routeViewsMRTRequest(&result); err != nil {
		return PublicMRTArchiveRequest{}, err
	}
	if !ref.At.Equal(ref.At.Truncate(result.Cadence)) {
		return PublicMRTArchiveRequest{}, ErrPublicMRTArchive
	}
	return result, nil
}

func routeViewsMRTRequest(result *PublicMRTArchiveRequest) error {
	const base = "https://archive.routeviews.org/"
	ref := result.Ref
	var root string
	switch ref.Collector {
	case "route-views2":
		root = base + "bgpdata/"
	case "route-views.eqix", "route-views.linx", "route-views.sg", "route-views.sydney",
		"route-views3", "route-views4", "route-views5", "route-views6":
		root = base + ref.Collector + "/bgpdata/"
	default:
		return ErrPublicMRTArchive
	}
	directory, prefix := "RIBS", "rib"
	result.Cadence = 2 * time.Hour
	if ref.Kind == PublicMRTUpdates {
		directory, prefix = "UPDATES", "updates"
		result.Cadence = 15 * time.Minute
	}
	result.Compression = "bzip2"
	result.Attribution = "University of Oregon RouteViews Project"
	result.URL = root + ref.At.Format("2006.01") + "/" + directory + "/" +
		prefix + "." + ref.At.Format("20060102.1504") + ".bz2"
	return nil
}

// OpenPublicMRTArchive is invoked only by an explicitly enabled archive import.
// It uses the existing guarded TLS client and rejects partial HTTP responses.
// The caller must verify its exact bounded byte count and seal the whole
// compressed stream before making any new coverage point visible.
func openPublicMRTArchive(ctx context.Context, request PublicMRTArchiveRequest, maxBytes int64, client Doer) (io.ReadCloser, int64, error) {
	if client == nil {
		guarded := crypto.GuardedHTTPClient(3 * time.Minute)
		guarded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		client = guarded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, request.URL, nil)
	if err != nil {
		return nil, 0, ErrPublicMRTArchive
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrPublicMRTArchive
	}
	if response.StatusCode != http.StatusOK || response.ContentLength < 1 || response.ContentLength > maxBytes ||
		response.Header.Get("Content-Range") != "" || response.Header.Get("Content-Encoding") != "" {
		response.Body.Close()
		return nil, 0, ErrPublicMRTArchive
	}
	return response.Body, response.ContentLength, nil
}
