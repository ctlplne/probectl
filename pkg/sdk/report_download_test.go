// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ctlplne/probectl/pkg/transport"
)

type reportCountingWriter struct {
	expected byte
	bytes    int64
}

func (w *reportCountingWriter) Write(value []byte) (int, error) {
	for _, next := range value {
		if next != w.expected {
			return 0, errors.New("another response entered this artifact")
		}
	}
	w.bytes += int64(len(value))
	return len(value), nil
}

func TestReportArtifactStreamingRetainsCompleteBodiesPastBufferedLimit(t *testing.T) {
	const total = MaxResponseBodyBytes + 65537
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lane := r.Header.Get("X-Probectl-Tenant")
		if (lane != "a" && lane != "b") || r.Header.Get("Authorization") != "Bearer "+lane {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
		chunk := bytes.Repeat([]byte(lane), 32<<10)
		for left := total; left > 0; {
			n := min(left, int64(len(chunk)))
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			left -= n
		}
	}))
	defer server.Close()
	for _, lane := range []string{"a", "b"} {
		client := NewClient(server.URL, WithHTTPClient(server.Client()), WithToken(lane), WithTenant(lane))
		output := &reportCountingWriter{expected: lane[0]}
		got, err := client.DownloadDashboardReportArtifactTo(t.Context(), DownloadDashboardReportArtifactRequest{Id: "same-artifact"}, output, total)
		if err != nil || got != total || output.bytes != total {
			t.Fatal("complete separately authenticated artifact was shortened or mixed", lane, got, err)
		}
		if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), DownloadDashboardReportArtifactRequest{Id: "same-artifact"}, io.Discard, total-1); !errors.Is(err, transport.ErrTooLarge) {
			t.Fatal("insufficient artifact admission silently shortened output", err)
		}
	}
}

func TestReportArtifactStreamingRejectsCancelledAndIncompleteResponses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "20")
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()
	client := NewClient(server.URL, WithHTTPClient(server.Client()))
	if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), DownloadDashboardReportArtifactRequest{Id: "artifact"}, io.Discard, 32); err == nil {
		t.Fatal("short declared artifact became a successful prefix")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.DownloadDashboardReportArtifactTo(ctx, DownloadDashboardReportArtifactRequest{Id: "artifact"}, io.Discard, 32); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled artifact stream continued", err)
	}
}
