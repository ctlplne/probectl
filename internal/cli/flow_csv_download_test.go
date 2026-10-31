// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestFlowCSVDownloadVerifiesBeforeEmittingAndHonorsBudget(t *testing.T) {
	for _, mode := range []string{"valid", "bad digest", "truncated", "over budget", "missing digest"} {
		t.Run(mode, func(t *testing.T) {
			body := []byte("record_type,bytes:total\ndetail,18446744073709551616001\n")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Probectl-Tenant") != "own" {
					t.Error("missing tenant header")
				}
				w.Header().Set("Content-Type", "text/csv")
				w.Header().Set("Content-Disposition", `attachment; filename="probectl.csv"`)
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				digest := hex.EncodeToString(crypto.Hash(body))
				if mode == "bad digest" {
					digest = strings.Repeat("0", 64)
				}
				if mode != "missing digest" {
					w.Header().Set("X-Probectl-SHA256", digest)
				}
				if mode == "truncated" {
					_, _ = w.Write(body[:10])
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client := &client{cfg: Config{BaseURL: server.URL, Tenant: "own"}, hc: server.Client()}
			var output bytes.Buffer
			budget := int64(1024)
			if mode == "over budget" {
				budget = 1
			}
			err := client.downloadFlowCSV("/v1/explorer/flow-snapshots/id/csv", budget, &output)
			if mode == "valid" {
				if err != nil || !bytes.Equal(output.Bytes(), body) {
					t.Fatalf("valid CSV failed: %v", err)
				}
			} else if err == nil || output.Len() != 0 {
				t.Fatalf("unverified/partial output emitted: %d %v", output.Len(), err)
			}
		})
	}
}

type repeatedCSVReader struct{ remaining int64 }

func (r *repeatedCSVReader) Read(body []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int(min(int64(len(body)), r.remaining))
	for i := 0; i < n; i++ {
		body[i] = 'x'
	}
	r.remaining -= int64(n)
	return n, nil
}

type countedCSVOutput struct {
	n int64
}

func (w *countedCSVOutput) Write(body []byte) (int, error) {
	w.n += int64(len(body))
	return len(body), nil
}

func TestFlowCSVDownloadBeyondJSONLimitStreamsWithBoundedMemory(t *testing.T) {
	size := maxBufferedResponseBody + 65536
	digest, err := crypto.HashReader(&repeatedCSVReader{size})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="probectl.csv"`)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("X-Probectl-SHA256", hex.EncodeToString(digest))
		_, _ = io.Copy(w, &repeatedCSVReader{size})
	}))
	defer server.Close()
	client := &client{cfg: Config{BaseURL: server.URL}, hc: server.Client()}
	output := &countedCSVOutput{}
	if err := client.downloadFlowCSV("/v1/explorer/flow-snapshots/id/csv", size, output); err != nil || output.n != size {
		t.Fatalf("large CSV %d/%d: %v", output.n, size, err)
	}
}
