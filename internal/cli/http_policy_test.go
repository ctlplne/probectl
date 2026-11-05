// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/httpbody"
)

func TestCLIConfiguredBufferedResponseKeepsCompleteLargerBody(t *testing.T) {
	const size = expectedCLIResponseBodyLimit + 1
	for _, tc := range []struct {
		name string
		size int64
		ok   bool
	}{{"exact-configured", size, true}, {"one-over-configured", size + 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &cliRepeatedByteReader{remaining: tc.size, value: 'x'}
			c := cliBodyLimitClient(http.StatusOK, func() io.ReadCloser { return io.NopCloser(reader) })
			c.cfg.MaxResponseBytes = strconv.FormatInt(size, 10)
			err := c.do(http.MethodGet, "/v1/tests", nil, nil)
			if tc.ok && (err != nil || reader.remaining != 0) {
				t.Fatal("configured complete response above32MiB was refused or shortened", err, reader.remaining)
			}
			if !tc.ok && !errors.Is(err, httpbody.ErrTooLarge) {
				t.Fatal("configured response admission did not refuse overflow", err)
			}
		})
	}
}

func TestCLIConfiguredDeadlinesReachEveryHTTPDoor(t *testing.T) {
	for _, mode := range []string{"json", "stream", "raw", "flow-csv"} {
		t.Run(mode, func(t *testing.T) {
			c := cliBodyLimitClient(http.StatusOK, func() io.ReadCloser { return io.NopCloser(strings.NewReader("owned")) })
			c.cfg.RequestTimeout, c.cfg.DownloadTimeout = "2h", "3h"
			c.hc.Transport = cliBodyLimitRoundTripper(func(r *http.Request) (*http.Response, error) {
				target := 2 * time.Hour
				if mode == "stream" || mode == "flow-csv" {
					target = 3 * time.Hour
				}
				deadline, ok := r.Context().Deadline()
				left := time.Until(deadline)
				if !ok || left < target-time.Minute || left > target {
					t.Fatal("configured finite deadline did not reach the actual request", mode, left)
				}
				header := http.Header{"Content-Type": {"text/csv"}, "Content-Disposition": {"attachment; filename=owned.csv"}, "X-Probectl-Sha256": {hex.EncodeToString(crypto.Hash([]byte("owned")))}}
				return &http.Response{StatusCode: http.StatusOK, Header: header, ContentLength: 5, Body: io.NopCloser(strings.NewReader("owned"))}, nil
			})
			var err error
			switch mode {
			case "json":
				err = c.do(http.MethodPost, "/v1/dashboard-reports", nil, nil)
			case "stream":
				err = c.stream(http.MethodGet, "/v1/dashboard-report-artifacts/owned", nil, io.Discard)
			case "raw":
				_, err = c.raw(http.MethodGet, "/v1/incidents/owned/evidence-package", nil, 10)
			case "flow-csv":
				err = c.downloadFlowCSV("/v1/explorer/flow-export/owned", 10, io.Discard)
			}
			if err != nil {
				t.Fatal("configured HTTP profile failed", mode, err)
			}
		})
	}
}

func TestCLIInvalidHTTPProfilesRefuseBeforeNetwork(t *testing.T) {
	for _, cfg := range []Config{{RequestTimeout: "0s"}, {RequestTimeout: "-1s"}, {RequestTimeout: "private-invalid-value"}, {DownloadTimeout: "0s"}, {MaxResponseBytes: "0"}, {MaxResponseBytes: "-1"}, {MaxResponseBytes: "999999999999999999999999"}} {
		c := cliBodyLimitClient(http.StatusOK, func() io.ReadCloser {
			t.Fatal("invalid HTTP admission reached the network")
			return nil
		})
		cfg.BaseURL = c.cfg.BaseURL
		c.cfg = cfg
		for _, call := range []func() error{
			func() error { return c.do(http.MethodGet, "/v1/tests", nil, nil) },
			func() error { return c.stream(http.MethodGet, "/v1/dashboard-reports/owned", nil, io.Discard) },
			func() error { _, err := c.raw(http.MethodGet, "/v1/incidents/owned", nil, 10); return err },
			func() error { return c.downloadFlowCSV("/v1/explorer/flow-export/owned", 10, io.Discard) },
		} {
			if err := call(); err == nil || strings.Contains(err.Error(), "private-invalid-value") {
				t.Fatal("invalid HTTP profile accepted or raw configuration leaked", err)
			}
		}
	}
}

func TestCLIHTTPAdmissionDoesNotBlockOfflineHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"version"}, {"dashboard-report", "generate", "--help"}, {"dashboard-report", "download", "--help"}} {
		var out, errs bytes.Buffer
		env := func(key string) string {
			if strings.HasPrefix(key, "PROBECTL_CLI_") {
				return "invalid-private-setting"
			}
			return ""
		}
		if code := runCLI(args, env, &out, &errs); code != 0 || strings.Contains(out.String()+errs.String(), "invalid-private-setting") {
			t.Fatal("offline command required a usable HTTP profile", args, code)
		}
	}
}

func TestCLIHTTPProfilesFlagsOverrideEnvironment(t *testing.T) {
	const size = expectedCLIResponseBodyLimit + 1
	socket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tests" {
			t.Error("unexpected configured CLI request", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		if _, err := io.WriteString(w, "[]"); err != nil {
			t.Error(err)
			return
		}
		if _, err := io.CopyN(w, &cliRepeatedByteReader{remaining: size - 2, value: ' '}, size-2); err != nil {
			t.Error(err)
		}
	}))
	defer socket.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []bool{false, true} {
		name := "environment"
		if flags {
			name = "flags-override-invalid-environment"
		}
		t.Run(name, func(t *testing.T) {
			env := func(key string) string {
				if flags && strings.HasPrefix(key, "PROBECTL_CLI_") {
					return "invalid-private-setting"
				}
				return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_CA_FILE": ca,
					"PROBECTL_CLI_REQUEST_TIMEOUT": "2m", "PROBECTL_CLI_DOWNLOAD_TIMEOUT": "3m",
					"PROBECTL_CLI_MAX_RESPONSE_BYTES": strconv.FormatInt(size, 10)}[key]
			}
			args := []string{"--json", "api", "GET", "/v1/tests"}
			if flags {
				args = append([]string{"--request-timeout", "2m", "--download-timeout", "3m", "--max-response-bytes", strconv.FormatInt(size, 10)}, args...)
			}
			var out, errs bytes.Buffer
			if code := runCLI(args, env, &out, &errs); code != 0 || strings.TrimSpace(out.String()) != "[]" {
				t.Fatal("finite CLI profile did not admit complete larger JSON", code, errs.String())
			}
		})
	}
}
