// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

type downloadFailureLifecycle struct {
	fakeTenantLifecycle
	body    []byte
	failure error
}

func (f *downloadFailureLifecycle) ExportRedacted(_ context.Context, _ string, w io.Writer, _ bool) (tenantlife.Manifest, error) {
	_, err := w.Write(f.body)
	if err != nil {
		return tenantlife.Manifest{}, err
	}
	return tenantlife.Manifest{}, f.failure
}
func (f *downloadFailureLifecycle) ExportSubject(_ context.Context, _, _ string, w io.Writer, _ bool) (tenantlife.SubjectManifest, error) {
	_, err := w.Write(f.body)
	if err != nil {
		return tenantlife.SubjectManifest{}, err
	}
	return tenantlife.SubjectManifest{}, f.failure
}

func TestLifecycleExportHTTPFailureNeverCompletesDownload(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	if _, err := gz.Write([]byte("owned complete fixture")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, http2 := range []bool{false, true} {
		protocol := "http1"
		if http2 {
			protocol = "http2"
		}
		t.Run(protocol, func(t *testing.T) {
			for _, route := range []struct{ name, method, path, request string }{
				{"tenant", http.MethodGet, "/v1/lifecycle/export", ""},
				{"subject", http.MethodPost, "/v1/lifecycle/subjects/export", `{"subject":"192.0.2.1"}`},
			} {
				t.Run(route.name, func(t *testing.T) {
					for _, tc := range []struct {
						name    string
						body    []byte
						failure error
						want    int
					}{
						{"before-output", nil, apierror.Forbidden("privacy authority changed"), http.StatusForbidden},
						{"dependency-before-output", nil, errors.New("owned private dependency detail"), http.StatusInternalServerError},
						{"during-output", bytes.Repeat([]byte("owned interrupted body"), 8192), errors.New("owned midstream refusal"), 0},
						{"after-complete-gzip", archive.Bytes(), errors.New("owned final audit refusal"), 0},
						{"success", archive.Bytes(), nil, http.StatusOK},
					} {
						t.Run(tc.name, func(t *testing.T) {
							srv := testServer(fakePinger{})
							srv.tenantLife = &downloadFailureLifecycle{body: tc.body, failure: tc.failure}
							listener := httptest.NewUnstartedServer(srv.Handler())
							listener.EnableHTTP2 = http2
							listener.StartTLS()
							defer listener.Close()
							request, err := http.NewRequestWithContext(t.Context(), route.method, listener.URL+route.path, strings.NewReader(route.request))
							if err != nil {
								t.Fatal(err)
							}
							if route.request != "" {
								request.Header.Set("Content-Type", "application/json")
							}
							response, err := listener.Client().Do(request)
							if err != nil {
								if tc.want != 0 {
									t.Fatal("expected an ordinary HTTP response", err)
								}
								return
							}
							defer response.Body.Close()
							expectedMajor := 1
							if http2 {
								expectedMajor = 2
							}
							if response.ProtoMajor != expectedMajor {
								t.Fatal("required protocol was not exercised", response.Proto)
							}
							body, readErr := io.ReadAll(response.Body)
							if tc.want == 0 {
								if readErr == nil {
									t.Fatal("failed export completed with a clean transport EOF", response.StatusCode, len(body))
								}
								if bytes.Contains(body, []byte(`"error":`)) {
									t.Fatal("JSON error was appended to an attachment")
								}
								return
							}
							if readErr != nil || response.StatusCode != tc.want {
								t.Fatal("unexpected response", response.StatusCode, readErr, string(body))
							}
							if tc.failure != nil {
								if response.Header.Get("Content-Disposition") != "" || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
									t.Fatal("pre-output failure became a download", response.Header)
								}
								if bytes.Contains(body, []byte("owned private dependency detail")) {
									t.Fatal("dependency detail leaked")
								}
							} else if response.Header.Get("Content-Type") != "application/gzip" || !strings.Contains(response.Header.Get("Content-Disposition"), "probectl-"+route.name+"-export.tar.gz") || !bytes.Equal(body, tc.body) {
								t.Fatal("successful attachment changed", response.Header, len(body))
							}
						})
					}
				})
			}
		})
	}
}

func TestLifecycleExportAbortPreservesUnexpectedPanicRecovery(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/lifecycle/export", nil)
	recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("owned unexpected panic") })).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), `"internal"`) {
		t.Fatal("unexpected panic no longer maps to stable 500", recorder.Code)
	}
}
