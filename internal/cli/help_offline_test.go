// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// openAPITestRequestTypeEnum reads the authoritative probe-type list straight
// from the control plane's OpenAPI document, so the help assertion is bound to
// the schema the server validates against rather than to a copy in the test.
func openAPITestRequestTypeEnum(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash("../control/openapi.json"))
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas struct {
				TestRequest struct {
					Properties struct {
						Type struct {
							Enum []string `json:"enum"`
						} `json:"type"`
					} `json:"properties"`
				} `json:"TestRequest"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	enum := doc.Components.Schemas.TestRequest.Properties.Type.Enum
	if len(enum) == 0 {
		t.Fatal("openapi.json TestRequest.type enum is empty")
	}
	return enum
}

// TestCLIHelpProbeTypesMatchOpenAPI proves the `--type` help in every locale
// renders exactly the OpenAPI TestRequest.type enum, in order. INV-07: the
// hand-maintained list had drifted (browser and voice were missing), so an
// operator reading --help could not discover two shipped probe types.
func TestCLIHelpProbeTypesMatchOpenAPI(t *testing.T) { //nolint:misspell // Spanish locale copy.
	want := strings.Join(openAPITestRequestTypeEnum(t), "|")
	for _, locale := range []string{"en", "es"} {
		var out, errb bytes.Buffer
		env := func(k string) string {
			if k == "PROBECTL_LOCALE" {
				return locale
			}
			return ""
		}
		code := runCLI([]string{"help"}, env, &out, &errb)
		if code != 0 {
			t.Fatalf("[%s] help exit = %d, stderr=%s", locale, code, errb.String())
		}
		if !strings.Contains(out.String(), want) {
			t.Fatalf("[%s] --type help does not render the OpenAPI enum %q:\n%s", locale, want, out.String())
		}
	}
}

// TestCLISubcommandHelpIsOffline proves that asking a representative set of
// sub-commands for help never dials the control plane (INV-07). A sub-command
// that treated -h as a positional id used to send a tenant-scoped request for
// "/-h"; one that ignored -h dialed anyway. Every request to this server is a
// failure of the test, so it both records and 500s on every hit.
func TestCLISubcommandHelpIsOffline(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// A mix of explicit direct-dial handlers (test/agent get), stream handlers
	// (dashboard-report download), the generic surface executor (rollout/incident
	// get), and the raw api passthrough.
	commands := [][]string{
		{"test", "get"},
		{"agent", "get"},
		{"rollout", "get"},
		{"incident", "get"},
		{"dashboard-report", "download"},
		{"api", "GET", "/v1/tests"},
	}
	env := func(k string) string {
		if k == "PROBECTL_API_URL" {
			return srv.URL
		}
		return ""
	}
	for _, base := range commands {
		for _, helpFlag := range []string{"-h", "--help"} {
			args := append(append([]string{}, base...), helpFlag)
			before := atomic.LoadInt32(&hits)
			var out, errb bytes.Buffer
			code := runCLI(args, env, &out, &errb)
			if dialed := atomic.LoadInt32(&hits) - before; dialed != 0 {
				t.Errorf("%v dialed the control plane %d time(s); CLI help must be offline", args, dialed)
			}
			if code == 1 {
				t.Errorf("%v exit = 1 (request error); help must succeed without a request", args)
			}
			if !strings.Contains(strings.ToLower(out.String()), "usage") {
				t.Errorf("%v printed no usage on stdout:\nstdout=%q\nstderr=%q", args, out.String(), errb.String())
			}
		}
	}
}
