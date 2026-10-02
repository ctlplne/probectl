// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
)

// AUTHZ-16: a tenant controls its alert-channel webhook URLs, which drive an
// outbound request from the control plane. Without a deny-by-default guard an
// operator can point the alert create/test surface at a private/link-local/
// metadata/loopback host (or a non-https scheme) and read the control plane's
// reachability oracle — the control plane becomes an SSRF proxy. The guard must
// refuse such URLs at BOTH create and test time, before any socket, with ONE
// identical response for every rejection reason so the surface leaks nothing.

// The exact rejection the guard must return (same code + message everywhere).
const (
	wantWebhookRejectCode    = "validation"
	wantWebhookRejectMessage = "alert: channel webhook url must be an https endpoint on a public, non-internal host"
)

// acceptingDoer is an alert webhook client that reports success WITHOUT opening
// a socket — it stands in for a deployment-injected webhook client. On
// vulnerable code it lets a tenant-supplied private/metadata URL "deliver"
// (HTTP 202), which is the SSRF success oracle; the fix must refuse such URLs
// before this client is ever reached, so .called must stay false.
type acceptingDoer struct{ called bool }

func (d *acceptingDoer) Do(*http.Request) (*http.Response, error) {
	d.called = true
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

func postAlertChannelTest(srv *Server, channelJSON string) *httptest.ResponseRecorder {
	body := `{"rule_name":"ssrf-probe","metric":"probectl_test_delivery","channel":` + channelJSON + `}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/test-channel", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func postAlertCreate(srv *Server, channelJSON string) *httptest.ResponseRecorder {
	body := `{"name":"ssrf-probe","metric":"probectl_test_delivery","type":"threshold","comparison":"gt","threshold":1,"channels":[` + channelJSON + `]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) (code, message string) {
	t.Helper()
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope %q: %v", rec.Body.String(), err)
	}
	return env.Error.Code, env.Error.Message
}

func TestAlertChannelWebhookSSRFGuardedAtCreateAndTest(t *testing.T) {
	// Every one of these is a distinct rejection reason (metadata, RFC1918,
	// loopback v4/v6, a decimal-smuggled 127.0.0.1, and a non-https scheme). The
	// guard must collapse them all to ONE identical response — no success oracle.
	badURLs := []string{
		"https://169.254.169.254/hook", // cloud metadata (link-local)
		"https://10.1.2.3/hook",        // RFC1918 private
		"https://127.0.0.1/hook",       // loopback
		"https://[::1]/hook",           // IPv6 loopback
		"https://2130706433/hook",      // decimal-smuggled 127.0.0.1
		"http://example.com/hook",      // plaintext scheme to a public host
	}

	for _, u := range badURLs {
		channelJSON := `{"type":"webhook","url":"` + u + `","secret":"sign-me"}`

		// --- test-channel surface -------------------------------------------
		doer := &acceptingDoer{}
		srv := testServer(fakePinger{}).WithAlertChannelDeps(alert.ChannelDeps{HTTPClient: doer})
		testRec := postAlertChannelTest(srv, channelJSON)
		if testRec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("test-channel %s = %d, want 422 (refused before any delivery); body=%s",
				u, testRec.Code, testRec.Body.String())
		}
		if doer.called {
			t.Fatalf("test-channel %s reached the webhook client — SSRF request was issued", u)
		}
		if strings.Contains(testRec.Body.String(), "sign-me") {
			t.Fatalf("test-channel %s leaked the channel secret: %s", u, testRec.Body.String())
		}
		testCode, testMsg := decodeAPIError(t, testRec)
		if testCode != wantWebhookRejectCode || testMsg != wantWebhookRejectMessage {
			t.Fatalf("test-channel %s error = {%q,%q}, want {%q,%q} (reason must not leak)",
				u, testCode, testMsg, wantWebhookRejectCode, wantWebhookRejectMessage)
		}

		// --- create surface: identical rejection, nothing stored -----------
		createRec := postAlertCreate(srv, channelJSON)
		if createRec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("create %s = %d, want 422 (refused before the store); body=%s",
				u, createRec.Code, createRec.Body.String())
		}
		createCode, createMsg := decodeAPIError(t, createRec)
		if createCode != testCode || createMsg != testMsg {
			t.Fatalf("create vs test response differ for %s: create {%q,%q} test {%q,%q} — surfaces are distinguishable",
				u, createCode, createMsg, testCode, testMsg)
		}
	}
}

// A well-formed public https webhook must still pass the guard and deliver, so
// the guard cannot be a blunt instrument that breaks legitimate channels.
func TestAlertChannelWebhookPublicHTTPSPassesGuard(t *testing.T) {
	doer := &acceptingDoer{}
	srv := testServer(fakePinger{}).WithAlertChannelDeps(alert.ChannelDeps{HTTPClient: doer})
	rec := postAlertChannelTest(srv, `{"type":"webhook","url":"https://hooks.example.com/alert","secret":"sign-me"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("public https webhook test = %d, want 202 (guard must not over-block); body=%s",
			rec.Code, rec.Body.String())
	}
	if !doer.called {
		t.Fatal("public https webhook test did not reach the delivery client")
	}
}
