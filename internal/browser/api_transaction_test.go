// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
)

func TestAPITransactionRunsTLSLoginThroughLogoutWithPrivateCaptures(t *testing.T) {
	const password = "fixture-only \"password\\with escapes"
	const token = "fixture-only-bearer"
	const requestID = "fixture-only-request-id"
	const exactNumber = json.Number("9007199254740993")
	logout := make(chan struct{}, 1)
	var foreignRequests atomic.Int64
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(foreign.Close)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/login":
			var input struct{ Password string }
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Password != password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-Request-ID", requestID)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "identity": exactNumber})
		case r.Method == http.MethodPatch && r.URL.Path == "/private/item":
			var input struct{ ID json.Number }
			if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Request-ID") != requestID ||
				r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&input) != nil || input.ID != exactNumber {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			time.Sleep(25 * time.Millisecond)
			_, _ = w.Write([]byte(`{"items":[{"state":"pending"},{"state":"ready","message":"match-this"}],"rate":100.0,"large":1e100000000000000000000,"credential":"fixture-only-bearer"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/logout":
			if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Item") != "match-this" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			select {
			case logout <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && r.URL.Path == "/expired":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodPatch && r.URL.Path == "/redirect":
			http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	base := server.URL + "/"
	_, origin, err := resolveAPIEndpoint(base, "")
	if err != nil {
		t.Fatal(err)
	}
	var cleared int
	driver := NewHTTPDriver(WithTargetGuard(canary.NewTargetGuard(true)),
		WithAPITransactionResources(defaultAPITransactionBytes, func(_ context.Context, alias, destination string) ([]byte, func(), error) {
			if alias != "login" || destination != origin {
				return nil, nil, errors.New("fixture password was requested for the wrong destination")
			}
			value := []byte(password)
			return value, func() { clear(value); cleared++ }, nil
		}))
	// Use the fixture's verified trust root. Guard and redirect handling remain
	// in the driver, with all traffic confined to the local HTTPS fixture.
	driver.transport = server.Client().Transport
	group := 1
	script := Script{Name: "API fixture", StartURL: base, Steps: []Step{
		{Name: "login", Action: Request, URL: "/login", APIRequest: &APIRequestStep{Method: http.MethodPost,
			JSONBody: json.RawMessage(`{"password":"${secret.login}"}`)}},
		{Name: "read entry token", Action: Capture, APICapture: &APICaptureStep{Name: "entry_token", JSONPath: "$.token"}},
		{Name: "read request identity", Action: Capture, APICapture: &APICaptureStep{Name: "number", JSONPath: "$.identity"}},
		{Name: "read response header", Action: Capture, APICapture: &APICaptureStep{Name: "request_id", Header: "X-Request-ID"}},
		{Name: "update item", Action: Request, URL: "/private/item", APIRequest: &APIRequestStep{Method: http.MethodPatch,
			Headers:  map[string][]string{"Authorization": {"Bearer ${capture.entry_token}"}, "X-Request-ID": {"${capture.request_id}"}},
			JSONBody: json.RawMessage(`{"id":"${capture.number}"}`)}},
		{Name: "verify item", Action: AssertJSON, APIJSON: &APIJSONAssertion{Path: "$.items[-1:].state", Operator: "eq", Expected: json.RawMessage(`"ready"`)}},
		{Name: "verify latency", Action: AssertLatency, APILatency: &APILatencyAssertion{MaximumMS: 2000}},
		{Name: "verify exact rate", Action: AssertJSON, APIJSON: &APIJSONAssertion{Path: "$.rate", Operator: "eq", Expected: json.RawMessage(`1e2`)}},
		{Name: "verify unexpanded exponent", Action: AssertJSON, APIJSON: &APIJSONAssertion{Path: "$.large", Operator: "eq", Expected: json.RawMessage(`10e99999999999999999999`)}},
		{Name: "capture item", Action: Capture, APICapture: &APICaptureStep{Name: "item", Regex: `"message":"([a-z-]+)"`, Group: &group}},
		{Name: "logout", Action: Request, URL: "/logout", APIRequest: &APIRequestStep{Method: http.MethodDelete,
			Headers: map[string][]string{"Authorization": {"Bearer ${capture.entry_token}"}, "X-Item": {"${capture.item}"}}}},
		{Name: "verify logout", Action: AssertStatus, Status: http.StatusNoContent},
	}}
	check := func(input Script, failAt string) {
		t.Helper()
		out, err := driver.Run(t.Context(), input)
		if err != nil || out.Result.Success != (failAt == "") || len(out.Screenshot) != 0 || out.Result.Screenshot != nil {
			t.Fatalf("unexpected API workflow state %t, error %v", out.Result.Success, err)
		}
		if failAt != "" {
			last := out.Result.Steps[len(out.Result.Steps)-1]
			if last.Name != failAt || last.Success {
				t.Fatalf("expected refusal at %q, got %q", failAt, last.Name)
			}
		}
		encoded, err := json.Marshal(out.Result)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"fixture-only", "match-this", "/private/item", "/login", "/logout"} {
			if strings.Contains(string(encoded), private) {
				t.Fatal("an API result contained private request or response bytes")
			}
		}
	}
	for header, value := range map[string]string{
		"Authorization": "Bearer literal ${capture.entry_token}",
		"X-Api-Key":     "literal${capture.entry_token}",
		"X-Auth-Token":  "${unrecognized.entry_token}",
		"Cookie":        "session=${capture.entry_token}; other=literal",
	} {
		invalid := script
		invalid.Steps = append([]Step(nil), script.Steps...)
		request := *invalid.Steps[4].APIRequest
		request.Headers = map[string][]string{header: {value}}
		invalid.Steps[4].APIRequest = &request
		if err := invalid.Validate(); err == nil {
			t.Fatalf("accepted a literal or malformed credential in %s", header)
		}
	}
	check(script, "")
	select {
	case <-logout:
	default:
		t.Fatal("the workflow did not send the authenticated logout")
	}
	tooSlow := script
	tooSlow.Steps = append([]Step(nil), script.Steps...)
	tooSlow.Steps[6].APILatency = &APILatencyAssertion{MaximumMS: 1}
	check(tooSlow, "verify latency")
	wrongJSON := script
	wrongJSON.Steps = append([]Step(nil), script.Steps...)
	wrongJSON.Steps[5].APIJSON = &APIJSONAssertion{Path: "$.items[*].state", Operator: "eq", Expected: json.RawMessage(`"unready"`)}
	check(wrongJSON, "verify item")
	expired := script
	expired.Steps = append(append([]Step(nil), script.Steps[:5]...), Step{
		Name: "verify active credential", Action: AssertStatus, Status: http.StatusOK,
	})
	expired.Steps[4].URL = "/expired"
	check(expired, "verify active credential")
	for _, target := range []string{foreign.URL, "/redirect"} {
		foreignScript := script
		foreignScript.Steps = append([]Step(nil), script.Steps...)
		foreignScript.Steps[4].URL = target
		check(foreignScript, "update item")
	}
	if foreignRequests.Load() != 0 {
		t.Fatal("a stored or redirected credential crossed the request's origin")
	}
	if cleared != 6 {
		t.Fatalf("expected the secret lease to be released per run, got %d", cleared)
	}
}
