// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI is a minimal stand-in for the control-plane /v1 API.
func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tests", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "11111111-1111-1111-1111-111111111111", "name": "edge-dns", "type": "dns", "target": "1.1.1.1", "interval_seconds": 30, "enabled": true},
		}})
	})
	mux.HandleFunc("POST /v1/tests", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["id"] = "22222222-2222-2222-2222-222222222222"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("DELETE /v1/tests/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/tests/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "not_found", "message": "test not found"}})
	})
	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "33333333-3333-3333-3333-333333333333", "name": "agent-1", "hostname": "host-a", "status": "online", "capabilities": []string{"icmp", "tcp"}},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, srv *httptest.Server, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	env := func(k string) string {
		if k == "PROBECTL_API_URL" {
			return srv.URL
		}
		return ""
	}
	code = Run(args, env, &out, &errb)
	return out.String(), errb.String(), code
}

func TestCLITestList(t *testing.T) {
	srv := fakeAPI(t)
	out, _, code := run(t, srv, "test", "list")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "edge-dns") || !strings.Contains(out, "NAME") {
		t.Errorf("table output missing expected rows:\n%s", out)
	}
}

func TestCLITestListJSON(t *testing.T) {
	srv := fakeAPI(t)
	out, _, code := run(t, srv, "--json", "test", "list")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	var tests []Test
	if err := json.Unmarshal([]byte(out), &tests); err != nil {
		t.Fatalf("output is not a JSON array: %v\n%s", err, out)
	}
	if len(tests) != 1 || tests[0].Name != "edge-dns" {
		t.Errorf("decoded = %+v", tests)
	}
}

func TestCLITestCreate(t *testing.T) {
	srv := fakeAPI(t)
	out, errs, code := run(t, srv, "test", "create", "--name", "x", "--type", "icmp", "--target", "1.1.1.1", "--param", "count=5")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(out, "created test") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestCLITestCreateBrowserScriptParam(t *testing.T) {
	const script = `{"name":"login","start_url":"https://app.example/login","steps":[{"action":"goto"},{"action":"assert_status","status":200}]}`
	var seen testRequest
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tests", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		out := Test{
			ID:              "22222222-2222-2222-2222-222222222222",
			Name:            seen.Name,
			Type:            seen.Type,
			Target:          seen.Target,
			IntervalSeconds: seen.IntervalSeconds,
			TimeoutSeconds:  seen.TimeoutSeconds,
			Params:          seen.Params,
			Enabled:         seen.Enabled,
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "--json", "test", "create",
		"--name", "login-browser",
		"--type", "browser",
		"--target", "https://app.example/login",
		"--param", "script="+script)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if seen.Type != "browser" || seen.Target != "https://app.example/login" {
		t.Fatalf("request = %+v", seen)
	}
	if seen.Params["script"] != script {
		t.Fatalf("script param was not preserved: %q", seen.Params["script"])
	}
	var created Test
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("json output: %v\n%s", err, out)
	}
	if created.Params["script"] != script {
		t.Fatalf("json output lost script param: %+v", created)
	}
}

func TestCLITestCreateRequiresFlags(t *testing.T) {
	srv := fakeAPI(t)
	_, errs, code := run(t, srv, "test", "create", "--name", "x")
	if code != 2 || !strings.Contains(errs, "required") {
		t.Errorf("missing --type should fail with usage; code=%d stderr=%s", code, errs)
	}
}

func TestCLIAgentList(t *testing.T) {
	srv := fakeAPI(t)
	out, _, code := run(t, srv, "agent", "list")
	if code != 0 || !strings.Contains(out, "agent-1") || !strings.Contains(out, "icmp,tcp") {
		t.Errorf("agent list output: code=%d\n%s", code, out)
	}
}

func TestCLIErrorStatusExitsNonZero(t *testing.T) {
	srv := fakeAPI(t)
	_, errs, code := run(t, srv, "test", "get", "44444444-4444-4444-4444-444444444444")
	if code != 1 || !strings.Contains(errs, "not found") {
		t.Errorf("a 404 should exit 1 with the server message; code=%d stderr=%s", code, errs)
	}
}

func TestCLIVersionHelpAndUnknown(t *testing.T) {
	srv := fakeAPI(t)
	if out, _, code := run(t, srv, "version"); code != 0 || !strings.Contains(out, "probectl") {
		t.Errorf("version: code=%d out=%s", code, out)
	}
	if out, _, code := run(t, srv, "help"); code != 0 || !strings.Contains(out, "Usage") {
		t.Errorf("help: code=%d out=%s", code, out)
	}
	if _, errs, code := run(t, srv, "bogus"); code != 2 || !strings.Contains(errs, "unknown command") {
		t.Errorf("unknown: code=%d stderr=%s", code, errs)
	}
	if _, _, code := run(t, srv); code != 2 {
		t.Errorf("no args should exit 2, got %d", code)
	}
}
