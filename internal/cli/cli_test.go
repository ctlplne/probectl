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

type cliString string

func (s cliString) String() string { return string(s) }

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
	return runWithEnv(t, srv, nil, args...)
}

func runWithEnv(t *testing.T, srv *httptest.Server, extra map[string]string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	env := func(k string) string {
		if k == "PROBECTL_API_URL" {
			return srv.URL
		}
		if extra != nil {
			return extra[k]
		}
		return ""
	}
	code = Run(args, env, &out, &errb)
	return out.String(), errb.String(), code
}

func TestCLIHelpLocalizes(t *testing.T) { //nolint:misspell // Spanish locale copy.
	srv := fakeAPI(t)
	out, _, code := runWithEnv(t, srv, map[string]string{"PROBECTL_LOCALE": "es-MX"}, "help")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "Uso:") || !strings.Contains(out, "Comandos:") { //nolint:misspell // Spanish locale copy.
		t.Fatalf("Spanish help missing localized headings:\n%s", out)
	}
	if strings.Contains(out, "Usage:") {
		t.Fatalf("Spanish help leaked English heading:\n%s", out)
	}
}

func TestCLIUnknownCommandLocalizes(t *testing.T) { //nolint:misspell // Spanish locale copy.
	srv := fakeAPI(t)
	_, errs, code := runWithEnv(t, srv, map[string]string{"PROBECTL_LOCALE": "es"}, "wat")
	if code != 2 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(errs, `comando desconocido "wat"`) { //nolint:misspell // Spanish locale copy.
		t.Fatalf("stderr missing localized unknown command:\n%s", errs)
	}
}

func TestCLIAPIErrorLocalizesByStableCode(t *testing.T) {
	srv := fakeAPI(t)
	_, errs, code := runWithEnv(t, srv, map[string]string{"PROBECTL_LOCALE": "es"}, "test", "get", "missing")
	if code != 1 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(errs, "No encontrado (not_found)") {
		t.Fatalf("stderr missing localized API error:\n%s", errs)
	}
	if strings.Contains(errs, "test not found") {
		t.Fatalf("stderr leaked server English fallback:\n%s", errs)
	}
}

func TestCLIAPIErrorIncludesRequestID(t *testing.T) {
	ok, err := formatAPIError([]byte(`{"error":{"code":"unavailable","message":"try later","request_id":"req-123"}}`), "en")
	if !ok {
		t.Fatal("formatAPIError did not recognize API error envelope")
	}
	if got := err.Error(); !strings.Contains(got, "request_id=req-123") || !strings.Contains(got, "unavailable") {
		t.Fatalf("formatted error missing code/request_id: %s", got)
	}
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

func TestCLIRolloutSurfaceHelp(t *testing.T) {
	var out, errs bytes.Buffer
	code := Run([]string{"rollout", "help"}, func(string) string { return "" }, &out, &errs)
	if code != 2 {
		t.Fatalf("rollout help exit = %d, want usage exit 2", code)
	}
	usage := errs.String()
	for _, want := range []string{
		"rollout",
		"fleet rollouts",
		"create",
		"advance <id>",
		"verify <id>",
		"halt <id>",
		"resume <id>",
		"Flags: --query k=v (repeatable), --body JSON, global --json",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("rollout help missing %q:\n%s", want, usage)
		}
	}
}

func TestCLIRolloutSurfaceMapsHumanGatedOps(t *testing.T) {
	spec, ok := surfaceCommands["rollout"]
	if !ok {
		t.Fatal("rollout CLI surface is not registered")
	}
	cases := map[string]apiOp{
		"create":  {Method: http.MethodPost, Path: "/v1/rollouts"},
		"advance": {Method: http.MethodPost, Path: "/v1/rollouts/{id}/advance", ArgName: "id"},
		"verify":  {Method: http.MethodPost, Path: "/v1/rollouts/{id}/verify", ArgName: "id"},
		"halt":    {Method: http.MethodPost, Path: "/v1/rollouts/{id}/halt", ArgName: "id"},
		"resume":  {Method: http.MethodPost, Path: "/v1/rollouts/{id}/resume", ArgName: "id"},
	}
	for name, want := range cases {
		got, ok := spec.Ops[name]
		if !ok {
			t.Fatalf("rollout CLI missing %q", name)
		}
		if got.Method != want.Method || got.Path != want.Path || got.ArgName != want.ArgName {
			t.Fatalf("rollout %s = %+v, want %+v", name, got, want)
		}
	}
}

func TestCLIInventoryViewSurfaceMapsSavedViews(t *testing.T) {
	spec, ok := surfaceCommands["inventory-view"]
	if !ok {
		t.Fatal("inventory-view CLI surface is not registered")
	}
	cases := map[string]apiOp{
		"list":   {Method: http.MethodGet, Path: "/v1/inventory/views"},
		"create": {Method: http.MethodPost, Path: "/v1/inventory/views"},
		"get":    {Method: http.MethodGet, Path: "/v1/inventory/views/{id}", ArgName: "id"},
	}
	for name, want := range cases {
		got, ok := spec.Ops[name]
		if !ok {
			t.Fatalf("inventory-view CLI missing %q", name)
		}
		if got.Method != want.Method || got.Path != want.Path || got.ArgName != want.ArgName {
			t.Fatalf("inventory-view %s = %+v, want %+v", name, got, want)
		}
	}
}

func TestCLICollectorRegister(t *testing.T) {
	var seen map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/collectors/register", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":    "00000000-0000-0000-0000-000000000001",
			"agent_id":     "11111111-1111-4111-8111-111111111111",
			"plane":        "flow",
			"capabilities": []string{"collector", "flow"},
			"config": map[string]any{
				"env":  map[string]string{"PROBECTL_FLOW_TENANT": "00000000-0000-0000-0000-000000000001", "PROBECTL_FLOW_AGENT_ID": "11111111-1111-4111-8111-111111111111"},
				"yaml": map[string]string{"tenant_id": "00000000-0000-0000-0000-000000000001", "agent_id": "11111111-1111-4111-8111-111111111111"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := `{"token":"pjt_token","plane":"flow","hostname":"edge-flow"}`
	out, errs, code := run(t, srv, "--json", "collector", "register", "--body", body)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if seen["token"] != "pjt_token" || seen["plane"] != "flow" || seen["hostname"] != "edge-flow" {
		t.Fatalf("request body = %#v", seen)
	}
	if !strings.Contains(out, `"plane": "flow"`) || !strings.Contains(out, "PROBECTL_FLOW_AGENT_ID") {
		t.Fatalf("collector registration output missing identity/config: %s", out)
	}
}

func TestCLIJourneyCriticalSurfaceCommands(t *testing.T) {
	var seenAsk map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("status"); got != "open" {
			t.Fatalf("incident status query = %q, want open", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "incident-123456789", "title": "WAN loss", "severity": "critical", "description": "edge packet loss"},
		}})
	})
	mux.HandleFunc("GET /v1/alerts/active", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "alert-1", "name": "packet loss", "severity": "warning", "description": "synthetic probe loss"},
		}})
	})
	mux.HandleFunc("GET /v1/topology", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nodes": []map[string]any{{"id": "edge-1", "name": "edge router"}},
			"links": []map[string]any{{"source": "edge-1", "target": "isp-1"}},
		})
	})
	mux.HandleFunc("POST /v1/ai/ask", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seenAsk); err != nil {
			t.Fatalf("decode ask request: %v", err)
		}
		if _, ok := seenAsk["tenant_id"]; ok {
			t.Fatalf("ask request body must not carry tenant_id: %#v", seenAsk)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"answer_id":  "answer-1",
			"root_cause": "ISP loss beyond edge",
			"confidence": "high",
		})
	})
	mux.HandleFunc("GET /v1/remediation/proposals", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "rem-1", "name": "open_ticket", "status": "pending", "description": "requires human approval"},
		}})
	})
	mux.HandleFunc("GET /v1/slos", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "slo-api", "name": "api availability", "status": "healthy", "description": "99.9 target"},
		}})
	})
	mux.HandleFunc("GET /v1/cost/summary", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"summary":  "monthly network cost normal",
			"currency": "USD",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := `{"question":"Why is WAN loss high?","subject":{"incident_id":"incident-123456789","target":"edge-1"}}`
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{name: "incidents", args: []string{"incident", "list", "--query", "status=open"}, want: []string{"WAN loss", "critical"}},
		{name: "alerts", args: []string{"alert", "active"}, want: []string{"packet loss", "warning"}},
		{name: "topology", args: []string{"topology", "show"}, want: []string{"edge router", "isp-1"}},
		{name: "ask", args: []string{"ai", "ask", "--body", body}, want: []string{"ISP loss beyond edge", "high"}},
		{name: "remediation", args: []string{"remediation", "list"}, want: []string{"open_ticket", "pending"}},
		{name: "slo", args: []string{"slo", "list"}, want: []string{"api availability", "healthy"}},
		{name: "cost", args: []string{"cost", "summary"}, want: []string{"monthly network cost normal", "USD"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errs, code := run(t, srv, tc.args...)
			if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, errs)
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Fatalf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
	if seenAsk["question"] != "Why is WAN loss high?" {
		t.Fatalf("ask request body = %#v", seenAsk)
	}
}

func TestCLIBGPSurfaceEvents(t *testing.T) {
	op, ok := surfaceCommands["bgp"].Ops["events"]
	if !ok {
		t.Fatal("missing probectl bgp events surface")
	}
	if op.Method != http.MethodGet || op.Path != "/v1/bgp/events" {
		t.Fatalf("bgp events op = %+v, want GET /v1/bgp/events", op)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bgp/events", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("prefix"); got != "192.0.2.0/24" {
			t.Fatalf("prefix query = %q, want 192.0.2.0/24", got)
		}
		if got := r.URL.Query().Get("asn"); got != "AS64500" {
			t.Fatalf("asn query = %q, want AS64500", got)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("limit query = %q, want 5", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{
				"id":          "incident-bgp-1",
				"incident_id": "incident-bgp-1",
				"kind":        "bgp.possible_hijack",
				"severity":    "critical",
				"title":       "possible hijack 192.0.2.0/24",
				"prefix":      "192.0.2.0/24",
				"occurred_at": "2026-06-30T12:00:00Z",
			},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "bgp", "events",
		"--query", "prefix=192.0.2.0/24",
		"--query", "asn=AS64500",
		"--query", "limit=5")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(out, "incident") || !strings.Contains(out, "possible hijack") || !strings.Contains(out, "critical") {
		t.Fatalf("BGP table output missing expected event:\n%s", out)
	}
}

func TestCLIDeviceSurfaceListAndMetrics(t *testing.T) {
	if got := surfaceCommands["device"].Ops["list"]; got.Method != http.MethodGet || got.Path != "/v1/devices" {
		t.Fatalf("device list op = %+v, want GET /v1/devices", got)
	}
	if got := surfaceCommands["device"].Ops["metrics"]; got.Method != http.MethodGet || got.Path != "/v1/device/metrics" {
		t.Fatalf("device metrics op = %+v, want GET /v1/device/metrics", got)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/devices", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "device:10.0.0.1", "name": "edge-r1", "address": "10.0.0.1"},
		}})
	})
	mux.HandleFunc("GET /v1/device/metrics", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("device"); got != "10.0.0.1" {
			t.Fatalf("device query = %q, want 10.0.0.1", got)
		}
		if got := r.URL.Query().Get("metric"); got != "probectl.device.cpu.utilization" {
			t.Fatalf("metric query = %q, want probectl.device.cpu.utilization", got)
		}
		if got := r.URL.Query().Get("limit"); got != "3" {
			t.Fatalf("limit query = %q, want 3", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"id": "collector-1|10.0.0.1|||probectl_device_cpu_utilization", "device": "10.0.0.1", "name": "probectl_device_cpu_utilization", "summary": "10.0.0.1", "metric": "probectl_device_cpu_utilization", "value": 42, "last_seen": "2026-06-30T12:00:00Z"},
		}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "device", "list")
	if code != 0 {
		t.Fatalf("list exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(out, "edge-r1") || !strings.Contains(out, "device:1") {
		t.Fatalf("device list output missing expected row:\n%s", out)
	}

	out, errs, code = run(t, srv, "device", "metrics",
		"--query", "device=10.0.0.1",
		"--query", "metric=probectl.device.cpu.utilization",
		"--query", "limit=3")
	if code != 0 {
		t.Fatalf("metrics exit = %d, stderr=%s", code, errs)
	}
	if !strings.Contains(out, "10.0.0.1") || !strings.Contains(out, "probectl_device_cpu_utilization") {
		t.Fatalf("device metrics output missing expected row:\n%s", out)
	}
}

func TestCLILifecycleExportStreamsTenantBundle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/lifecycle/export", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("redact"); got != "true" {
			t.Fatalf("redact query = %q, want true", got)
		}
		if got := r.Header.Get("Accept"); got != "application/gzip" {
			t.Fatalf("Accept = %q, want application/gzip", got)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("tenant-bundle-bytes"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "lifecycle", "export", "--redact")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if out != "tenant-bundle-bytes" {
		t.Fatalf("tenant bundle stream not copied to stdout: %q", out)
	}
}

func TestCLILifecycleSubjectExportStreamsBundle(t *testing.T) {
	var seen map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/lifecycle/subjects/export", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "alice") {
			t.Fatalf("subject must not travel in URL: %s", r.URL.String())
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("bundle-bytes"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "lifecycle", "subject-export", "--subject", "alice@example.com", "--redact")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if out != "bundle-bytes" {
		t.Fatalf("bundle stream not copied to stdout: %q", out)
	}
	if seen["subject"] != "alice@example.com" || seen["redact"] != true {
		t.Fatalf("request body = %#v", seen)
	}
}

func TestCLILifecycleSubjectEraseRequiresExactConfirm(t *testing.T) {
	srv := fakeAPI(t)
	_, errs, code := run(t, srv, "lifecycle", "subject-erase", "--subject", "alice@example.com", "--confirm", "alice")
	if code != 2 || !strings.Contains(errs, "--confirm") {
		t.Fatalf("bad confirmation should fail locally: code=%d stderr=%s", code, errs)
	}
}

func TestCLILifecycleSubjectErasePostsBody(t *testing.T) {
	var seen map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/lifecycle/subjects/erase", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "alice") {
			t.Fatalf("subject must not travel in URL: %s", r.URL.String())
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"complete":      true,
			"subject_hash":  "hash",
			"report_sha256": "sha",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	out, errs, code := run(t, srv, "--json", "lifecycle", "subject-erase",
		"--subject", "alice@example.com",
		"--confirm", "alice@example.com",
		"--reason", "dsar")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, errs)
	}
	if seen["subject"] != "alice@example.com" || seen["confirm"] != "alice@example.com" || seen["reason"] != "dsar" {
		t.Fatalf("request body = %#v", seen)
	}
	if !strings.Contains(out, `"complete": true`) || !strings.Contains(out, `"report_sha256": "sha"`) {
		t.Fatalf("subject erasure report not printed: %s", out)
	}
}

func TestCLIErrorStatusExitsNonZero(t *testing.T) {
	srv := fakeAPI(t)
	_, errs, code := run(t, srv, "test", "get", "44444444-4444-4444-4444-444444444444")
	if code != 1 || !strings.Contains(errs, "Not found (not_found)") {
		t.Errorf("a 404 should exit 1 with the localized API code; code=%d stderr=%s", code, errs)
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

func TestCLIGenericOutputHelpers(t *testing.T) {
	var out bytes.Buffer
	if code := printGeneric(&out, nil, false, http.MethodDelete); code != 0 || strings.TrimSpace(out.String()) != "ok" {
		t.Fatalf("delete nil output: code=%d out=%q", code, out.String())
	}

	out.Reset()
	if code := printGeneric(&out, map[string]any{"items": []any{}}, false, http.MethodGet); code != 0 || !strings.Contains(out.String(), "No items.") {
		t.Fatalf("empty items output: code=%d out=%q", code, out.String())
	}

	out.Reset()
	items := []any{
		map[string]any{
			"id":          "123456789abcdef",
			"title":       "edge incident",
			"severity":    "critical",
			"description": cliString("wan loss"),
		},
	}
	if code := printGeneric(&out, map[string]any{"items": items}, false, http.MethodGet); code != 0 {
		t.Fatalf("items output code = %d", code)
	}
	got := out.String()
	for _, want := range []string{"ID", "12345678", "edge incident", "critical", "wan loss"} {
		if !strings.Contains(got, want) {
			t.Fatalf("generic table missing %q:\n%s", want, got)
		}
	}

	if first := firstString(map[string]any{"n": 12}, "n"); first != "" {
		t.Fatalf("non-string firstString = %q, want empty", first)
	}
}

func TestCLISurfaceUsageAndDetailPrinters(t *testing.T) {
	var out bytes.Buffer
	printSurfaceUsage(&out, surfaceCommand{
		Name:    "incidents",
		Summary: "incident operations",
		Ops: map[string]apiOp{
			"show": {Method: http.MethodGet, Path: "/v1/incidents/{id}", ArgName: "id"},
			"list": {Method: http.MethodGet, Path: "/v1/incidents"},
		},
	})
	usage := out.String()
	for _, want := range []string{"incidents", "incident operations", "list", "show <id>", "--query k=v"} {
		if !strings.Contains(usage, want) {
			t.Fatalf("surface usage missing %q:\n%s", want, usage)
		}
	}

	out.Reset()
	printTest(&out, Test{
		ID:              "test-1",
		Name:            "dns",
		Type:            "dns",
		Target:          "one.one.one.one",
		IntervalSeconds: 30,
		TimeoutSeconds:  5,
		Enabled:         true,
		Params:          map[string]string{"resolver": "1.1.1.1"},
	})
	if got := out.String(); !strings.Contains(got, "params:") || !strings.Contains(got, "resolver=1.1.1.1") {
		t.Fatalf("test detail missing params:\n%s", got)
	}

	out.Reset()
	printAgent(&out, Agent{
		ID:           "agent-1",
		Name:         "edge",
		Hostname:     "edge-01",
		AgentVersion: "0.4.0",
		Status:       "online",
		Capabilities: []string{"icmp", "dns"},
	})
	if got := out.String(); !strings.Contains(got, "agent_version: 0.4.0") || !strings.Contains(got, "icmp, dns") {
		t.Fatalf("agent detail output wrong:\n%s", got)
	}
}
