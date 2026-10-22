// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testPolicy = "probectl-agent-image-integrity"
	testSum    = "sum-of-the-rendered-spec"
	ivpolPath  = "/apis/policies.kyverno.io/v1/imagevalidatingpolicies/" + testPolicy
	vwcPath    = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/" + DefaultKyvernoWebhookConfiguration
)

const readyPolicy = `{"metadata":{"annotations":{"probectl.dev/policy-sha256":"sum-of-the-rendered-spec"}},
 "status":{"conditionStatus":{"ready":true,"conditions":[{"type":"WebhookConfigured","status":"True"},{"type":"RBACPermissionsChecked","status":"True"}]}}}`

const servingWebhooks = `{"webhooks":[
 {"name":"ivpol.validate.kyverno.svc-ignore","failurePolicy":"Ignore","clientConfig":{"service":{"path":"/ivpol/validate/other"}}},
 {"name":"ivpol.validate.kyverno.svc-fail","failurePolicy":"Fail","clientConfig":{"service":{"path":"/ivpol/validate/aaa/probectl-agent-image-integrity"}}}]}`

// TestAdmissionCheckReportsEveryWayVerificationStops is the unit half of the
// RTO-12 vanished-webhook detection: each state in which Kyverno no longer
// verifies the agent image (policy gone, stale, not Ready, webhook
// configuration deleted by a Kyverno scaled to zero, only an Ignore webhook,
// a webhook for another policy) is reported, an unreadable state is an error
// (fail closed), and the healthy state reports nothing. The live half is leg
// W1 of scripts/kyverno_admission_smoke.sh.
func TestAdmissionCheckReportsEveryWayVerificationStops(t *testing.T) {
	for _, tc := range []struct {
		name     string
		objects  map[string]string // path -> body; absent = 404
		status   int               // when set, every request answers this status
		wantErr  bool
		wantProb []string
	}{
		{name: "verifying", objects: map[string]string{ivpolPath: readyPolicy, vwcPath: servingWebhooks}},
		{name: "policy deleted", objects: map[string]string{vwcPath: servingWebhooks},
			wantProb: []string{"is not in the cluster"}},
		{name: "stale policy", objects: map[string]string{ivpolPath: strings.Replace(readyPolicy, testSum, "old", 1), vwcPath: servingWebhooks},
			wantProb: []string{"is not the policy this release renders"}},
		{name: "not ready", objects: map[string]string{ivpolPath: strings.Replace(readyPolicy, `"ready":true`, `"ready":false`, 1), vwcPath: servingWebhooks},
			wantProb: []string{"is not Ready"}},
		{name: "webhook not configured", objects: map[string]string{ivpolPath: strings.Replace(readyPolicy, `"WebhookConfigured","status":"True"`, `"WebhookConfigured","status":"False"`, 1), vwcPath: servingWebhooks},
			wantProb: []string{"is not Ready"}},
		{name: "kyverno scaled to zero", objects: map[string]string{ivpolPath: readyPolicy},
			wantProb: []string{"is missing (Kyverno removes it"}},
		{name: "ignore only", objects: map[string]string{ivpolPath: readyPolicy, vwcPath: strings.Replace(servingWebhooks, `"Fail"`, `"Ignore"`, 1)},
			wantProb: []string{"has no failurePolicy=Fail webhook serving"}},
		{name: "another policy", objects: map[string]string{ivpolPath: readyPolicy, vwcPath: strings.Replace(servingWebhooks, "/aaa/probectl-agent-image-integrity", "/probectl-agent-image-integrity-old", 1)},
			wantProb: []string{"has no failurePolicy=Fail webhook serving"}},
		{name: "not an ivpol webhook", objects: map[string]string{ivpolPath: readyPolicy, vwcPath: strings.Replace(servingWebhooks, "/ivpol/validate/aaa/", "/validate/fail/", 1)},
			wantProb: []string{"has no failurePolicy=Fail webhook serving"}},
		{name: "forbidden", status: http.StatusForbidden, wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("the observe-only check sent %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("Authorization = %q, want the service-account bearer token", got)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					return
				}
				body, ok := tc.objects[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			check := newTestCheck(t, srv)
			problems, err := check.Run(context.Background())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("an unreadable state was not an error (problems %v): the check must fail closed", problems)
				}
				return
			}
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(problems) != len(tc.wantProb) {
				t.Fatalf("problems = %q, want %d matching %q", problems, len(tc.wantProb), tc.wantProb)
			}
			for i, want := range tc.wantProb {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want it to say %q", i, problems[i], want)
				}
			}
		})
	}
}

func TestAdmissionCheckRefusesPlaintextAPIServer(t *testing.T) {
	check := AdmissionCheck{APIServer: "http://10.0.0.1:443", Policy: testPolicy, Client: http.DefaultClient}
	if _, err := check.Run(context.Background()); err == nil {
		t.Fatal("a plaintext API server URL was accepted")
	}
}

func TestInClusterAPIServer(t *testing.T) {
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "fd00::1", "KUBERNETES_SERVICE_PORT": "443"}
	got, err := InClusterAPIServer(func(k string) string { return env[k] })
	if err != nil || got != "https://[fd00::1]:443" {
		t.Fatalf("InClusterAPIServer = %q, %v", got, err)
	}
	if _, err := InClusterAPIServer(func(string) string { return "" }); err == nil {
		t.Fatal("no in-cluster environment was accepted")
	}
}

func newTestCheck(t *testing.T, srv *httptest.Server) AdmissionCheck {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewAdmissionCheckClient(caFile)
	if err != nil {
		t.Fatal(err)
	}
	return AdmissionCheck{APIServer: srv.URL, TokenFile: tokenFile, Policy: testPolicy, PolicySHA256: testSum, Client: client}
}
