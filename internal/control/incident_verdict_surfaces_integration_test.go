// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveIncidentVerdictServedReaders(t *testing.T, f *roleExplanationAPIFixture, tenant, id string, input incident.VerdictInput, want incident.FaultVerdict) {
	t.Helper()
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "verdict-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	assert := func(raw []byte, want incident.FaultVerdict, surface string) {
		t.Helper()
		var got incident.FaultVerdict
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.ContractVersion != "probectl.incident-verdict.v1" || !got.Preview || got.IncidentID != id || got.ValidUntil == nil {
			t.Fatalf("served verdict metadata: contract=%q preview=%v same_incident=%v deadline=%v", got.ContractVersion, got.Preview, got.IncidentID == id, got.ValidUntil != nil)
		}
		var expected incident.FaultVerdict
		encoded, _ := json.Marshal(want)
		if err := json.Unmarshal(encoded, &expected); err != nil {
			t.Fatal(err)
		}
		expected.EvaluatedAt = got.EvaluatedAt
		if !reflect.DeepEqual(got, expected) {
			t.Fatal("reader changed original hypotheses, citations, scope, coverage or validity", surface, verdictReaderDifference(expected, got), got.Domain, expected.Domain)
		}
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/verdict", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
	request.Header.Set("Content-Type", "application/json")
	response, err := socket.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("served verdict failed", response.StatusCode, err, closeErr)
	}
	assert(raw, want, "REST")
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	result, err := client.GetIncidentVerdict(t.Context(), sdk.GetIncidentVerdictRequest{Id: id, Body: &sdk.IncidentVerdictInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}})
	if err != nil {
		t.Fatal("generated verdict SDK failed", err)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assert(raw, want, "SDK")
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "incident", "verdict", id, "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr); code != 0 {
		t.Fatal("verified TLS verdict CLI failed", code, stderr.String())
	}
	assert(stdout.Bytes(), want, "CLI")
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		var native incident.FaultVerdict
		call(tenant, "incident_verdict", map[string]any{"incident_id": id, "from": input.From, "to": input.To}, &native, true)
		raw, err := json.Marshal(native)
		if err != nil {
			t.Fatal(err)
		}
		var redacted incident.FaultVerdict
		expectedBody, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(expectedBody, &redacted); err != nil {
			t.Fatal(err)
		}
		for i := range redacted.Hypotheses {
			for _, citations := range [][]incident.VerdictCitation{redacted.Hypotheses[i].For, redacted.Hypotheses[i].Against} {
				for j := range citations {
					citations[j].AgentID = ai.RedactTextForTenant(citations[j].AgentID, ai.DefaultRedaction, tenant)
					if route := citations[j].Routing; route != nil {
						route.Address = ai.RedactTextForTenant(route.Address, ai.DefaultRedaction, tenant)
						route.Prefix = ai.RedactTextForTenant(route.Prefix, ai.DefaultRedaction, tenant)
					}
				}
			}
		}
		assert(raw, redacted, "native "+wire)
	}
}

func proveIncidentVerdictForeignReaderRefusal(t *testing.T, f *roleExplanationAPIFixture, tenant, foreignID string, input incident.VerdictInput) {
	t.Helper()
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	if result, err := client.GetIncidentVerdict(t.Context(), sdk.GetIncidentVerdictRequest{Id: foreignID, Body: &sdk.IncidentVerdictInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}}); err == nil || result != nil {
		t.Fatal("foreign incident returned a generated verdict payload")
	}
	if raw, err := client.ExportIncidentEvidenceBytes(t.Context(), sdk.ExportIncidentEvidenceBytesRequest{Id: foreignID, Body: &sdk.IncidentEvidenceExportInput{Verdict: &sdk.IncidentVerdictInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}}}); err == nil || len(raw) != 0 {
		t.Fatal("foreign incident returned signed verdict bytes")
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(tenant, "incident_verdict", map[string]any{"incident_id": foreignID, "from": input.From, "to": input.To}, nil, false)
	}
}

// Report JSON field paths only: fixture diagnostics must not dump tenant data.
func verdictReaderDifference(want, got any) string {
	encode := func(value any) any {
		body, _ := json.Marshal(value)
		var out any
		_ = json.Unmarshal(body, &out)
		return out
	}
	var first func(any, any, string) string
	first = func(a, b any, path string) string {
		if reflect.DeepEqual(a, b) {
			return ""
		}
		switch left := a.(type) {
		case map[string]any:
			right, ok := b.(map[string]any)
			if !ok {
				return path + " (type)"
			}
			keys := []string{}
			for key := range left {
				keys = append(keys, key)
			}
			for key := range right {
				if _, exists := left[key]; !exists {
					keys = append(keys, key)
				}
			}
			slices.Sort(keys)
			for _, key := range keys {
				if result := first(left[key], right[key], path+"."+key); result != "" {
					return result
				}
			}
		case []any:
			right, ok := b.([]any)
			if !ok {
				return path + " (type)"
			}
			if len(left) != len(right) {
				return path + " (length)"
			}
			for i := range left {
				if result := first(left[i], right[i], fmt.Sprintf("%s[%d]", path, i)); result != "" {
					return result
				}
			}
		}
		return path
	}
	return first(encode(want), encode(got), "response")
}
