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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

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
	assert := func(raw []byte) {
		t.Helper()
		var got incident.FaultVerdict
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.ContractVersion != "probectl.incident-verdict.v1" || !got.Preview || got.IncidentID != id || got.ValidUntil == nil {
			t.Fatal("served verdict lost its contract or authority deadline")
		}
		var expected incident.FaultVerdict
		encoded, _ := json.Marshal(want)
		if err := json.Unmarshal(encoded, &expected); err != nil {
			t.Fatal(err)
		}
		expected.EvaluatedAt = got.EvaluatedAt
		if !reflect.DeepEqual(got, expected) {
			t.Fatal("reader changed original hypotheses, citations, scope, coverage or validity", got.Domain, expected.Domain)
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
	assert(raw)
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	result, err := client.GetIncidentVerdict(t.Context(), sdk.GetIncidentVerdictRequest{Id: id, Body: &sdk.IncidentVerdictInput{From: input.From.Format(time.RFC3339Nano), To: input.To.Format(time.RFC3339Nano)}})
	if err != nil {
		t.Fatal("generated verdict SDK failed", err)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	assert(raw)
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	if code := cli.RunWithStdin([]string{"--json", "incident", "verdict", id, "--body-file", "-"}, getenv, bytes.NewReader(body), &stdout, &stderr); code != 0 {
		t.Fatal("verified TLS verdict CLI failed", code, stderr.String())
	}
	assert(stdout.Bytes())
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		var native incident.FaultVerdict
		call(tenant, "incident_verdict", map[string]any{"incident_id": id, "from": input.From, "to": input.To}, &native, true)
		raw, err := json.Marshal(native)
		if err != nil {
			t.Fatal(err)
		}
		assert(raw)
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
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		call(tenant, "incident_verdict", map[string]any{"incident_id": foreignID, "from": input.From, "to": input.To}, nil, false)
	}
}
