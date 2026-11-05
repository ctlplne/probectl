// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Compile before the generation heap baseline: this is a production CLI,
// separate from the observed control/test process and its source admission.
func buildCompleteSourceCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "probectl")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, "./cmd/probectl")
	command.Dir = filepath.Join("..", "..")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile release CLI: %v\n%s", err, output)
	}
	return binary
}

// Replace only one lane's direct client with the compiled terminal client.
// The same single authenticated public POST and complete independent output
// checks remain; no extra source generation, input retry or shortened result.
func completeSourceGenerateCLI(t *testing.T, binary string, socket *httptest.Server, token, tenant string, input reportGenerateRequest) reportArtifactView {
	t.Helper()
	dir := t.TempDir()
	caFile, bodyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bodyFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--request-timeout", "150s", "--json", "dashboard-report", "generate", "--body-file", bodyFile)
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if key != "PROBECTL_API_URL" && key != "PROBECTL_CA_FILE" && key != "PROBECTL_API_TOKEN" && key != "PROBECTL_TENANT" && !strings.HasPrefix(key, "PROBECTL_CLI_") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "PROBECTL_API_URL="+socket.URL, "PROBECTL_CA_FILE="+caFile, "PROBECTL_API_TOKEN="+token, "PROBECTL_TENANT="+tenant)
	output, err := command.Output()
	if err != nil {
		// Never print the environment, command credentials or server payload.
		t.Fatal("compiled CLI complete report generation failed", err)
	}
	var artifact reportArtifactView
	if err := json.Unmarshal(output, &artifact); err != nil || artifact.ID == "" {
		t.Fatal("compiled CLI report metadata was incomplete or malformed", err)
	}
	t.Log("compiled CLI complete report generation: verified TLS, current bearer/tenant, explicit150s request profile; control heap observation excludes CLI process")
	return artifact
}
