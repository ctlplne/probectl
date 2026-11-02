// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

func TestNMSImportConfigExportRequiresCurrentBindingAndSeparateCredentialName(t *testing.T) {
	const tenantID = "00000000-0000-4000-8000-000000000101"
	const contextID = "00000000-0000-4000-8000-000000000102"
	const sourceID = "00000000-0000-4000-8000-000000000103"
	const planID = "00000000-0000-4000-8000-000000000104"
	const itemID = "11111111222233334444555555555555"
	const agentID = "device-agent-a"
	const target = "192.0.2.44"
	preview := nmsimport.PollTargetPreview{TenantID: tenantID, ContextID: contextID,
		SourceID: sourceID, ItemID: itemID, HostID: "edge-r1",
		EntityID: "00000000-0000-4000-8000-000000000105", AgentID: agentID,
		TargetAddress: target, PollSeconds: 120, PlanID: planID, Revision: 2}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/nms-imports/poll-target-preview" {
			t.Errorf("wrong preview route: %s %s", r.Method, r.URL.Path)
		}
		var got map[string]string
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil ||
			got["context_id"] != contextID || got["source_id"] != sourceID ||
			got["item_external_id"] != itemID || got["agent_id"] != agentID ||
			got["target_address"] != target {
			t.Errorf("preview selection: %+v err=%v", got, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(preview)
	}))
	t.Cleanup(srv.Close)
	nameFile := filepath.Join(t.TempDir(), "credential-name")
	if err := os.WriteFile(nameFile, []byte("edge-ro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "device.yaml")
	args := []string{"nms-import", "config-export", "--context-id", contextID,
		"--source-id", sourceID, "--item-id", itemID, "--agent-id", agentID,
		"--target-address", target, "--port", "1161", "--transport", "snmpv3",
		"--credential-name-file", nameFile, "--expected-plan-id", planID,
		"--expected-revision", "2", "--out", output}
	if err := os.Chmod(nameFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := run(t, srv, args...); code != 2 ||
		!strings.Contains(stderr, "want 0600") || requests != 0 {
		t.Fatalf("shared credential name reached server: code=%d stderr=%q requests=%d", code, stderr, requests)
	}
	if err := os.Chmod(nameFile, 0o600); err != nil {
		t.Fatal(err)
	}
	staleArgs := append([]string(nil), args...)
	staleArgs[len(staleArgs)-3] = "1"
	if _, stderr, code := run(t, srv, staleArgs...); code != 1 ||
		!strings.Contains(stderr, "changed") || requests != 1 {
		t.Fatalf("stale proposal created output: code=%d stderr=%q requests=%d", code, stderr, requests)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("stale proposal left output: %v", err)
	}
	stdout, stderr, code := run(t, srv, args...)
	if code != 0 || stderr != "" || requests != 2 || !strings.Contains(stdout, "install explicitly") {
		t.Fatalf("export: code=%d stdout=%q stderr=%q requests=%d", code, stdout, stderr, requests)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output is not owner-only: info=%v err=%v", info, err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := device.Parse(raw)
	if err != nil || parsed.TenantID != tenantID || parsed.AgentID != agentID ||
		len(parsed.Devices) != 1 || parsed.Devices[0].Address != target ||
		parsed.Devices[0].Port != 1161 ||
		parsed.Devices[0].Credential != "edge-ro" || parsed.Devices[0].Interval != 120*time.Second {
		t.Fatalf("shipped device parser refused export: %+v err=%v", parsed, err)
	}
	if strings.Contains(string(raw), "10.0.0.1") || strings.Contains(string(raw), "community") {
		t.Fatalf("source address or credential material leaked: %s", raw)
	}
	if _, stderr, code := run(t, srv, args...); code != 1 ||
		!strings.Contains(stderr, "cannot create output") {
		t.Fatalf("existing config overwritten: code=%d stderr=%q", code, stderr)
	}
}
