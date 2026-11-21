// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestDeviceConfigPolicyCommitsOwnedEvaluationsAndRedactedWitnesses(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithDeviceOps(device.NewPostgresOpsStore(f.pool))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	binding := configPolicyBindingInput{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}
	body := func(expected string, rules []device.ConfigPolicyRule) map[string]any {
		return map[string]any{"binding": binding, "expected_revision": expected, "rules": rules}
	}
	type stored struct {
		ID         string                         `json:"archive_id"`
		Evaluation *device.ConfigPolicyEvaluation `json:"evaluation"`
	}
	const policyRoute = "/v1/device/config-policy"
	const sentinel = "secret-synthetic-config-policy-fixture"
	var ids [2]string
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "metrics.write")
		})
		rules := []device.ConfigPolicyRule{{ID: "clock", Mode: device.ConfigRuleTemplate, Template: device.ConfigPolicyIOSNTP},
			{ID: "legacy-snmp", Mode: device.ConfigRuleMustNotContain, Text: "snmp-server community"}}
		policy := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, policyRoute, body("0", rules), http.StatusOK)
		var configured device.ConfigPolicyRevision
		if err := json.Unmarshal(policy, &configured); err != nil || configured.Version != "1" ||
			len(configured.Rules) != 2 || configured.Rules[0].Revision != "1" {
			t.Fatal("invalid persisted policy revision", err)
		}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, policyRoute, body("0", rules), http.StatusConflict)
		content := "version 17.9\nntp server 192.0.2.33\nend\n"
		if lane == 0 {
			content = "version 17.9\nsnmp-server community " + sentinel + " RO\nend\n"
		}
		archive := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/device/configs",
			map[string]any{"device": "same-canonical-router", "binding": binding, "content": content}, http.StatusCreated)
		var original device.ConfigVersion
		if err := json.Unmarshal(archive, &original); err != nil || original.ID == "" || bytes.Contains(archive, []byte(sentinel)) {
			t.Fatal("archive response did not preserve only redacted content", err)
		}
		ids[lane] = original.ID
		path := "/v1/device/configs/" + original.ID + "/policy-evaluation"
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path, nil, http.StatusOK)
		var result stored
		if err := json.Unmarshal(raw, &result); err != nil || result.ID != original.ID || result.Evaluation == nil ||
			result.Evaluation.PolicyVersion != "1" || len(result.Evaluation.Verdicts) != 2 || bytes.Contains(raw, []byte(sentinel)) {
			t.Fatal("exact owned policy evaluation is missing or exposed the secret sentinel", err)
		}
		verifyConfigPolicyFixtureResult(t, lane, result.Evaluation.Verdicts, original.ContentHash)
		csv := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, path+"?format=csv", nil, http.StatusOK)
		if bytes.Contains(csv, []byte(sentinel)) || !bytes.Contains(csv, []byte(original.ContentHash)) ||
			lane == 0 && !bytes.Contains(csv, []byte("snmp-server community [redacted] RO")) {
			t.Fatal("CSV lost original redacted evidence")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var signals, foreign int
			err := sc.Q.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND kind='device.config_policy_violation'),
				(SELECT count(*) FROM device_config_policy_revisions WHERE tenant_id=$2)`, tenant, f.tenants[1-lane]).
				Scan(&signals, &foreign)
			if err == nil && (foreign != 0 || signals != 1-lane) {
				t.Fatal("a passing, foreign, or repeated evaluation emitted the wrong signals")
			}
			return err
		})
	}
	for lane, tenant := range f.tenants {
		foreign := "/v1/device/configs/" + ids[1-lane] + "/policy-evaluation"
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, foreign, nil, http.StatusNotFound)
	}
	verifyDeviceConfigPolicyClients(t, f, socket, ids)
	verifyNativeDeviceConfigPolicy(t, f, binding, ids)
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=statement_timestamp()
			WHERE tenant_id=$1 AND agent_id=$2 AND source_ref=$3 AND source_kind='device_target'`, f.tenants[0], binding.AgentID, binding.SourceRef)
		return err
	})
	path := "/v1/device/configs/" + ids[0] + "/policy-evaluation"
	callSeasonalAPI(t, socket, f.tokens[f.tenants[0]], http.MethodGet, path, nil, http.StatusNotFound)
}

func verifyDeviceConfigPolicyClients(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ids [2]string) {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "device-policy-cli-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		original := sdk.GetDeviceConfigPolicyEvaluationRequest{Id: ids[lane]}
		sdkResult, err := client.GetDeviceConfigPolicyEvaluation(t.Context(), original)
		if err != nil || sdkResult == nil || sdkResult.ArchiveId != ids[lane] || sdkResult.Evaluation == nil {
			t.Fatal("the SDK lost the authorized configuration policy evaluation", err)
		}
		if result, err := client.GetDeviceConfigPolicyEvaluation(t.Context(), sdk.GetDeviceConfigPolicyEvaluationRequest{Id: ids[1-lane]}); err == nil || result != nil {
			t.Fatal("the SDK received a foreign configuration policy evaluation")
		}
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		var out, stderr bytes.Buffer
		args := []string{"--json", "device", "config-policy-evaluation", ids[lane]}
		if code := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &out, &stderr); code != 0 ||
			!bytes.Contains(out.Bytes(), []byte(ids[lane])) || bytes.Contains(out.Bytes(), []byte(ids[1-lane])) {
			t.Fatal("CLI failed to retain exactly the authorized configuration policy evaluation", code, stderr.String())
		}
		out.Reset()
		stderr.Reset()
		args[len(args)-1] = ids[1-lane]
		if code := cli.RunWithStdin(args, getenv, bytes.NewReader(nil), &out, &stderr); code == 0 || out.Len() != 0 {
			t.Fatal("CLI returned a foreign configuration policy evaluation")
		}
	}
}

func verifyNativeDeviceConfigPolicy(t *testing.T, f *roleExplanationAPIFixture, binding configPolicyBindingInput, ids [2]string) {
	t.Helper()
	seedInterfaceRoleMCPConsent(f)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
	}
	for wireIndex, wire := range []string{"2025-11-25", "2026-07-28"} {
		call := interfaceRoleTLSCaller(t, f, wire, false)
		want := strconv.Itoa(wireIndex + 1)
		for lane, tenant := range f.tenants {
			var policy device.ConfigPolicyRevision
			call(tenant, "device_config_policy", binding, &policy, true)
			if policy.Version != want {
				t.Fatal("native policy read lost the active revision", wire, lane)
			}
			var result struct {
				ID         string                         `json:"archive_id"`
				Evaluation *device.ConfigPolicyEvaluation `json:"evaluation"`
			}
			call(tenant, "device_config_policy_evaluation", map[string]string{"id": ids[lane]}, &result, true)
			if result.ID != ids[lane] || result.Evaluation == nil || result.Evaluation.PolicyVersion != "1" ||
				len(result.Evaluation.Verdicts) != 2 || result.Evaluation.Verdicts[0].ArchiveID != ids[lane] ||
				len(result.Evaluation.Verdicts[0].ArchiveSHA256) != 64 {
				t.Fatal("native result lost its immutable archive or revision provenance", wire, lane, result.Evaluation)
			}
			call(tenant, "device_config_policy_evaluation", map[string]string{"id": ids[1-lane]}, &result, false)
			call(tenant, "device_config_policy_publish", map[string]any{"binding": binding, "expected_revision": want,
				"rules": []device.ConfigPolicyRule{{ID: "updated", Mode: device.ConfigRuleMustContain, Text: "ntp server"}}}, &policy, true)
			if policy.Version != strconv.Itoa(wireIndex+2) {
				t.Fatal("native policy did not publish an independent version", wire, lane)
			}
		}
	}
}

func verifyConfigPolicyFixtureResult(t *testing.T, lane int, verdicts []device.ConfigPolicyVerdict, digest string) {
	t.Helper()
	for _, verdict := range verdicts {
		if verdict.ArchiveSHA256 != digest || verdict.RuleRevision != "1" {
			t.Fatal("policy receipt lost the original hash or revision")
		}
	}
	if lane == 1 && (verdicts[0].State != "pass" || verdicts[1].State != "pass") {
		t.Fatal("the independently compliant device should pass")
	}
	if lane == 0 {
		if verdicts[0].State != "violation" || verdicts[1].State != "violation" || len(verdicts[1].OffendingLines) != 1 {
			t.Fatal("the failed rules lost their provenance")
		}
		line := verdicts[1].OffendingLines[0]
		if line.Number != 2 || strings.TrimSpace(line.Text) != "snmp-server community [redacted] RO" {
			t.Fatal("redacted witness and source position were changed")
		}
	}
}
