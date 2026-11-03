// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
)

type recordedAlertEvaluations struct {
	tenants []string
	limit   *int
}

func (*recordedAlertEvaluations) AlertTagAdmission(context.Context, *auth.Principal) (func(), error) {
	return func() {}, nil
}
func (b *recordedAlertEvaluations) AlertEvaluations(_ context.Context, p *auth.Principal, input AlertEvaluationsInput) (alert.EvaluationsResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	b.limit = input.Limit
	return alert.EvaluationsResult{TagSelectionAccess: "available", Items: []alert.EvaluationReceipt{{RuleID: input.RuleID, TagSelection: &alert.TagSelectionReceipt{TargetKind: "test", TagRevision: "9007199254740993", AsOf: time.Date(2026, 11, 3, 22, 0, 0, 0, time.UTC)}}}}, nil
}
func TestNativeAlertEvaluationsRequireUserStrictBoundsAndPreserveExactClock(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	b := &recordedAlertEvaluations{}
	s := newTestServer(&fakeBackend{}, testGate(), WithAlertEvaluationBackend(b, json.RawMessage(`{"type":"object"}`)))
	p := principal("tenant-a", "alert.read")
	p.UserID = "reader"
	if !listedToolNames(t, handle(t, s, p, 1, "tools/list", nil))["alert_evaluations"] {
		t.Fatal("ordinary alert reader lost receipt parity without metadata grants")
	}
	missing := principal("tenant-a", "tags.read", "test.read", "metrics.read")
	missing.UserID = "reader"
	if code, _ := errCode(handle(t, s, missing, 2, "tools/call", map[string]any{"name": "alert_evaluations", "arguments": map[string]any{"rule_id": id}})); code != codeForbidden || len(b.tenants) != 0 {
		t.Fatal("missing alert.read reached native receipt backend")
	}
	if code, _ := errCode(handle(t, s, principal("tenant-a", "alert.read"), 3, "tools/call", map[string]any{"name": "alert_evaluations", "arguments": map[string]any{"rule_id": id}})); code != codeUnauthorized || len(b.tenants) != 0 {
		t.Fatal("non-user receipt caller reached backend")
	}
	for _, raw := range []string{
		`{"rule_id":"` + id + `","tenant_id":"foreign"}`,
		`{"Rule_ID":"` + id + `"}`,
		`{"rule_id":"` + id + `","limit":0}`,
		`{"rule_id":"` + id + `","limit":101}`,
		`{"rule_id":"` + id + `","limit":1.5}`,
		`{"rule_id":"` + id + `","limit":null}`,
		`{"rule_id":"not-owned"}`,
		`{"rule_id":"` + id + `","fingerprint":"` + strings.Repeat("x", 2049) + `"}`,
	} {
		if resultOf(t, handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_evaluations", "arguments": json.RawMessage(raw)}))["isError"] != true || len(b.tenants) != 0 {
			t.Fatal("ambiguous, unbounded or hinted receipt input reached backend")
		}
	}
	// Duplicate fields are rejected by native RPC syntax before dispatch, not
	// represented as a tool-result error. Both layers must keep the backend cold.
	duplicate := json.RawMessage(`{"rule_id":"` + id + `","rule_id":"` + id + `"}`)
	if code, ok := errCode(handle(t, s, p, 4, "tools/call", map[string]any{"name": "alert_evaluations", "arguments": duplicate})); !ok || code != codeInvalidParams || len(b.tenants) != 0 {
		t.Fatal("duplicate native receipt keys passed the RPC boundary")
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		p.TenantID = tenant
		out := resultOf(t, handle(t, s, p, 5, "tools/call", map[string]any{"name": "alert_evaluations", "arguments": map[string]any{"rule_id": id, "limit": 100}}))
		encoded, err := json.Marshal(out)
		if err != nil || out["isError"] == true || b.tenants[len(b.tenants)-1] != tenant || b.limit == nil || *b.limit != 100 || !strings.Contains(string(encoded), "9007199254740993") {
			t.Fatal("native receipt lost current tenant, explicit limit or exact decimal clock")
		}
	}
	hidden := newTestServer(&fakeBackend{}, testGate(), WithAlertEvaluationBackend(b, nil))
	if listedToolNames(t, handle(t, hidden, p, 6, "tools/list", nil))["alert_evaluations"] {
		t.Fatal("native receipt published without its API schema")
	}
}
