// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type recordedNMSImportBackend struct{ tenants []string }

func (b *recordedNMSImportBackend) NMSImportRows(_ context.Context, p *auth.Principal,
	_ NMSImportRowsInput) (NMSImportRowsResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportRowsResult{Items: []NMSImportRowResult{}}, nil
}

func (b *recordedNMSImportBackend) NMSImportDryRun(_ context.Context, p *auth.Principal,
	_ NMSImportDryRunInput) (NMSImportDryRunResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportDryRunResult{Items: []NMSImportDiffItemResult{}}, nil
}

func (b *recordedNMSImportBackend) NMSImportPollTarget(_ context.Context, p *auth.Principal,
	_ NMSImportPollTargetInput) (NMSImportPollTargetResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportPollTargetResult{TenantID: p.TenantID}, nil
}

func (b *recordedNMSImportBackend) NMSImportPollProposals(_ context.Context, p *auth.Principal,
	_ NMSImportPollProposalsInput) (NMSImportPollProposalsResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportPollProposalsResult{Items: []NMSImportPollProposalResult{}}, nil
}

func (b *recordedNMSImportBackend) NMSImportAlertTarget(_ context.Context, p *auth.Principal,
	_ NMSImportAlertTargetInput) (NMSImportAlertTargetResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportAlertTargetResult{TenantID: p.TenantID, Enabled: false}, nil
}

func (b *recordedNMSImportBackend) NMSImportAlertApply(_ context.Context, p *auth.Principal,
	_ NMSImportAlertApplyInput) (NMSImportAlertApplyResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportAlertApplyResult{Created: true}, nil
}

func (b *recordedNMSImportBackend) NMSImportExportStart(_ context.Context, p *auth.Principal,
	_ NMSImportExportStartInput) (NMSImportExportStartResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportExportStartResult{PlanID: "plan", State: "capturing", Preview: true}, nil
}

func (b *recordedNMSImportBackend) NMSImportExportPage(_ context.Context, p *auth.Principal,
	_ NMSImportExportPageInput) (NMSImportExportPageResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportExportPageResult{PageHash: "hash"}, nil
}

func (b *recordedNMSImportBackend) NMSImportExportSeal(_ context.Context, p *auth.Principal,
	_ NMSImportExportSealInput) (NMSImportExportSealResult, error) {
	b.tenants = append(b.tenants, p.TenantID)
	return NMSImportExportSealResult{State: "sealed", Preview: true}, nil
}

func TestNMSImportMCPAuthorizationAndTenantHint(t *testing.T) {
	b := &recordedNMSImportBackend{}
	s := newTestServer(&fakeBackend{}, testGate(), WithNMSImportBackend(b),
		WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, nil }))
	reader := principal("tenant-a", "nms.import.read")
	reader.UserID = "reader"
	if got := listedToolNames(t, handle(t, s, reader, 1, "tools/list", nil)); !got["nms_import_rows"] || !got["nms_import_dry_run"] || !got["nms_import_poll_proposals"] || !got["nms_import_poll_target"] || !got["nms_import_alert_target"] || got["nms_import_alert_apply"] {
		t.Fatalf("import read tools missing from catalog: %v", got)
	}
	denied := principal("tenant-a", "entities.read")
	denied.UserID = "reader"
	if code, _ := errCode(handle(t, s, denied, 2, "tools/call", map[string]any{
		"name": "nms_import_rows", "arguments": map[string]any{"context_id": "ctx", "plan_id": "plan"},
	})); code != codeForbidden || len(b.tenants) != 0 {
		t.Fatalf("unauthorized import read reached backend: code=%d tenants=%v", code, b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 3, "tools/call", map[string]any{
		"name": "nms_import_rows", "arguments": map[string]any{"context_id": "ctx", "plan_id": "plan"},
	}))["isError"] == true || len(b.tenants) != 1 || b.tenants[0] != "tenant-a" {
		t.Fatalf("authorized import read changed tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, reader, 4, "tools/call", map[string]any{
		"name": "nms_import_dry_run", "arguments": map[string]any{
			"context_id": "ctx", "plan_id": "plan", "review_hash": "hash", "tenant_id": "tenant-b"},
	}))["isError"] != true || len(b.tenants) != 1 {
		t.Fatalf("caller tenant hint reached import backend: %v", b.tenants)
	}
	if code, _ := errCode(handle(t, s, reader, 5, "tools/call", map[string]any{
		"name": "nms_import_alert_apply", "arguments": map[string]any{
			"context_id": "ctx", "source_id": "source", "rule_external_id": "31",
			"agent_id": "agent", "target_address": "target", "plan_id": "plan",
			"snapshot_hash": "hash", "entity_id": "entity"},
	})); code != codeForbidden || len(b.tenants) != 1 {
		t.Fatalf("read-only caller reached alert write backend: code=%d tenants=%v", code, b.tenants)
	}
	writer := principal("tenant-a", "nms.import.read", "nms.import.write")
	writer.UserID = "writer"
	if got := listedToolNames(t, handle(t, s, writer, 6, "tools/list", nil)); !got["nms_import_alert_apply"] {
		t.Fatalf("authorized alert write tool missing: %v", got)
	}
	if resultOf(t, handle(t, s, writer, 7, "tools/call", map[string]any{
		"name": "nms_import_alert_apply", "arguments": map[string]any{
			"context_id": "ctx", "source_id": "source", "rule_external_id": "31",
			"agent_id": "agent", "target_address": "target", "plan_id": "plan",
			"snapshot_hash": "hash", "entity_id": "entity"},
	}))["isError"] == true || len(b.tenants) != 2 || b.tenants[1] != "tenant-a" {
		t.Fatalf("authorized alert write changed tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 8, "tools/call", map[string]any{
		"name": "nms_import_alert_apply", "arguments": map[string]any{
			"context_id": "ctx", "source_id": "source", "rule_external_id": "31",
			"agent_id": "agent", "target_address": "target", "plan_id": "plan",
			"snapshot_hash": "hash", "entity_id": "entity", "tenant_id": "tenant-b"},
	}))["isError"] != true || len(b.tenants) != 2 {
		t.Fatalf("caller tenant hint reached alert write backend: %v", b.tenants)
	}
	if code, _ := errCode(handle(t, s, reader, 9, "tools/call", map[string]any{
		"name": "nms_import_export_start", "arguments": map[string]any{
			"context_id": "ctx", "source_kind": "orion", "instance_ref": "lab"},
	})); code != codeForbidden || len(b.tenants) != 2 {
		t.Fatalf("read-only caller started an export preview: code=%d tenants=%v", code, b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 10, "tools/call", map[string]any{
		"name": "nms_import_export_start", "arguments": map[string]any{
			"context_id": "ctx", "source_kind": "prtg", "instance_ref": "lab"},
	}))["isError"] == true || len(b.tenants) != 3 || b.tenants[2] != "tenant-a" {
		t.Fatalf("authorized export start changed tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 11, "tools/call", map[string]any{
		"name": "nms_import_export_page", "arguments": map[string]any{
			"context_id": "ctx", "plan_id": "plan", "resource": "devices",
			"page_number": 0, "first_row": 0,
			"page": []map[string]any{{"id": "101", "name": "router"}}},
	}))["isError"] == true || len(b.tenants) != 4 || b.tenants[3] != "tenant-a" {
		t.Fatalf("authorized export page changed tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 12, "tools/call", map[string]any{
		"name": "nms_import_export_seal", "arguments": map[string]any{
			"context_id": "ctx", "plan_id": "plan", "expected_pages": 1, "expected_rows": 1},
	}))["isError"] == true || len(b.tenants) != 5 || b.tenants[4] != "tenant-a" {
		t.Fatalf("authorized export seal changed tenant: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 13, "tools/call", map[string]any{
		"name": "nms_import_export_page", "arguments": map[string]any{
			"context_id": "ctx", "plan_id": "plan", "resource": "devices",
			"page_number": 0, "first_row": 0,
			"page": []map[string]any{{"id": "101"}}, "tenant_id": "tenant-b"},
	}))["isError"] != true || len(b.tenants) != 5 {
		t.Fatalf("caller tenant hint reached export page backend: %v", b.tenants)
	}
	if resultOf(t, handle(t, s, writer, 14, "tools/call", map[string]any{
		"name": "nms_import_export_page", "arguments": map[string]any{
			"context_id": "ctx", "plan_id": "plan", "resource": "devices",
			"page_number": 0, "first_row": 0, "page": "source-secret"},
	}))["isError"] != true || len(b.tenants) != 5 {
		t.Fatalf("scalar source page reached export backend: %v", b.tenants)
	}
}
