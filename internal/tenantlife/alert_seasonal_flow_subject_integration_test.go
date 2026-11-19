// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSeasonalFlowEvidenceSubjectErasureIncludesOriginalRoutingScope(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	pool := flowQueryRuntime(t, admin)
	red := mkTenant(t, admin, "thermal-subject-red-"+flowQueryUUID(t))
	blue := mkTenant(t, admin, "thermal-subject-blue-"+flowQueryUUID(t))
	defer func() {
		if _, err := admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	}()
	const subject = "192.0.2.141"
	viewID := flowQueryUUID(t)
	for _, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return seedSeasonalReceiptSubjectRows(ctx, sc, viewID, subject)
		}); err != nil {
			t.Fatal(err)
		}
	}
	engine := New(pool, nil, nil, nil, nil, "owned seasonal source scope", testLog())
	var retained bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), red, viewID, &retained, false); err != nil {
		t.Fatal(err)
	}
	const path = "postgres/alert_evaluation_receipts.jsonl"
	if strings.Contains(readTarGz(t, retained.Bytes())[path], "seasonal-structural") {
		t.Fatal("a configured view ID was treated as the subject")
	}
	var archive bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), red, subject, &archive, false); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(readTarGz(t, archive.Bytes())[path]), "\n")
	if len(rows) != 3 || !strings.Contains(strings.Join(rows, "\n"), "seasonal-subject-compact") ||
		!strings.Contains(strings.Join(rows, "\n"), "seasonal-subject-shared") {
		t.Fatal("all stored proof versions must expose source subject references")
	}
	for _, row := range rows {
		if !strings.Contains(row, red) || !strings.Contains(row, "seasonal-subject") || strings.Contains(row, blue) {
			t.Fatal("the original reader scope was omitted or crossed tenant boundaries")
		}
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), red, subject, "privacy-admin", "verified test subject"); err != nil {
		t.Fatal(err)
	}
	const selected = `SELECT count(*) FROM alert_evaluation_receipts WHERE tenant_id=$1 AND fingerprint LIKE $2`
	if countRows(t, admin, selected, red, "seasonal-subject%") != 0 || countRows(t, admin, selected, red, "seasonal-structural%") != 3 ||
		countRows(t, admin, selected, blue, "seasonal-subject%") != 3 {
		t.Fatal("subject erasure did not preserve the unrelated scope and sibling tenant")
	}
}

func seedSeasonalReceiptSubjectRows(ctx context.Context, sc tenancy.Scope, viewID, subject string) error {
	rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Owned flow baseline", Type: alert.Baseline, Metric: alert.SeasonalFlowMetric, Window: 20,
		Sensitivity: 3, Severity: alert.SeverityWarning})
	if err != nil {
		return err
	}
	for label, address := range map[string]string{"seasonal-subject": subject, "seasonal-structural": "192.0.2.254"} {
		route := map[string]any{"captures": []any{map[string]any{"src": address}}}
		legacy := map[string]any{"version": 1, "tenant_id": sc.Tenant.String(), "inputs": []any{map[string]any{"id": viewID, "routing": route}}}
		compact := map[string]any{"version": 2, "tenant_id": sc.Tenant.String(), "timeline": map[string]any{"id": viewID, "periods": []any{map[string]any{"routing": route}}}}
		if err := appendSeasonalSubjectReceipt(ctx, sc, rule, label, legacy); err != nil {
			return err
		}
		if err := appendSeasonalSubjectReceipt(ctx, sc, rule, label+"-compact", compact); err != nil {
			return err
		}
		shared := map[string]any{"version": 3, "tenant_id": sc.Tenant.String(), "timeline": map[string]any{"id": viewID, "shared_routing": route}}
		if err := appendSeasonalSubjectReceipt(ctx, sc, rule, label+"-shared", shared); err != nil {
			return err
		}
	}
	return nil
}

func appendSeasonalSubjectReceipt(ctx context.Context, sc tenancy.Scope, rule *alert.Rule, label string, proof map[string]any) error {
	scope, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	receipt := alert.EvaluationReceipt{ContractVersion: alert.EvaluationReceiptVersion, RuleID: rule.ID, Fingerprint: label,
		RuleRevision: rule.UpdatedAt.UTC().Format(time.RFC3339Nano), State: alert.EvaluationFiring, ObservedAt: time.Now().UTC(),
		Expectation: alert.EvaluationExpectation{Kind: alert.Baseline, Seasonal: &alert.SeasonalEvaluationEvidence{
			Exact: &anomaly.SeasonalDecimalBand{Current: "7", Lower: "4", Upper: "6"}, FlowScope: scope}}, RequiredBreaches: 1}
	return (store.AlertEvaluations{}).Append(ctx, sc, receipt)
}
