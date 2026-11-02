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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Two tenants can import the same source address into independent routing
// contexts. A foreign context or plan has the same 404; redacted rows are
// reachable only through the authenticated tenant's sealed plan and bounded
// read permission.
func TestNMSImportSealedRowsRouteIsTenantAndContextBound(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "nms-rows-a"), freshTenant(t, db, "nms-rows-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove NMS route fixtures: %v", err)
		}
	})
	capturer := nmsimport.NewCaptureStore(db.Pool(),
		func(context.Context, tenancy.Scope, string, string, map[string]any) error { return nil })
	type fixture struct{ tenant, contextID, planID, snapshotHash, label string }
	makeFixture := func(tenant, label string) fixture {
		t.Helper()
		response := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": "West DC", "vrf_label": "Private"})
		var routing entity.ContextRecord
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &routing) != nil {
			t.Fatalf("create import context: %d %s", response.Code, response.Body.String())
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		planID, err := capturer.StartPlan(ctx, routing.ContextID, nmsimport.LibreNMS,
			"route-lab", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		body := `{"status":"ok","devices":[{"device_id":17,"display":"` + label +
			`","ip":"10.42.0.1","community":"source-only-secret"}],"count":1}`
		hash, err := capturer.CaptureLibreNMSDevices(ctx, routing.ContextID, planID,
			strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return fixture{tenant: tenant, contextID: routing.ContextID, planID: planID,
			snapshotHash: hash, label: label}
	}
	left, right := makeFixture(a, "Edge A"), makeFixture(b, "Edge B")
	if left.contextID == right.contextID || left.planID == right.planID {
		t.Fatal("tenant import contexts or plans collided")
	}
	for _, own := range []fixture{left, right} {
		base := "/v1/nms-imports/" + own.planID + "/rows?context_id=" + own.contextID
		response := apiReq(t, h, http.MethodGet, base+"&limit=1", own.tenant, nil)
		var page nmsimport.SealedRowsPage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil ||
			page.ContextID != own.contextID || page.PlanID != own.planID ||
			page.RowCount != 1 || len(page.Items) != 1 || page.Items[0].Label != own.label ||
			page.Items[0].Address != "10.42.0.1" ||
			strings.Contains(response.Body.String(), "source-only-secret") {
			t.Fatalf("tenant import page %s: %d %s", own.tenant, response.Code, response.Body.String())
		}
		other := left
		if own.tenant == left.tenant {
			other = right
		}
		for _, contextID := range []string{own.contextID, other.contextID} {
			foreign := apiReq(t, h, http.MethodGet,
				"/v1/nms-imports/"+other.planID+"/rows?context_id="+contextID,
				own.tenant, nil)
			if foreign.Code != http.StatusNotFound {
				t.Fatalf("foreign import plan disclosed through %s: %d %s",
					contextID, foreign.Code, foreign.Body.String())
			}
		}
		for _, query := range []string{"&cursor=-2", "&limit=101"} {
			invalid := apiReq(t, h, http.MethodGet, base+query, own.tenant, nil)
			if invalid.Code != http.StatusBadRequest {
				t.Fatalf("unbounded import page accepted: %d %s", invalid.Code, invalid.Body.String())
			}
		}
	}
	reviewHashes := make(map[string]string)
	for _, own := range []fixture{left, right} {
		base := "/v1/nms-imports/" + own.planID
		finalizeBody := map[string]any{"context_id": own.contextID, "snapshot_hash": own.snapshotHash}
		if response := apiReq(t, h, http.MethodPost, base+"/finalize-review", own.tenant, finalizeBody); response.Code != http.StatusConflict {
			t.Fatalf("unreviewed plan became preview: %d %s", response.Code, response.Body.String())
		}
		choiceBody := map[string]any{"context_id": own.contextID,
			"snapshot_hash": own.snapshotHash,
			"choices":       []nmsimport.ReviewChoice{{RowNumber: 0, Action: "unmapped"}}}
		other := left
		if own.tenant == left.tenant {
			other = right
		}
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/"+other.planID+"/review-choices", own.tenant, choiceBody); response.Code != http.StatusNotFound {
			t.Fatalf("foreign tenant reviewed plan: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/"+other.planID+"/finalize-review", own.tenant, finalizeBody); response.Code != http.StatusNotFound {
			t.Fatalf("foreign tenant finalized plan: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost, base+"/review-choices", own.tenant,
			map[string]any{"context_id": own.contextID, "snapshot_hash": strings.Repeat("0", 64),
				"choices": choiceBody["choices"]}); response.Code != http.StatusNotFound {
			t.Fatalf("stale snapshot reviewed: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodPost, base+"/review-choices", own.tenant, choiceBody); response.Code != http.StatusNoContent {
			t.Fatalf("own review choices: %d %s", response.Code, response.Body.String())
		}
		finalized := apiReq(t, h, http.MethodPost, base+"/finalize-review", own.tenant, finalizeBody)
		if finalized.Code != http.StatusOK || !strings.Contains(finalized.Body.String(), `"state":"preview"`) {
			t.Fatalf("own review finalize: %d %s", finalized.Code, finalized.Body.String())
		}
		var review struct {
			Hash string `json:"review_hash"`
		}
		if json.Unmarshal(finalized.Body.Bytes(), &review) != nil || len(review.Hash) != 64 {
			t.Fatalf("review hash missing from finalization: %s", finalized.Body.String())
		}
		reviewHashes[own.planID] = review.Hash
		dryRunURL := base + "/dry-run?context_id=" + own.contextID + "&review_hash=" + review.Hash
		if response := apiReq(t, h, http.MethodGet, dryRunURL+"&limit=101", own.tenant, nil); response.Code != http.StatusBadRequest {
			t.Fatalf("unbounded destination dry run accepted: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodGet, base+"/dry-run?context_id="+own.contextID+
			"&review_hash="+strings.Repeat("0", 64), own.tenant, nil); response.Code != http.StatusNotFound {
			t.Fatalf("wrong frozen review hash read destination diff: %d %s", response.Code, response.Body.String())
		}
		if response := apiReq(t, h, http.MethodGet,
			"/v1/nms-imports/"+other.planID+"/dry-run?context_id="+own.contextID+
				"&review_hash="+review.Hash, own.tenant, nil); response.Code != http.StatusNotFound {
			t.Fatalf("foreign tenant read destination diff: %d %s", response.Code, response.Body.String())
		}
		dryRun := apiReq(t, h, http.MethodGet, dryRunURL, own.tenant, nil)
		var diff nmsimport.ReviewDiffPage
		if dryRun.Code != http.StatusOK || json.Unmarshal(dryRun.Body.Bytes(), &diff) != nil ||
			len(diff.Items) != 1 || diff.Items[0].Action != "unmapped" ||
			diff.Items[0].ExternalID != "17" || strings.Contains(dryRun.Body.String(), "source-only-secret") {
			t.Fatalf("tenant destination dry run: %d %s", dryRun.Code, dryRun.Body.String())
		}
		response := apiReq(t, h, http.MethodGet,
			base+"/rows?context_id="+own.contextID, own.tenant, nil)
		var page nmsimport.SealedRowsPage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil ||
			len(page.Items) != 1 || !page.Items[0].Reviewed || page.Items[0].Action != "unmapped" {
			t.Fatalf("reviewed page lost decision: %d %s", response.Code, response.Body.String())
		}
	}
	srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "deny west import rows", Enabled: true,
			Effect: auth.PolicyDeny, Permission: permNMSImportRead,
			Resource: map[string]string{"site_label": "West DC"}},
			{Name: "deny west import review", Enabled: true,
				Effect: auth.PolicyDeny, Permission: permNMSImportWrite,
				Resource: map[string]string{"site_label": "West DC"}}}, nil
	}}
	for _, check := range []struct {
		fixture fixture
		status  int
	}{{left, http.StatusForbidden}, {right, http.StatusOK}} {
		response := apiReq(t, h, http.MethodGet,
			"/v1/nms-imports/"+check.fixture.planID+"/rows?context_id="+check.fixture.contextID,
			check.fixture.tenant, nil)
		if response.Code != check.status {
			t.Fatalf("import context policy tenant=%s: %d %s",
				check.fixture.tenant, response.Code, response.Body.String())
		}
		// The same read permission and routing-context policy protect the
		// destination comparison after review is finalized.
		dryRun := apiReq(t, h, http.MethodGet,
			"/v1/nms-imports/"+check.fixture.planID+"/dry-run?context_id="+
				check.fixture.contextID+"&review_hash="+reviewHashes[check.fixture.planID],
			check.fixture.tenant, nil)
		if dryRun.Code != check.status {
			t.Fatalf("dry-run context policy tenant=%s: %d %s",
				check.fixture.tenant, dryRun.Code, dryRun.Body.String())
		}
	}
	if response := apiReq(t, h, http.MethodPost,
		"/v1/nms-imports/"+left.planID+"/finalize-review", left.tenant,
		map[string]string{"context_id": left.contextID, "snapshot_hash": left.snapshotHash}); response.Code != http.StatusForbidden {
		t.Fatalf("context policy allowed review finalize: %d %s", response.Code, response.Body.String())
	}
}

// The route uses the same tenant/context write boundary as capture and review.
// Equal private addresses in two tenants never identify one destination.
func TestNMSImportApplyRouteWritesOnlyReviewedTenantAndIsIdempotent(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "nms-apply-a"), freshTenant(t, db, "nms-apply-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove NMS apply fixtures: %v", err)
		}
	})
	capturer := nmsimport.NewCaptureStore(db.Pool(),
		func(context.Context, tenancy.Scope, string, string, map[string]any) error { return nil })
	type fixture struct{ tenant, contextID, planID, snapshotHash, reviewHash string }
	makeFixture := func(tenant, label string) fixture {
		t.Helper()
		response := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": "Import DC", "vrf_label": "Private"})
		var routing entity.ContextRecord
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &routing) != nil {
			t.Fatalf("create apply context: %d %s", response.Code, response.Body.String())
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		planID, err := capturer.StartPlan(ctx, routing.ContextID, nmsimport.LibreNMS,
			"apply-lab", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		body := `{"status":"ok","devices":[{"device_id":17,"display":"` + label +
			`","ip":"10.42.0.1","location_id":9,"community":"source-only-secret"}],"count":1}`
		snapshotHash, err := capturer.CaptureLibreNMSDevices(ctx, routing.ContextID,
			planID, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		base := "/v1/nms-imports/" + planID
		choice := map[string]any{"context_id": routing.ContextID, "snapshot_hash": snapshotHash,
			"choices": []nmsimport.ReviewChoice{{RowNumber: 0, Action: "create"}}}
		if r := apiReq(t, h, http.MethodPost, base+"/review-choices", tenant, choice); r.Code != http.StatusNoContent {
			t.Fatalf("review create: %d %s", r.Code, r.Body.String())
		}
		finalized := apiReq(t, h, http.MethodPost, base+"/finalize-review", tenant,
			map[string]string{"context_id": routing.ContextID, "snapshot_hash": snapshotHash})
		var frozen struct {
			ReviewHash string `json:"review_hash"`
		}
		if finalized.Code != http.StatusOK || json.Unmarshal(finalized.Body.Bytes(), &frozen) != nil ||
			len(frozen.ReviewHash) != 64 {
			t.Fatalf("finalize create: %d %s", finalized.Code, finalized.Body.String())
		}
		return fixture{tenant, routing.ContextID, planID, snapshotHash, frozen.ReviewHash}
	}
	left, right := makeFixture(a, "Edge A"), makeFixture(b, "Edge B")
	apply := func(actor, contextID string, f fixture, hash string) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/"+f.planID+"/apply",
			actor, map[string]string{"context_id": contextID,
				"snapshot_hash": f.snapshotHash, "review_hash": hash})
	}
	if r := apply(a, left.contextID, right, right.reviewHash); r.Code != http.StatusNotFound {
		t.Fatalf("foreign plan applied: %d %s", r.Code, r.Body.String())
	}
	if r := apply(a, right.contextID, left, left.reviewHash); r.Code != http.StatusNotFound {
		t.Fatalf("foreign context applied: %d %s", r.Code, r.Body.String())
	}
	if r := apply(a, left.contextID, left, strings.Repeat("0", 64)); r.Code != http.StatusNotFound {
		t.Fatalf("wrong review hash applied: %d %s", r.Code, r.Body.String())
	}
	for _, f := range []fixture{left, right} {
		first := apply(f.tenant, f.contextID, f, f.reviewHash)
		var progress nmsimport.ApplyProgress
		if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &progress) != nil ||
			progress.State != "applied" || progress.Applied != 1 || progress.Remaining != 0 {
			t.Fatalf("tenant apply: %d %s", first.Code, first.Body.String())
		}
		retry := apply(f.tenant, f.contextID, f, f.reviewHash)
		if retry.Code != http.StatusOK || json.Unmarshal(retry.Body.Bytes(), &progress) != nil ||
			progress.Applied != 0 || progress.State != "applied" {
			t.Fatalf("idempotent apply: %d %s", retry.Code, retry.Body.String())
		}
	}
	for _, f := range []fixture{left, right} {
		var count int
		err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(f.tenant)),
			db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT count(*) FROM entities
					WHERE tenant_id=$1 AND context_id=$2 AND kind='device'`, f.tenant,
					f.contextID).Scan(&count)
			})
		if err != nil || count != 1 {
			t.Fatalf("tenant device count = %d, %v", count, err)
		}
	}
}
