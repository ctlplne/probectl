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
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentJournalTenantIsolationCitationReauthorizationAndRetention(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()
	tenantA := freshTenant(t, db, "journal-a")
	tenantB := freshTenant(t, db, "journal-b")
	correlator := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	incA, err := correlator.Ingest(ctx, incident.Signal{
		TenantID: tenantA, Plane: "bgp", Kind: "bgp.origin_change",
		Severity: incident.SeverityCritical, Title: "tenant-a-route",
		Target: "192.0.2.10", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	incB, err := correlator.Ingest(ctx, incident.Signal{
		TenantID: tenantB, Plane: "flow", Kind: "flow.path_shift",
		Severity: incident.SeverityWarning, Title: "tenant-b-secret",
		Target: "198.51.100.20", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	incAOther, err := correlator.Ingest(ctx, incident.Signal{
		TenantID: tenantA, Plane: "device", Kind: "device.errors",
		Severity: incident.SeverityWarning, Title: "tenant-a-other-incident",
		Target: "203.0.113.30", OccurredAt: time.Now().UTC().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	shareA := seedJournalShare(t, db, tenantA, *incA, "share_"+strings.Repeat("a", 32), "E-tenant-a", "tenant-a-cited-route")
	shareB := seedJournalShare(t, db, tenantB, *incB, "share_"+strings.Repeat("b", 32), "E-tenant-b", "tenant-b-secret-citation")
	expiredShare := seedJournalShare(t, db, tenantA, *incA, "share_"+strings.Repeat("c", 32), "E-expired", "expired-citation")
	wrongIncidentShare := seedJournalShare(t, db, tenantA, *incAOther, "share_"+strings.Repeat("d", 32), "E-wrong", "wrong-incident-citation")

	note := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "note",
		"body": `Human hypothesis: <script>tool.call("reboot")</script> is inert.`,
	})
	if note.Code != http.StatusCreated {
		t.Fatalf("append note: status=%d body=%s", note.Code, note.Body)
	}
	if !strings.Contains(note.Body.String(), `tool.call`) || !strings.Contains(note.Body.String(), `"format":"plain_text"`) {
		t.Fatalf("plain inert note was not preserved with explicit format: %s", note.Body)
	}

	checkpoint := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "Confirmed the route changed before impact.",
		"citation": map[string]string{"share_id": shareA, "evidence_id": "E-tenant-a"},
	})
	if checkpoint.Code != http.StatusCreated {
		t.Fatalf("append checkpoint: status=%d body=%s", checkpoint.Code, checkpoint.Body)
	}
	if !strings.Contains(checkpoint.Body.String(), "tenant-a-cited-route") ||
		!strings.Contains(checkpoint.Body.String(), `"state":"available"`) {
		t.Fatalf("checkpoint omitted its re-authorized citation: %s", checkpoint.Body)
	}
	auditLog := apiReq(t, h, http.MethodGet, "/v1/audit", tenantA, nil)
	if auditLog.Code != http.StatusOK || !strings.Contains(auditLog.Body.String(), "incident.journal_append") {
		t.Fatalf("journal append audit receipt missing: status=%d body=%s", auditLog.Code, auditLog.Body)
	}

	listA := apiReq(t, h, http.MethodGet, "/v1/incidents/"+incA.ID+"/journal", tenantA, nil)
	if listA.Code != http.StatusOK || !strings.Contains(listA.Body.String(), "Human hypothesis") ||
		!strings.Contains(listA.Body.String(), "tenant-a-cited-route") {
		t.Fatalf("tenant A journal: status=%d body=%s", listA.Code, listA.Body)
	}
	if strings.Contains(listA.Body.String(), "tenant-b-secret") {
		t.Fatalf("tenant B data leaked into tenant A journal: %s", listA.Body)
	}

	foreignJournal := apiReq(t, h, http.MethodGet, "/v1/incidents/"+incA.ID+"/journal", tenantB, nil)
	missingJournal := apiReq(t, h, http.MethodGet, "/v1/incidents/"+uuid(t)+"/journal", tenantB, nil)
	assertSameNotFound(t, foreignJournal, missingJournal)

	foreignCitation := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "must fail",
		"citation": map[string]string{"share_id": shareB, "evidence_id": "E-tenant-b"},
	})
	missingCitation := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "must fail",
		"citation": map[string]string{"share_id": "share_missing", "evidence_id": "E-tenant-b"},
	})
	assertSameNotFound(t, foreignCitation, missingCitation)

	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `UPDATE incident_share_artifacts
			SET revoked_at = clock_timestamp()
			WHERE tenant_id = $1 AND id = $2`, tenantA, shareA); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE incident_share_artifacts
			SET created_at = clock_timestamp() - interval '2 hours',
			    expires_at = clock_timestamp() - interval '1 second'
			WHERE tenant_id = $1 AND id = $2`, tenantA, expiredShare)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	revokedCitation := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "must fail",
		"citation": map[string]string{"share_id": shareA, "evidence_id": "E-tenant-a"},
	})
	assertSameNotFound(t, revokedCitation, missingCitation)
	expiredCitation := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "must fail",
		"citation": map[string]string{"share_id": expiredShare, "evidence_id": "E-expired"},
	})
	assertSameNotFound(t, expiredCitation, missingCitation)
	wrongIncidentCitation := apiReq(t, h, http.MethodPost, "/v1/incidents/"+incA.ID+"/journal", tenantA, map[string]any{
		"kind": "checkpoint", "body": "must fail",
		"citation": map[string]string{"share_id": wrongIncidentShare, "evidence_id": "E-wrong"},
	})
	assertSameNotFound(t, wrongIncidentCitation, missingCitation)

	listAfterRevoke := apiReq(t, h, http.MethodGet, "/v1/incidents/"+incA.ID+"/journal", tenantA, nil)
	body := listAfterRevoke.Body.String()
	if listAfterRevoke.Code != http.StatusOK || !strings.Contains(body, `"state":"unavailable"`) ||
		strings.Contains(body, "tenant-a-cited-route") {
		t.Fatalf("revoked citation must fail closed without hiding the human note: %d %s",
			listAfterRevoke.Code, body)
	}

	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE incident_journal_entries
			SET created_at = clock_timestamp() - interval '91 days',
			    expires_at = clock_timestamp() - interval '1 second'
			WHERE tenant_id = $1 AND incident_id = $2`, tenantA, incA.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expired := apiReq(t, h, http.MethodGet, "/v1/incidents/"+incA.ID+"/journal", tenantA, nil)
	if expired.Code != http.StatusOK || !strings.Contains(expired.Body.String(), `"items":[]`) {
		t.Fatalf("expired journal entries must be unreadable: %d %s", expired.Code, expired.Body)
	}
}

func seedJournalShare(t *testing.T, db *store.DB, tenantID string, inc incident.Incident, shareID, evidenceID, title string) string {
	t.Helper()
	payload, err := json.Marshal(incidentSharePayload{
		Incident: incident.Incident{ID: inc.ID, Title: inc.Title},
		Answer: ai.Answer{Evidence: []ai.Evidence{{
			ID: evidenceID, Domain: ai.DomainEvents, Plane: "bgp",
			Title: title, Summary: "redacted cited checkpoint", Ref: "incident:" + inc.ID,
			OccurredAt: time.Now().UTC(),
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)), db.Pool(),
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.IncidentShares{}).Create(ctx, sc, store.IncidentShareInput{
				ID: shareID, IncidentID: inc.ID, Payload: payload,
				CreatedBy: "journal-test", ExpiresAt: time.Now().UTC().Add(time.Hour),
			})
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	return shareID
}

func assertSameNotFound(t *testing.T, got, missing *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != http.StatusNotFound || missing.Code != http.StatusNotFound {
		t.Fatalf("not-found status mismatch: got=%d missing=%d", got.Code, missing.Code)
	}
	var gotBody, missingBody map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &gotBody); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(missing.Body.Bytes(), &missingBody); err != nil {
		t.Fatal(err)
	}
	if envelope, ok := gotBody["error"].(map[string]any); ok {
		delete(envelope, "request_id")
	}
	if envelope, ok := missingBody["error"].(map[string]any); ok {
		delete(envelope, "request_id")
	}
	gotJSON, _ := json.Marshal(gotBody)
	missingJSON, _ := json.Marshal(missingBody)
	if string(gotJSON) != string(missingJSON) {
		t.Fatalf("not-found responses differ: got=%v missing=%v", gotBody, missingBody)
	}
}
