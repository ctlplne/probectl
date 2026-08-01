// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func TestIncidentShareArtifactRedactsSecretsAndTenant(t *testing.T) {
	inc := incident.Incident{
		ID: "inc-1", TenantID: "tenant-secret", Title: "failure password=hunter22 at 10.0.0.1",
		Target: "10.0.0.1", StartedAt: time.Now().Add(-time.Minute), LastSeenAt: time.Now(),
		Signals: []incident.Signal{{
			TenantID: "tenant-secret", Title: "Authorization: Bearer raw-token", Summary: "api_key=secret-value",
			Target: "10.0.0.1", Attributes: map[string]string{
				"owner": "alice@example.com", "password": "hunter22", "tenant_id": "tenant-secret",
			},
		}},
	}
	redacted := redactIncidentForShare(inc, ai.RedactionPolicy{MaskIPs: true, MaskPII: true, TokenKey: []byte("01234567890123456789012345678901")}, inc.TenantID)
	b, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, forbidden := range []string{"tenant-secret", "hunter22", "raw-token", "secret-value", "10.0.0.1", "alice@example.com"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("redacted share contains %q: %s", forbidden, body)
		}
	}
}

func TestIncidentShareAnswerRedactsPlanAndNestedEvidenceSecrets(t *testing.T) {
	answer := ai.Answer{
		Question: "why did 10.0.0.1 fail?",
		InvestigationPlan: []ai.InvestigationStep{{
			Goal: "inspect alice@example.com", NodeID: "10.0.0.1",
			Selector: map[string]string{"target": "10.0.0.1", "password": "hunter22"},
		}},
		Evidence: []ai.Evidence{{Fields: ai.Row{
			"api_key": "raw-token",
			"tenant":  "tenant-a",
			"nested":  map[string]any{"credential": "secret-value", "owner": "alice@example.com"},
		}}},
	}
	redacted := redactAnswerForShare(answer, ai.RedactionPolicy{
		MaskIPs: true, MaskPII: true, TokenKey: []byte("01234567890123456789012345678901"),
	}, "tenant-a")
	body, err := json.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"tenant-a", "10.0.0.1", "hunter22", "raw-token", "secret-value", "alice@example.com"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("redacted answer contains %q: %s", forbidden, body)
		}
	}
}

func TestIncidentShareContextRejectsTenantSelector(t *testing.T) {
	inc := incident.Incident{StartedAt: time.Now().Add(-time.Minute), LastSeenAt: time.Now()}
	_, err := validatedShareContext(incidentShareContext{Filters: map[string]string{"tenant_id": "other"}}, inc, ai.DefaultRedaction, "tenant-a")
	if err == nil {
		t.Fatal("tenant selector in a share context must fail closed")
	}
}

func TestIncidentShareSelectionRequiresAuthorizedArtifactEvidence(t *testing.T) {
	inc := incident.Incident{ID: "inc-1", Signals: []incident.Signal{{Title: "one"}}}
	answer := ai.Answer{Evidence: []ai.Evidence{{ID: "E-real", Fields: ai.Row{"id": "inc-1:0"}}}}

	if got := authorizedShareSelection(&incidentShareSelection{Kind: "evidence", ID: "cross-tenant-evidence"}, inc, answer); got != nil {
		t.Fatalf("unauthorized evidence selection survived: %+v", got)
	}
	if got := authorizedShareSelection(&incidentShareSelection{Kind: "evidence", ID: "inc-1:0"}, inc, answer); got == nil {
		t.Fatal("authorized incident signal selection was removed")
	}
}

func TestIncidentShareABAC(t *testing.T) {
	const tenantID = "00000000-0000-0000-0000-0000000000f1"
	principal := &auth.Principal{
		TenantID: tenantID,
		UserID:   "share-contractor",
		Permissions: map[string]bool{
			permIncidentRead: true,
			permAIQuery:      true,
		},
		Attributes: map[string]string{"department": "contractor"},
	}
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/incidents/inc-1/shares",
			strings.NewReader(`{"context":{}}`))
		req.SetPathValue("id", "inc-1")
		return req.WithContext(auth.WithPrincipal(req.Context(), principal))
	}

	t.Run("deny overrides RBAC before evidence access", func(t *testing.T) {
		cache := newClosedABACCache(t)
		cache.data[tenantID] = abacEntry{
			policies: []auth.Policy{{
				Name:       "deny contractor AI evidence",
				Effect:     auth.PolicyDeny,
				Permission: permAIQuery,
				Subject:    map[string]string{"department": "contractor"},
				Priority:   100,
				Enabled:    true,
			}},
			expiry: time.Now().Add(time.Hour),
		}
		srv := testServer(nil)
		srv.pool = cache.pool // non-nil; an authorized path would attempt storage.
		srv.abac = cache

		err := srv.handleCreateIncidentShare(httptest.NewRecorder(), request())
		domainErr, ok := apierror.As(err)
		if !ok || domainErr.Kind != apierror.KindForbidden {
			t.Fatalf("ABAC-denied incident share = %v, want forbidden before storage", err)
		}
	})

	t.Run("policy load failure fails closed", func(t *testing.T) {
		cache := newClosedABACCache(t)
		srv := testServer(nil)
		srv.pool = cache.pool
		srv.abac = cache

		err := srv.handleCreateIncidentShare(httptest.NewRecorder(), request())
		domainErr, ok := apierror.As(err)
		if !ok || domainErr.Kind != apierror.KindUnavailable {
			t.Fatalf("incident-share policy load failure = %v, want unavailable", err)
		}
	})
}

func TestIncidentShareExpiryHonorsObjectRetention(t *testing.T) {
	oneDay := 1
	srv := testServer(nil)
	srv.tenantLife = &fakeTenantLifecycle{policy: tenantlife.RetentionPolicy{ObjectRetentionDays: &oneDay}}
	expires, err := srv.incidentShareExpiry(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	remaining := time.Until(expires)
	if remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Fatalf("expiry remaining = %s, want tenant retention cap near 24h", remaining)
	}
}
