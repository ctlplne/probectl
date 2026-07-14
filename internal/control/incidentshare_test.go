// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
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
