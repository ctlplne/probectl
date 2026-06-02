//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/store"
)

// aiAnswer mirrors the /v1/ai/ask response for assertions.
type aiAnswer struct {
	ID                   string `json:"id"`
	RootCause            string `json:"root_cause"`
	InsufficientEvidence bool   `json:"insufficient_evidence"`
	Evidence             []struct {
		ID string `json:"id"`
	} `json:"evidence"`
	Findings []struct {
		Citations []struct {
			EvidenceID string `json:"evidence_id"`
		} `json:"citations"`
	} `json:"findings"`
}

// End-to-end RCA against Postgres (S24 Done-when): a critical BGP incident for
// tenant A becomes cited evidence in a grounded answer; every finding resolves to
// real evidence (citation integrity); feedback persists; and tenant B — with no
// such incident — gets an insufficient-evidence answer, proving the assistant is
// tenant-scoped via the S23 boundary (it never sees another tenant's signals).
func TestAIAskGroundedCitedAndTenantScoped(t *testing.T) {
	h, db := setupAPI(t)
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	ctx := context.Background()
	// A fresh tenant isolates this test's incident from the shared integration DB
	// (the default tenant's incidents are asserted on by TestIncidentCorrelationAndAPI).
	tnA, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("aimain-%d", time.Now().UnixNano()), "AI Main")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tenant := tnA.ID
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "possible hijack 192.0.2.0/24", Target: "192.0.2.0/24", Prefix: "192.0.2.0/24", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Tenant A: a grounded, cited root cause naming the routing event.
	rec := apiReq(t, h, http.MethodPost, "/v1/ai/ask", tenant, map[string]any{
		"question": "why is 192.0.2.0/24 unreachable? any routing changes?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("ask: status %d body %s", rec.Code, rec.Body)
	}
	var ans aiAnswer
	mustJSON(t, rec, &ans)
	if ans.InsufficientEvidence || len(ans.Evidence) == 0 {
		t.Fatalf("expected a grounded answer, got %+v", ans)
	}
	if !strings.Contains(strings.ToLower(ans.RootCause), "hijack") {
		t.Errorf("root cause should name the routing signal, got %q", ans.RootCause)
	}
	ids := map[string]bool{}
	for _, e := range ans.Evidence {
		ids[e.ID] = true
	}
	for _, f := range ans.Findings {
		for _, cit := range f.Citations {
			if !ids[cit.EvidenceID] {
				t.Errorf("finding cites missing evidence %q (citation integrity)", cit.EvidenceID)
			}
		}
	}

	// Feedback persists, tenant-scoped → 204.
	if rec := apiReq(t, h, http.MethodPost, "/v1/ai/feedback", tenant, map[string]any{
		"answer_id": ans.ID, "rating": "up", "comment": "spot on",
	}); rec.Code != http.StatusNoContent {
		t.Errorf("feedback: status %d body %s", rec.Code, rec.Body)
	}

	// Tenant B has no such incident → insufficient evidence (tenant isolation:
	// the assistant cannot see tenant A's signals).
	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("aiiso-%d", time.Now().UnixNano()), "AI Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	rec = apiReq(t, h, http.MethodPost, "/v1/ai/ask", tn.ID, map[string]any{
		"question": "why is 192.0.2.0/24 unreachable? any routing changes?",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant B ask: status %d body %s", rec.Code, rec.Body)
	}
	var bAns aiAnswer
	mustJSON(t, rec, &bAns)
	if !bAns.InsufficientEvidence || len(bAns.Evidence) != 0 {
		t.Errorf("tenant B must not see tenant A's incident; got %+v", bAns)
	}
}
