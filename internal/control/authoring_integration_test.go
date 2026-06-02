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

type discoverResp struct {
	Proposals []struct {
		Spec struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"spec"`
	} `json:"proposals"`
}

// End-to-end S26 against Postgres: discovery proposes a monitorable target seen in
// an incident but not yet tested, ranked + deduped against existing tests; and NL
// authoring yields a schema-valid config — all pending confirmation, none created.
func TestAuthoringDiscoverAndAuthor(t *testing.T) {
	h, db := setupAPI(t)
	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	ctx := context.Background()
	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("author-%d", time.Now().UnixNano()), "Authoring")
	if err != nil {
		t.Fatal(err)
	}
	tenant := tn.ID
	now := time.Now().UTC().Truncate(time.Second)

	// A monitorable target seen in an incident, with no test yet.
	if _, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "network", Kind: "alert.firing", Severity: incident.SeverityWarning,
		Title: "high latency to shop", Target: "shop.example.com", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// A target that IS already monitored → must be deduped out of discovery.
	if rec := apiReq(t, h, http.MethodPost, "/v1/tests", tenant, map[string]any{
		"name": "quad9", "type": "icmp", "target": "9.9.9.9",
	}); rec.Code != http.StatusCreated {
		t.Fatalf("create test: %d %s", rec.Code, rec.Body)
	}
	if _, err := c.Ingest(ctx, incident.Signal{
		TenantID: tenant, Plane: "network", Kind: "alert.firing", Severity: incident.SeverityInfo,
		Title: "blip", Target: "9.9.9.9", OccurredAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Discover proposes shop (HTTP) but not the already-monitored 9.9.9.9.
	rec := apiReq(t, h, http.MethodPost, "/v1/ai/discover", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body)
	}
	var disc discoverResp
	mustJSON(t, rec, &disc)
	var sawShop bool
	for _, p := range disc.Proposals {
		if strings.Contains(p.Spec.Target, "shop.example.com") {
			sawShop = true
			if p.Spec.Type != "http" {
				t.Errorf("shop should be an http proposal, got %s", p.Spec.Type)
			}
		}
		if strings.Contains(p.Spec.Target, "9.9.9.9") {
			t.Errorf("an already-monitored target must be deduped, got %+v", p.Spec)
		}
	}
	if !sawShop {
		t.Errorf("discovery should propose shop.example.com, got %+v", disc.Proposals)
	}

	// Author: NL → a schema-valid proposal (never created).
	rec = apiReq(t, h, http.MethodPost, "/v1/ai/author", tenant, map[string]any{"prompt": "ping 9.9.9.9 from every site"})
	if rec.Code != http.StatusOK {
		t.Fatalf("author: %d %s", rec.Code, rec.Body)
	}
	var prop struct {
		Spec struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"spec"`
	}
	mustJSON(t, rec, &prop)
	if prop.Spec.Type != "icmp" || prop.Spec.Target != "9.9.9.9" {
		t.Errorf("author proposal = %+v", prop.Spec)
	}
}
