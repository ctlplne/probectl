// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
)

type autotaskTestDoer func(*http.Request) (*http.Response, error)

func (f autotaskTestDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }

func autotaskTestResponse(t *testing.T, payload any) (*http.Response, error) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
}

const autotaskTestSettings = `{
  "username":"fixture-user", "api_secret":"fixture-value", "integration_code":"fixture-tracking",
  "company_id":7, "contract_id":4, "queue_id":8, "priority":2, "open_status":1, "resolved_status":5,
  "due_after":"48h", "progress_field":"probectl progress", "console_origin":"https://console.example.invalid"
}`

func autotaskTestConnector(t *testing.T, tenant string, client Doer) *autotask {
	t.Helper()
	provider, err := NewTenantConnector(tenant, "autotask", "https://psa.example.invalid/atservicesrest/v1.0", autotaskTestSettings, client)
	if err != nil {
		t.Fatal(err)
	}
	return provider.(*autotask)
}

func TestAutotaskTicketLifecycleUsesStableOwnedTicket(t *testing.T) {
	var stored autotaskTicketRecord
	var writes []autotaskTicketWrite
	const path = "/atservicesrest/v1.0/Tickets"
	probe := incident.Incident{
		TenantID: "left", ID: "20200000-0000-4000-8000-000000000001", Severity: incident.SeverityWarning,
		SignalCount: 3, LastSeenAt: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
	}
	client := autotaskTestDoer(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("UserName") != "fixture-user" || r.Header.Get("Secret") != "fixture-value" ||
			r.Header.Get("ApiIntegrationCode") != "fixture-tracking" {
			t.Fatal("missing documented Autotask authentication headers")
		}
		switch r.Method + " " + r.URL.Path {
		case http.MethodPost + " " + path + "/query":
			items := []autotaskTicketRecord{}
			if stored.ID != 0 {
				items = append(items, stored)
			}
			return autotaskTestResponse(t, map[string]any{"items": items})
		case http.MethodGet + " " + path + "/12":
			return autotaskTestResponse(t, map[string]any{"item": stored})
		case http.MethodPost + " " + path, http.MethodPatch + " " + path:
			var write autotaskTicketWrite
			if err := json.NewDecoder(r.Body).Decode(&write); err != nil {
				t.Fatal(err)
			}
			writes = append(writes, write)
			if r.Method == http.MethodPost {
				stored = autotaskTicketRecord{ID: 12, CompanyID: write.CompanyID, ContractID: write.ContractID, ExternalID: write.ExternalID}
			}
			return autotaskTestResponse(t, map[string]int64{"itemId": 12})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})
	provider := autotaskTestConnector(t, probe.TenantID, client)
	first, err := provider.Open(t.Context(), probe)
	if err != nil || first.ExternalRef != "12" {
		t.Fatalf("create = %+v, %v", first, err)
	}
	if retry, err := provider.Open(t.Context(), probe); err != nil || retry != first || len(writes) != 1 {
		t.Fatalf("retry = %+v, %v, %d writes", retry, err, len(writes))
	}
	create := writes[0]
	if create.CompanyID != 7 || create.ContractID != 4 || create.QueueID != 8 || create.Priority != 2 ||
		create.Status != 1 || create.Due == nil || len(create.ExternalID) > 50 ||
		!strings.Contains(create.Description, "https://console.example.invalid/ui/incidents?incident="+probe.ID) {
		t.Fatalf("incorrect native ticket mapping: %+v", create)
	}
	probe.SignalCount++
	for _, transition := range []struct {
		write func() error
		want  int64
	}{
		{func() error { return provider.Update(t.Context(), probe, first.ExternalRef) }, 0},
		{func() error { return provider.Resolve(t.Context(), probe, first.ExternalRef) }, 5},
		{func() error { return provider.Reopen(t.Context(), probe, first.ExternalRef) }, 1},
	} {
		if err := transition.write(); err != nil {
			t.Fatal(err)
		}
		write := writes[len(writes)-1]
		if write.ID != 12 || write.Status != transition.want || write.Description != "" || write.CompanyID != 0 ||
			len(write.Fields) != 1 || write.Fields[0].Name != "probectl progress" || !strings.HasPrefix(write.Fields[0].Value, "4 signals") {
			t.Fatalf("transition attempted to modify unrelated ticket fields: %+v", write)
		}
	}
	stored.Status = 5
	snapshot := TicketStatusSnapshot{
		TenantID: probe.TenantID, Connector: "autotask", IncidentID: probe.ID,
		ExternalRef: first.ExternalRef, IncidentVersion: "31", LinkVersion: "35",
	}
	resolved, err := provider.ResolvedTickets(t.Context(), []TicketStatusSnapshot{snapshot})
	if err != nil || len(resolved) != 1 || resolved[0] != snapshot {
		t.Fatalf("resolved tickets = %+v, %v, want the original local snapshot", resolved, err)
	}
	stored.ExternalID = "another-owner"
	if resolved, err := provider.ResolvedTickets(t.Context(), []TicketStatusSnapshot{snapshot}); err == nil || len(resolved) != 0 {
		t.Fatal("a vendor status from a different ownership key reached the local result")
	}
	t.Run("foreign ticket binding", assertAutotaskRejectsForeignTicket)
}

func assertAutotaskRejectsForeignTicket(t *testing.T) {
	t.Helper()
	first := incident.Incident{TenantID: "left", ID: "20200000-0000-4000-8000-000000000001"}
	second := first
	second.TenantID = "right"
	var foreign autotaskTicketRecord
	var reads int
	client := autotaskTestDoer(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("foreign ticket reached a vendor write: %s", r.Method)
		}
		reads++
		return autotaskTestResponse(t, map[string]any{"item": foreign})
	})
	a := autotaskTestConnector(t, first.TenantID, client)
	b := autotaskTestConnector(t, second.TenantID, client)
	foreignSettings := strings.Replace(autotaskTestSettings, "{", `{"tenant_id":"left",`, 1)
	if _, err := NewTenantConnector(second.TenantID, "autotask", "https://psa.example.invalid/atservicesrest/v1.0", foreignSettings, client); err == nil || strings.Contains(err.Error(), "fixture-value") {
		t.Fatal("connector settings could override tenant identity or disclose credentials")
	}
	keyA, errA := a.incidentKey(first)
	keyB, errB := b.incidentKey(second)
	if errA != nil || errB != nil || keyA == keyB {
		t.Fatal("different tenants must have separate external references even in the same PSA company")
	}
	foreign = autotaskTicketRecord{ID: 12, CompanyID: 7, ContractID: 4, ExternalID: keyA}
	if _, err := b.Open(t.Context(), first); err == nil || reads != 0 {
		t.Fatal("wrong incident tenant reached the vendor")
	}
	if err := b.Resolve(t.Context(), second, "12"); err == nil || reads != 1 {
		t.Fatal("wrong external reference was accepted in a shared company")
	}
}
