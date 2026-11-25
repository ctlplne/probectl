// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
)

const haloTestSettings = `{
  "client_id":"fixture-id", "client_secret":"fixture-value+&",
  "customer_id":7, "contract_id":4, "site_id":13, "user_id":14, "ticket_type_id":8,
  "priority_id":2, "open_status":1, "resolved_status":5, "progress_field_id":23,
  "due_after":"48h", "console_origin":"https://console.example.invalid"
}`

func TestHaloPSATicketLifecycle(t *testing.T) {
	inc := incident.Incident{TenantID: "left", ID: "20200000-0000-4000-8000-000000000001",
		Severity: incident.SeverityWarning, SignalCount: 3, LastSeenAt: time.Now()}
	const endpoint = "/api/Tickets"
	var tokenCalls int
	var ticket haloTicket
	var writes []haloTicketWrite
	var contractClient int32 = 7
	fake := autotaskTestDoer(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == "/auth/token" {
			tokenCalls++
			if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
				r.ParseForm() != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
				r.PostForm.Get("client_id") != "fixture-id" || r.PostForm.Get("client_secret") != "fixture-value+&" ||
				r.PostForm.Get("scope") != "all" {
				t.Fatal("unexpected OAuth request")
			}
			return autotaskTestResponse(t, map[string]any{"access_token": "fixture.token", "token_type": "Bearer", "expires_in": 3600})
		}
		if r.Header.Get("Authorization") != "Bearer fixture.token" {
			t.Fatal("ticket API used the wrong bearer token")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/ClientContract/4":
			return autotaskTestResponse(t, map[string]int32{"id": 4, "client_id": contractClient})
		case "GET " + endpoint:
			q := r.URL.Query()
			if q.Get("client_id") != "7" || q.Get("ticketcontract_id") != "4" || q.Get("pageinate") != "true" {
				t.Fatal("ticket search omitted company, contract or pagination")
			}
			switch {
			case q.Get("third_party_id_string") == "" && (q.Get("ticketids") != "12" || q.Get("status_id") != "5"):
				t.Fatal("status lookup omitted the requested ticket or state")
			case q.Get("third_party_id_string") != "" && !strings.HasPrefix(q.Get("third_party_id_string"), "pbctl-"):
				t.Fatal("recovery search omitted the stable ticket key")
			}
			items := []haloTicket{}
			if ticket.ID > 0 && (q.Get("status_id") == "" || ticket.Status == 5) {
				projection := ticket
				projection.ContractID = 0 // Halo's list projection omits this field.
				items = append(items, projection)
			}
			return autotaskTestResponse(t, map[string]any{"record_count": len(items), "tickets": items})
		case "GET " + endpoint + "/12":
			return autotaskTestResponse(t, ticket)
		case "POST " + endpoint:
			var batch []haloTicketWrite
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil || len(batch) != 1 {
				t.Fatalf("unexpected ticket request array: %+v, %v", batch, err)
			}
			write := batch[0]
			writes = append(writes, write)
			if write.ID == 0 {
				ticket = haloTicket{ID: 12, ClientID: write.ClientID, ContractID: write.ContractID, ThirdPartyID: write.ThirdPartyID}
			}
			if write.Status != 0 {
				ticket.Status = write.Status
			}
			return autotaskTestResponse(t, ticket)
		default:
			t.Fatalf("unexpected Halo request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})
	provider, err := NewTenantConnector(inc.TenantID, "halopsa", "https://halo.example.invalid", haloTestSettings, fake)
	if err != nil {
		t.Fatal(err)
	}
	halo := provider.(*haloPSA)
	contractClient = 99
	if _, err := halo.Open(t.Context(), inc); !errors.Is(err, errTicketCreateRejected) || len(writes) != 0 {
		t.Fatal("a contract from another company allowed a create", err)
	}
	contractClient = 7
	first, err := halo.Open(t.Context(), inc)
	if err != nil || first.ExternalRef != "12" || len(writes) != 1 {
		t.Fatalf("create = %+v, %v, writes = %d", first, err, len(writes))
	}
	created := writes[0]
	if created.ClientID != 7 || created.ContractID != 4 || created.SiteID != 13 || created.UserID != 14 ||
		created.TicketType != 8 || created.Priority != 2 || created.Status != 1 || created.TargetDate == nil ||
		!strings.Contains(created.Details, "https://console.example.invalid/ui/incidents?incident="+inc.ID) {
		t.Fatalf("wrong create mapping: %+v", created)
	}
	if retry, err := halo.Open(t.Context(), inc); err != nil || retry != first || len(writes) != 1 {
		t.Fatalf("repeated open = %+v, %v, writes = %d", retry, err, len(writes))
	}
	inc.SignalCount++
	for _, step := range []struct {
		write func() error
		want  int32
	}{
		{func() error { return halo.Update(t.Context(), inc, first.ExternalRef) }, 0},
		{func() error { return halo.Reopen(t.Context(), inc, first.ExternalRef) }, 1},
		{func() error { return halo.Resolve(t.Context(), inc, first.ExternalRef) }, 5},
	} {
		if err := step.write(); err != nil {
			t.Fatal(err)
		}
		update := writes[len(writes)-1]
		if update.ID != 12 || update.Status != step.want || update.ClientID != 0 || update.Details != "" ||
			len(update.Fields) != 1 || update.Fields[0].ID != 23 || !strings.HasPrefix(update.Fields[0].Value, "4 signals") {
			t.Fatalf("unexpected ticket update: %+v", update)
		}
	}
	snapshot := TicketStatusSnapshot{TenantID: inc.TenantID, IncidentID: inc.ID, Connector: "halopsa",
		ExternalRef: first.ExternalRef, IncidentVersion: "101", LinkVersion: "103"}
	if resolved, err := halo.ResolvedTickets(t.Context(), []TicketStatusSnapshot{snapshot}); err != nil || len(resolved) != 1 || resolved[0] != snapshot {
		t.Fatalf("resolved snapshots = %+v, %v", resolved, err)
	}
	ticket.ContractID = 99
	if resolved, err := halo.ResolvedTickets(t.Context(), []TicketStatusSnapshot{snapshot}); err == nil || len(resolved) != 0 {
		t.Fatal("status from an unbound contract reached the incident")
	}
	if err := halo.Resolve(t.Context(), inc, first.ExternalRef); err == nil || tokenCalls != 1 || len(writes) != 4 {
		t.Fatal("a foreign contract permitted an update, or the token cache was lost", err)
	}
	t.Run("OAuth rejects unsafe responses", assertHaloOAuthRejectsUnsafeResponses)
}

func assertHaloOAuthRejectsUnsafeResponses(t *testing.T) {
	var redirected atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			http.Redirect(w, r, "/collect", http.StatusTemporaryRedirect)
			return
		}
		redirected.Add(1)
	}))
	t.Cleanup(receiver.Close)
	provider, err := configuredHaloPSA("left", receiver.URL, haloTestSettings, receiver.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.api.auth.headers(t.Context()); err == nil || redirected.Load() != 0 ||
		strings.Contains(err.Error(), "fixture-value") {
		t.Fatal("token exchange followed a redirect or exposed its credentials", err)
	}

	token := autotaskTestDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(
			`{"access_token":"fixture.token","token_type":"Bearer","expires_in":9223372036854775807}`))}, nil
	})
	provider, err = configuredHaloPSA("left", "https://halo.example.invalid", haloTestSettings, token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.api.auth.headers(t.Context()); err == nil || provider.api.auth.token != "" {
		t.Fatal("an overflowing lifetime populated the token cache")
	}
}
