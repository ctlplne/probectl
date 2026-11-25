// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestCustomerChatNotificationsKeepTheirFixedAttributionSeparate(t *testing.T) {
	const customer = "Northstar [network](https://brand.example.test)"
	brand := branding.Branding{Customer: &branding.CustomerIdentity{Name: customer}}
	ctx := branding.WithOutput(t.Context(), brand)
	inc := incident.Incident{ID: "one", TenantID: "northstar", Title: "Network loss"}
	for _, vendor := range []string{"slack", "teams"} {
		t.Run(vendor, func(t *testing.T) {
			doer := &fakeDoer{}
			chat := newChat(vendor, "https://hooks.example.test", doer)
			if _, err := chat.Open(ctx, inc); err != nil {
				t.Fatal(err)
			}
			if err := chat.Resolve(ctx, inc, "one"); err != nil {
				t.Fatal(err)
			}
			calls := doer.calls()
			if len(calls) != 2 {
				t.Fatalf("expected an open and a resolve notification, got %d", len(calls))
			}
			for _, call := range calls {
				if !bytes.Contains(call.body, []byte(customer)) ||
					!bytes.Contains(call.body, []byte("Powered by probectl")) ||
					!bytes.Contains(call.body, []byte("https://probectl.com")) {
					t.Fatal("customer chat lost its brand or fixed attribution")
				}
				payload := bodyJSON(t, call.body)
				if vendor == "slack" && payload["blocks"] == nil {
					t.Fatal("Slack mixed the badge with customer-controlled markdown")
				}
				if vendor == "teams" {
					assertTeamsCustomerBranding(t, call.body, customer)
				}
			}
		})
	}
}

func assertTeamsCustomerBranding(t *testing.T, raw []byte, customer string) {
	t.Helper()
	var payload struct {
		Attachments []struct {
			Content struct {
				Body []struct {
					Type    string
					Text    string
					Inlines []struct {
						Type         string
						Text         string
						SelectAction json.RawMessage
					}
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Attachments) != 1 || len(payload.Attachments[0].Content.Body) != 2 {
		t.Fatal("Teams must render the notification and attribution as separate card blocks")
	}
	body := payload.Attachments[0].Content.Body
	if body[0].Type != "RichTextBlock" || len(body[0].Inlines) != 1 || body[0].Inlines[0].Type != "TextRun" ||
		!strings.Contains(body[0].Inlines[0].Text, customer) || len(body[0].Inlines[0].SelectAction) != 0 {
		t.Fatal("Teams customer text must render literally without a configurable link")
	}
	if body[1].Type != "TextBlock" || body[1].Text != "[Powered by probectl](https://probectl.com)" {
		t.Fatal("Teams lost the fixed probectl link")
	}
}

func TestCustomerNotificationRecoveryKeepsTwoTenantBrandsSeparate(t *testing.T) {
	store := newMemStore()
	names := map[string]string{"north": "Northstar", "south": "Southwind"}
	d := NewDispatcher(store, quiet()).WithBranding(func(_ context.Context, tenant string) branding.Branding {
		return branding.Branding{Customer: &branding.CustomerIdentity{Name: names[tenant]}}
	})
	destinations := make(map[string]*fakeDoer)
	for tenant := range names {
		destination := &fakeDoer{respond: func(_, _ string, _ []byte) (int, string) {
			return http.StatusOK, `{"external_ref":"same-ticket"}`
		}}
		destinations[tenant] = destination
		d.Register(tenant, newPSA("https://psa.example.test/tickets", "test-signing-key", destination))
		store.setIncidents(tenant, incident.Incident{ID: "same-id", TenantID: tenant, Status: incident.StatusOpen})
	}
	d.Reconcile(t.Context())
	for tenant := range names {
		store.setIncidents(tenant, incident.Incident{ID: "same-id", TenantID: tenant, Status: incident.StatusResolved})
	}
	d.Reconcile(t.Context())
	for tenant, destination := range destinations {
		calls := destination.calls()
		if len(calls) != 2 {
			t.Fatalf("%s: expected exactly two deliveries, got %d", tenant, len(calls))
		}
		for i, action := range []string{"create", "resolve"} {
			var event psaEvent
			if err := json.Unmarshal(calls[i].body, &event); err != nil {
				t.Fatal(err)
			}
			if event.Action != action || event.Ticket.ExternalKey != "same-id" ||
				!strings.HasPrefix(event.Ticket.Evidence, names[tenant]+"\nPowered by probectl (https://probectl.com)\n") {
				t.Fatalf("%s: recovered %s lost its own brand or fixed attribution: %+v", tenant, action, event.Ticket)
			}
		}
	}
	store.setIncidents("south", incident.Incident{ID: "foreign-row", TenantID: "north", Status: incident.StatusOpen})
	d.Reconcile(t.Context())
	for tenant, destination := range destinations {
		if count := len(destination.calls()); count != 2 {
			t.Fatalf("%s: a row from another tenant reached a connector, got %d deliveries", tenant, count)
		}
	}
}
