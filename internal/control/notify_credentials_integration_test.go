// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFailedWebhookLogsKeepTwoTenantCredentialsPrivate(t *testing.T) {
	const alphaPath, alphaSignature = "/workflow/alpha-fixture-hook", "alpha-fixture-signature"
	const betaPath, betaSignature = "/workflow/beta-fixture-hook", "beta-fixture-signature"
	var alphaCalls, betaCalls, incorrectCalls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" ||
			!bytes.Contains(body, []byte(`"contentType":"application/vnd.microsoft.card.adaptive"`)) {
			incorrectCalls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == alphaPath && r.URL.Query().Get("sig") == alphaSignature && bytes.Contains(body, []byte("alpha-link")):
			alphaCalls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.Path == betaPath && r.URL.Query().Get("sig") == betaSignature && bytes.Contains(body, []byte("beta-link")):
			betaCalls.Add(1)
			w.WriteHeader(http.StatusAccepted)
		default:
			incorrectCalls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(receiver.Close)
	db := changeDB(t)
	alpha, beta := freshTenant(t, db, "notify-alpha"), freshTenant(t, db, "notify-beta")
	links := pgLinkStore{pool: db.Pool()}
	var logData bytes.Buffer
	dispatcher := notify.NewDispatcher(links, slog.New(slog.NewJSONHandler(&logData, nil)))
	for _, route := range []struct{ tenant, path, signature string }{{alpha, alphaPath, alphaSignature}, {beta, betaPath, betaSignature}} {
		connector, ok := notify.NewConnector("teams", receiver.URL+route.path+"?sig="+route.signature, "", receiver.Client())
		if !ok {
			t.Fatal("could not configure Teams fixture")
		}
		dispatcher.Register(route.tenant, connector)
	}
	first := openIncidentVia(t, db, dispatcher, alpha, "alpha-link")
	second := openIncidentVia(t, db, dispatcher, beta, "beta-link")
	good, err := links.Get(t.Context(), beta, second.ID, "teams")
	if err != nil || good == nil || good.TenantID != beta {
		t.Fatal("the successful delivery failed to persist its tenant link")
	}
	for _, id := range []string{first.ID, second.ID} {
		bad, err := links.Get(t.Context(), alpha, id, "teams")
		if err != nil || bad != nil {
			t.Fatal("the failed delivery acquired a link or saw the other tenant's link")
		}
	}
	if alphaCalls.Load() < 2 || betaCalls.Load() != 1 || incorrectCalls.Load() != 0 {
		t.Fatal("the receiver did not observe retries and a separate successful tenant delivery")
	}
	logs := logData.String()
	if !strings.Contains(logs, "returned HTTP 503") || strings.Contains(logs, "fixture-hook") || strings.Contains(logs, "fixture-signature") {
		t.Fatal("delivery logs must retain status and exclude all webhook credentials")
	}
}

func TestAutotaskTicketCredentialsAndInboundLinksKeepTenantIsolation(t *testing.T) {
	const endpoint = "/atservicesrest/v1.0/Tickets"
	const mirrorPath = "/mirror/"
	const alphaBrand, betaBrand = "Northstar NOC", "Southwind NOC"
	var createdAlpha, createdBeta, unexpected atomic.Int32
	var readAlphaStatus, readBetaStatus atomic.Int32
	var alphaResolutions, betaResolutions atomic.Int32
	var alphaClosed atomic.Bool
	var alphaExternalID, alphaResolution atomic.Value
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxFixtureBody = 8192
		w.Header().Set("Content-Type", "application/json")
		if lane, ok := strings.CutPrefix(r.URL.Path, mirrorPath); ok {
			var message struct{ Text string }
			if r.Method != http.MethodPost || (lane != "alpha" && lane != "beta") ||
				json.NewDecoder(io.LimitReader(r.Body, maxFixtureBody)).Decode(&message) != nil || message.Text == "" {
				unexpected.Add(1)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if strings.Contains(message.Text, "incident resolved") {
				if lane == "alpha" {
					alphaResolution.Store(message.Text)
					alphaResolutions.Add(1)
				} else {
					betaResolutions.Add(1)
				}
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		user := r.Header.Get("UserName")
		if (user != "alpha" && user != "beta") || r.Header.Get("Secret") != user+"-fixture" ||
			r.Header.Get("ApiIntegrationCode") != "fixture-integration" {
			unexpected.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == endpoint+"/query" {
			var query struct {
				Filter []struct{ Field string } `json:"filter"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, maxFixtureBody)).Decode(&query) != nil {
				unexpected.Add(1)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			statusQuery := false
			for _, f := range query.Filter {
				statusQuery = statusQuery || f.Field == "status"
			}
			if statusQuery {
				if user == "alpha" {
					readAlphaStatus.Add(1)
				} else {
					readBetaStatus.Add(1)
				}
			}
			if externalID, ok := alphaExternalID.Load().(string); user == "alpha" && ok && (!statusQuery || alphaClosed.Load()) {
				state := 1
				if alphaClosed.Load() {
					state = 5
				}
				_, _ = fmt.Fprintf(w, `{"items":[{"id":12,"companyID":101,"externalID":%q,"status":%d}]}`, externalID, state)
				return
			}
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == endpoint+"/12" && user == "alpha" {
			externalID, _ := alphaExternalID.Load().(string)
			_, _ = fmt.Fprintf(w, `{"item":{"id":12,"companyID":101,"externalID":%q}}`, externalID)
			return
		}
		if r.Method == http.MethodPatch && r.URL.Path == endpoint && user == "alpha" {
			var patch struct {
				ID     int `json:"id"`
				Status int `json:"status"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, maxFixtureBody)).Decode(&patch) == nil && patch.ID == 12 && patch.Status == 0 {
				_, _ = io.WriteString(w, `{"itemId":12}`)
				return
			}
		}
		var ticket struct {
			CompanyID  int    `json:"companyID"`
			ExternalID string `json:"externalID"`
		}
		if r.Method != http.MethodPost || r.URL.Path != endpoint || json.NewDecoder(io.LimitReader(r.Body, maxFixtureBody)).Decode(&ticket) != nil || ticket.ExternalID == "" {
			unexpected.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case user == "alpha" && ticket.CompanyID == 101:
			createdAlpha.Add(1)
			alphaExternalID.Store(ticket.ExternalID)
			w.WriteHeader(http.StatusServiceUnavailable) // ticket exists, but the acknowledgement is lost
			return
		case user == "beta" && ticket.CompanyID == 202:
			createdBeta.Add(1)
		default:
			unexpected.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"itemId":12}`)
	}))
	t.Cleanup(receiver.Close)

	db := changeDB(t)
	alpha, beta := freshTenant(t, db, "autotask-alpha"), freshTenant(t, db, "autotask-beta")
	links := pgLinkStore{pool: db.Pool()}
	d := notify.NewDispatcher(links, slog.New(slog.NewTextHandler(io.Discard, nil)))
	otherWorker := notify.NewDispatcher(links, slog.New(slog.NewTextHandler(io.Discard, nil)))
	names := map[string]string{alpha: alphaBrand, beta: betaBrand}
	lookup := func(_ context.Context, tenant string) branding.Branding {
		brand := branding.Default()
		if name := names[tenant]; name != "" {
			brand.Customer = &branding.CustomerIdentity{Name: name}
		}
		return brand
	}
	d.WithBranding(lookup)
	otherWorker.WithBranding(lookup)
	inbound := map[string]config.NotifyInbound{}
	for _, lane := range []struct {
		name, tenant string
		company      int
	}{{"alpha", alpha, 101}, {"beta", beta, 202}} {
		settings := fmt.Sprintf(`{"username":%q,"api_secret":%q,"integration_code":"fixture-integration",
			"company_id":%d,"priority":2,"open_status":1,"resolved_status":5,"due_after":"48h",
			"progress_field":"probectl progress","console_origin":"https://console.example.invalid"}`,
			lane.name, lane.name+"-fixture", lane.company)
		connector, err := notify.NewTenantConnector(lane.tenant, "autotask", receiver.URL+"/atservicesrest/v1.0", settings, receiver.Client())
		if err != nil {
			t.Fatal(err)
		}
		d.Register(lane.tenant, connector)
		otherWorker.Register(lane.tenant, connector)
		mirror, ok := notify.NewConnector("slack", receiver.URL+mirrorPath+lane.name, "", receiver.Client())
		if !ok {
			t.Fatal("notification mirror unavailable")
		}
		d.Register(lane.tenant, mirror)
		otherWorker.Register(lane.tenant, mirror)
		inbound[lane.name] = config.NotifyInbound{TenantID: lane.tenant, Provider: "autotask", Secret: lane.name + "-signed-receiver-fixture-value"}
	}
	left := openIncidentVia(t, db, d, alpha, "left-autotask-link")
	right := openIncidentVia(t, db, d, beta, "right-autotask-link")
	pending, err := links.Get(t.Context(), alpha, left.ID, "autotask")
	if err != nil || pending == nil || pending.Status != notify.LinkOpening || pending.ExternalRef != "" || createdAlpha.Load() != 1 {
		t.Fatal("an ambiguous create must retain the reservation without another vendor write", err)
	}
	if acquired, err := links.ReserveOpen(t.Context(), beta, left.ID, "autotask"); err != nil || acquired {
		t.Fatal("the sibling tenant could reserve a foreign incident", err)
	}
	otherWorker.Reconcile(t.Context())
	for tenant, id := range map[string]string{alpha: left.ID, beta: right.ID} {
		link, err := links.FindByRef(t.Context(), tenant, "autotask", "12")
		if err != nil || link == nil || link.IncidentID != id {
			t.Fatalf("vendor reference did not resolve to the tenant's own incident: %v", err)
		}
	}
	snapshots, err := links.OpenTicketStatuses(t.Context(), alpha, "autotask", "", 1)
	if err != nil || len(snapshots) != 1 || snapshots[0].IncidentID != left.ID {
		t.Fatal("failed to snapshot alpha's confirmed ticket", err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(alpha))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Incidents{}).Resolve(ctx, sc, left.ID); err != nil {
			return err
		}
		_, err := (store.Incidents{}).Reopen(ctx, sc, left.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if changed, err := links.ResolveTicketStatus(t.Context(), snapshots[0]); err != nil || changed != nil {
		t.Fatal("stale ticket status undid a newer local reopen", err)
	}
	alphaClosed.Store(true)
	otherWorker.Reconcile(t.Context())
	otherWorker.Reconcile(t.Context()) // repeat the native reconciliation after the local commit
	h := buildNotifyHandler(db, d, inbound)
	body := []byte(`{"external_ref":"12","status":"resolved"}`)
	post := func(name, secret string) int {
		r := httptest.NewRequest(http.MethodPost, "https://control.example.invalid/ingest/itsm/autotask/"+name, bytes.NewReader(body))
		r.Header.Set(notify.InboundSignatureHeader, sign(secret, body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if post("beta", inbound["alpha"].Secret) != http.StatusUnauthorized || post("alpha", inbound["alpha"].Secret) != http.StatusAccepted {
		t.Fatal("the provider callback did not require the registered tenant's signature")
	}
	drainNotify(t, d, alpha)
	for _, lane := range []struct {
		tenant string
		id     string
		status incident.Status
	}{{alpha, left.ID, incident.StatusResolved}, {beta, right.ID, incident.StatusOpen}} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			row, err := (store.Incidents{}).Get(ctx, sc, lane.id)
			if err == nil && row.Status != lane.status {
				return fmt.Errorf("incident status = %s, want %s", row.Status, lane.status)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if createdAlpha.Load() != 1 || createdBeta.Load() != 1 || readAlphaStatus.Load() == 0 || readBetaStatus.Load() == 0 || unexpected.Load() != 0 {
		t.Fatal("both tenants must read their own native status without duplicate delivery or an echo")
	}
	message, _ := alphaResolution.Load().(string)
	if alphaResolutions.Load() != 1 || betaResolutions.Load() != 0 ||
		!strings.Contains(message, alphaBrand) || strings.Contains(message, betaBrand) ||
		!strings.Contains(message, "Powered by probectl (https://probectl.com)") {
		t.Fatalf("polled resolution lost its own customer brand, fixed attribution or tenant scope: %q", message)
	}
}

func TestHaloPSATicketStatusAndTokensStayTenantScoped(t *testing.T) {
	type haloRecord struct {
		ID       int    `json:"id"`
		Company  int    `json:"client_id"`
		Contract int    `json:"contract_id"`
		Marker   string `json:"third_party_id_string"`
		Status   int    `json:"status_id"`
	}
	const endpoint = "/api/Tickets"
	tickets := map[string]haloRecord{}
	tokens := map[string]int{}
	statusReads := map[string]int{}
	var mu sync.Mutex
	var unexpected int
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		reject := func() {
			unexpected++
			w.WriteHeader(http.StatusBadRequest)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/auth/token" {
			if r.ParseForm() != nil || r.URL.RawQuery != "" {
				reject()
				return
			}
			name := r.PostForm.Get("client_id")
			if (name != "alpha" && name != "beta") || r.PostForm.Get("client_secret") != name+"-fixture" ||
				r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "all" {
				reject()
				return
			}
			tokens[name]++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": name + ".fixture", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		name, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		name, suffix := strings.CutSuffix(name, ".fixture")
		if !ok || !suffix || (name != "alpha" && name != "beta") || tokens[name] == 0 {
			reject()
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/ClientContract/9":
			_ = json.NewEncoder(w).Encode(map[string]int{"id": 9, "client_id": 7})
		case "GET " + endpoint:
			query := r.URL.Query()
			if query.Get("client_id") != "7" || query.Get("ticketcontract_id") != "9" {
				reject()
				return
			}
			found := []haloRecord{}
			if query.Get("status_id") == "5" {
				if query.Get("ticketids") != "12" {
					reject()
					return
				}
				statusReads[name]++
				// Both logins can encounter the alpha record because they share
				// a vendor customer. The probectl ticket marker must fence beta.
				if record := tickets["alpha"]; record.Status == 5 {
					record.Contract = 0 // The documented list projection omits it.
					found = append(found, record)
				}
			} else if marker := query.Get("third_party_id_string"); strings.HasPrefix(marker, "pbctl-") {
				if record := tickets[name]; record.Marker == marker {
					found = append(found, record)
				}
			} else {
				reject()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"record_count": len(found), "tickets": found})
		case "GET " + endpoint + "/12":
			_ = json.NewEncoder(w).Encode(tickets[name])
		case "POST " + endpoint:
			var batch []haloRecord
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
			if dec.Decode(&batch) != nil || len(batch) != 1 || batch[0].ID != 0 || tickets[name].ID != 0 ||
				batch[0].Company != 7 || batch[0].Contract != 9 || batch[0].Status != 1 {
				reject()
				return
			}
			record := batch[0]
			record.ID = 12
			tickets[name] = record
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(record)
		default:
			reject()
		}
	}))
	t.Cleanup(receiver.Close)

	db := changeDB(t)
	alpha, beta := freshTenant(t, db, "halo-alpha"), freshTenant(t, db, "halo-beta")
	links := pgLinkStore{pool: db.Pool()}
	d := notify.NewDispatcher(links, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for name, tenant := range map[string]string{"alpha": alpha, "beta": beta} {
		settings := fmt.Sprintf(`{"client_id":%q,"client_secret":%q,"customer_id":7,"contract_id":9,
			"ticket_type_id":8,"priority_id":2,"open_status":1,"resolved_status":5,
			"progress_field_id":23,"due_after":"48h","console_origin":"https://console.example.invalid"}`, name, name+"-fixture")
		connector, err := notify.NewTenantConnector(tenant, "halopsa", receiver.URL, settings, receiver.Client())
		if err != nil {
			t.Fatal(err)
		}
		d.Register(tenant, connector)
	}
	left := openIncidentVia(t, db, d, alpha, "left-halo-link")
	right := openIncidentVia(t, db, d, beta, "right-halo-link")
	for tenant, id := range map[string]string{alpha: left.ID, beta: right.ID} {
		link, err := links.FindByRef(t.Context(), tenant, "halopsa", "12")
		if err != nil || link == nil || link.IncidentID != id {
			t.Fatal("shared vendor reference did not recover the caller tenant's link", err)
		}
	}
	if foreign, err := links.Get(t.Context(), beta, left.ID, "halopsa"); err != nil || foreign != nil {
		t.Fatal("beta could read alpha's link", err)
	}

	mu.Lock()
	record := tickets["alpha"]
	record.Status = 5
	tickets["alpha"] = record
	mu.Unlock()
	d.Reconcile(t.Context())
	d.Reconcile(t.Context())
	for _, lane := range []struct {
		tenant, id string
		want       incident.Status
	}{{alpha, left.ID, incident.StatusResolved}, {beta, right.ID, incident.StatusOpen}} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			row, err := (store.Incidents{}).Get(ctx, sc, lane.id)
			if err == nil && row.Status != lane.want {
				return fmt.Errorf("incident status = %s, want %s", row.Status, lane.want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if tokens["alpha"] != 1 || tokens["beta"] != 1 || tickets["alpha"].Marker == tickets["beta"].Marker ||
		statusReads["alpha"] != 1 || statusReads["beta"] == 0 || unexpected != 0 {
		t.Fatal("OAuth caches, ticket ownership, repeated status reads, or echo suppression failed")
	}
}
