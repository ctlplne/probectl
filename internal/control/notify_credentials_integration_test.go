// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/notify"
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
