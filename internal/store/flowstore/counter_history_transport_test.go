// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

func TestCounterHistoryTransportPublishesOnlyCompleteAcknowledgedPollsAndReaderRows(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"complete", "partial", "late-insert-error", "foreign-read", "trailing-error"} {
		t.Run(mode, func(t *testing.T) {
			rows := counterHistoryRows(t, tenant)
			var markers atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query().Get("query")
				if query == "" {
					if err := r.ParseForm(); err != nil {
						t.Error(err)
						return
					}
					query = r.PostForm.Get("query")
				}
				user, _, _ := r.BasicAuth()
				switch {
				case strings.HasPrefix(query, "INSERT INTO "+sharedCounterHistoryTable):
					body, err := io.ReadAll(r.Body)
					if err != nil || user != "control" || !strings.Contains(string(body), `"counter_value":18446744073709551615`) || r.URL.Query().Get("wait_end_of_query") != "1" || !strings.Contains(query, "SETTINGS async_insert=0,wait_for_async_insert=1") {
						t.Error("original exact insert or completion acknowledgement changed", err)
					}
					if mode == "late-insert-error" {
						_, _ = io.WriteString(w, "Code: 241. query failed after HTTP headers")
					}
				case strings.HasPrefix(query, "INSERT INTO "+sharedCounterPollTable):
					markers.Add(1)
				case strings.HasPrefix(query, "SELECT toString(count()) AS n FROM "+sharedCounterHistoryTable):
					if user != "control" || r.URL.Query().Get("param_capture") != "" || r.PostForm.Get("param_tenant") != tenant {
						t.Error("publication count lost control authority or put selectors in URL")
					}
					n := "4"
					if mode == "partial" {
						n = "2"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"n": n})
				case strings.HasPrefix(query, "SELECT "+counterReadColumns()+" FROM "+sharedCounterHistoryTable):
					if user != "reader" || r.URL.Query().Get(tenantSettingName) != tenant || !strings.Contains(query, "FROM "+sharedCounterPollTable+" FINAL WHERE tenant_id={tenant:String} AND ts>=") {
						t.Error("counter read bypassed reader isolation or whole-poll commit markers")
					}
					for i, row := range rows {
						document := counterPortableDocument(row)
						if mode == "foreign-read" && i == len(rows)-1 {
							document["tenant_id"] = "66666666-6666-4666-8666-666666666666"
						}
						_ = json.NewEncoder(w).Encode(document)
					}
					if mode == "trailing-error" {
						_, _ = io.WriteString(w, "Code: 159. execution limit exceeded\n")
					}
				}
			}))
			defer server.Close()
			backend, err := NewClickHouseWithClient(server.URL, 0, chtest.Client("control"))
			if err != nil {
				t.Fatal(err)
			}
			backend.WithTenantScoping(true).WithReader(chtest.Client("reader"))
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			err = backend.InsertCounterPoll(ctx, rows, counterHistoryBudget())
			if mode == "partial" || mode == "late-insert-error" {
				if err == nil || markers.Load() != 0 {
					t.Fatal("a partial or unacknowledged poll became committed", err, markers.Load())
				}
				return
			}
			if err != nil || markers.Load() != 1 {
				t.Fatal("a verified complete poll was not committed", err, markers.Load())
			}
			got, err := backend.CounterPoints(ctx, counterHistoryQuery(rows))
			if mode == "foreign-read" || mode == "trailing-error" {
				if err == nil || got != nil {
					t.Fatal("a foreign or incomplete backend stream returned a successful prefix", len(got), err)
				}
				return
			}
			if err != nil || len(got) != len(rows) || got[0].Value != ^uint64(0) {
				t.Fatal("complete exact reader stream failed", len(got), err)
			}
		})
	}
}
