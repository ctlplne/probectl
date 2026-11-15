// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestSourceReportBudgetKeepsSeparateDeadlineAndQueryResourcePolicy(t *testing.T) {
	server := testServer(fakePinger{})
	server.flowStore = flowstore.NewMemory()
	query := flowstore.DefaultExplorerBudget()
	query.ExecutionLimit, query.ReadBytes = 2*time.Second, 3<<30
	if err := flowstore.AttachExplorerBudget(server.flowStore, query); err != nil {
		t.Fatal(err)
	}
	for _, selected := range []time.Duration{0, 25 * time.Hour} {
		server.cfg = &config.Config{ReportOperationTimeout: selected}
		budget, err := server.sourceReportBudget()
		want := selected
		if want == 0 {
			want = 5 * time.Minute
		}
		if err != nil || budget.ExecutionLimit != want {
			t.Fatal("complete source-backed report inherited the interactive query deadline", err)
		}
		budget.ExecutionLimit = query.ExecutionLimit
		if budget != query || flowstore.ExplorerQueryBudget(server.flowStore) != query {
			t.Fatal("report deadline changed query resources or interactive admission")
		}
	}
	server.cfg.ReportOperationTimeout = -1
	if _, err := server.sourceReportBudget(); err == nil {
		t.Fatal("invalid report deadline admitted")
	}
}

func TestReportResponseOutlivesOrdinaryTLSWriteDeadline(t *testing.T) {
	server := testServer(fakePinger{})
	server.cfg = &config.Config{ReportOperationTimeout: 2 * time.Second}
	socket := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped := &statusRecorder{ResponseWriter: w}
		if err := server.extendReportResponse(wrapped, r); err != nil {
			t.Error(err)
			return
		}
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(wrapped, r.Header.Get("X-Probectl-Tenant"))
	}))
	socket.Config.WriteTimeout = 200 * time.Millisecond
	socket.StartTLS()
	t.Cleanup(socket.Close)
	for _, tenant := range []string{"first-assessment", "second-assessment"} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Probectl-Tenant", tenant)
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal("admitted report response was reset by the ordinary listener deadline", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != tenant {
			t.Fatal("report response was cut off or borrowed another caller's bytes", err)
		}
	}
}
