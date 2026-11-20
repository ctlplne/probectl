// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package outage_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/outage"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type outageReceiptLane struct {
	id, slug, cookie string
	targets          []string
}

type outageReceipt struct {
	outage.Snapshot
	Running bool                `json:"outage_running"`
	FeedsOn bool                `json:"feeds_enabled"`
	Feeds   []outage.FeedHealth `json:"feeds"`
}

func TestShippedOutageFusesOwnedVantagesWithLastGoodMirror(t *testing.T) {
	mirror := t.TempDir()
	feed := filepath.Join(mirror, "ioda")
	asnTable := filepath.Join(mirror, "asn.csv")
	stamp := time.Now().Add(-time.Minute).Unix()
	// Documented IODA schema with a synthetic event owned by this fixture.
	raw := fmt.Sprintf(`{"data":[{"entity":{"type":"asn","code":"64496","name":"Fixture transit"},"start":%d,"duration":0,"score":5000,"datasource":"fixture"}]}`, stamp)
	for path, content := range map[string]string{feed: raw, asnTable: "network,asn,organization\n127.0.0.0/8,64496,Fixture transit\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stack := shipped.Start(t, shipped.Options{Name: "outagemirror", TenantBand: 3, Env: map[string]string{
		"PROBECTL_OUTAGE_FEEDS_ENABLED": "true",
		"PROBECTL_OUTAGE_FEEDS":         "ioda",
		"PROBECTL_OUTAGE_MIRROR":        mirror,
		"PROBECTL_OUTAGE_REFRESH":       "2s",
		"PROBECTL_FLOW_ENRICH_ASN_FILE": asnTable,
	}})
	operator := stack.OnboardOperator(t, "root@msp-outage-receipt.example")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "owned outage fixture", http.StatusServiceUnavailable)
	}))
	t.Cleanup(target.Close)

	lanes := [2]outageReceiptLane{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		lane.slug = "outage-" + strconv.FormatInt(stamp, 36) + "-" + strconv.Itoa(i)
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, lane.slug, lane.slug))
		lane.id = tenant.ID
		lane.cookie = stack.SignIn(t, lane.id, email, lane.slug)
		config := "canaries:\n"
		for _, site := range []string{"first", "second"} {
			endpoint := target.URL + "/" + lane.slug + "-" + site
			name := lane.slug + "-" + site
			lane.targets = append(lane.targets, endpoint)
			code, body := stack.Do(t, lane.cookie, http.MethodPost, "/v1/tests", map[string]any{
				"name": name, "type": "http", "target": endpoint, "enabled": true, "interval_seconds": 20, "timeout_seconds": 5,
				"params": map[string]string{"allow_private_targets": "true"},
			})
			var created struct{ ID string }
			if code != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.ID == "" {
				t.Fatal("the tenant could not create its original probe", code)
			}
			config += fmt.Sprintf(`  - test_id: %q
    type: http
    target: %q
    interval: 2s
    timeout: 5s
    params:
      allow_private_targets: "true"
`, created.ID, endpoint)
		}
		identity := stack.EnrollAgent(t, lane.id, uuid.NewString(), lane.slug)
		stack.StartAgent(t, identity, lane.slug, []string{"http"}, config)
	}
	for _, lane := range lanes {
		shipped.Await(t, lane.slug+" fused outage and local vantage", 45*time.Second, func() bool {
			view := readOutageReceipt(t, stack, lane.cookie)
			return len(view.Feeds) == 1 && view.Feeds[0].Status == "ok" && expectedOutageScope(view, lane.targets, stamp)
		})
	}
	temporary := feed + ".next"
	if err := os.WriteFile(temporary, []byte("malformed lab fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, feed); err != nil {
		t.Fatal(err)
	}
	for i, lane := range lanes {
		shipped.Await(t, lane.slug+" last-good outage cache", 15*time.Second, func() bool {
			view := readOutageReceipt(t, stack, lane.cookie)
			return len(view.Feeds) == 1 && view.Feeds[0].Status == "failed" && view.Feeds[0].Events == 1 &&
				expectedOutageScope(view, lane.targets, stamp)
		})
		token := stack.APIToken(t, lane.cookie, "metrics.read")
		var cli outageReceipt
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &cli, "outage", "list")
		if len(cli.Feeds) != 1 || cli.Feeds[0].Status != "failed" || !expectedOutageScope(cli, lane.targets, stamp) {
			t.Fatal("the CLI did not retain the tenant's outage evidence and failed feed state")
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/outages", CAFile: stack.CAFile, TrustCertFiles: stack.TrustCerts(),
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			Expect:  append([]string{"Internet outages", "Fixture transit", "Feed health & provenance", "failed"}, lane.targets...),
			Absent:  lanes[1-i].targets,
			Theme:   []string{"light", "dark"}[i],
		})
	}
}

func readOutageReceipt(t *testing.T, stack *shipped.Stack, cookie string) outageReceipt {
	t.Helper()
	code, raw := stack.Do(t, cookie, http.MethodGet, "/v1/outages", nil)
	var view outageReceipt
	if code != http.StatusOK || json.Unmarshal(raw, &view) != nil {
		t.Fatal("the tenant's outage view could not be read", code)
	}
	return view
}

func expectedOutageScope(view outageReceipt, targets []string, stamp int64) bool {
	if !view.Running || !view.FeedsOn || !view.ScopeResolution || len(view.Events) != 1 || len(view.Vantage) != 1 {
		return false
	}
	external, local := view.Events[0], view.Vantage[0]
	if external.Source != "ioda" || external.Start.Unix() != stamp || local.Source != "vantage" ||
		external.Scope.Code != "AS64496" || local.Scope.Code != "AS64496" || !external.Ongoing || !local.Ongoing {
		return false
	}
	for _, event := range []outage.EventView{external, local} {
		var affected []string
		for _, impact := range event.Affected {
			if impact.CanaryType != "http" || impact.Failures < 2 {
				return false
			}
			affected = append(affected, impact.Target)
		}
		if !slices.Equal(affected, targets) {
			return false
		}
	}
	return true
}
