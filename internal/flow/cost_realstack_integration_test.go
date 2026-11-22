// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cost"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type shippedCostResponse struct {
	Running bool         `json:"cost_running"`
	Summary cost.Summary `json:"summary"`
}

// TestShippedCostEngineFromCollectedFlows runs the shipped cost consumer in
// two supported configurations. Only the sovereign fixture configures a
// deployment-wide owner or budget. Small synthetic IPFIX records travel
// exclusively to the enrolled loopback collectors.
func TestShippedCostEngineFromCollectedFlows(t *testing.T) {
	t.Run("scoped-volume", func(t *testing.T) {
		stack := shipped.Start(t, shipped.Options{Name: "cost-volume", TenantBand: 4, Env: map[string]string{
			"PROBECTL_COST_ENABLED": "true", "PROBECTL_COST_PRICED": "false",
		}})
		operator := stack.OnboardOperator(t, "root@msp-cost.example")
		run := "cost-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		lanes := [2]nativeLane{{name: "red", octet: 190}, {name: "blue", octet: 190}}
		for i := range lanes {
			lanes[i].provision(t, stack, operator, run)
			lanes[i].apiToken = stack.APIToken(t, lanes[i].cookie, "metrics.read")
			cold := readShippedCost(t, stack, &lanes[i])
			if cold.Priced || cold.ZonesMapped || cold.TotalBytes != 0 || !cold.DataSince.IsZero() {
				t.Fatalf("an unobserved tenant reported pricing or coverage: %+v", cold)
			}
		}
		amounts := [2]uint64{64 << 20, 32 << 20}
		var sent [2]time.Time
		for i := range lanes {
			sent[i] = writeShippedCostObservation(t, &lanes[i], i, amounts[i])
			waitForStoredShippedCostObservation(t, stack, &lanes[i], sent[i], amounts[i]*10)
			waitForShippedCost(t, stack, &lanes[i], amounts[i]*10)
			if i == 0 {
				if other := readShippedCost(t, stack, &lanes[1]); other.TotalBytes != 0 || !other.DataSince.IsZero() {
					t.Fatalf("the sibling acquired volume or coverage: %+v", other)
				}
			}
		}
		for i := range lanes {
			lane := &lanes[i]
			want := amounts[i] * 10
			scoped := readShippedCost(t, stack, lane)
			if scoped.TotalBytes != want || scoped.ByClass[cost.ClassUnknown].Bytes != want ||
				scoped.TotalUSD != 0 || scoped.DataSince.Before(sent[i]) || scoped.Priced || scoped.ZonesMapped {
				t.Fatalf("the cost calculation lost scoped sampled volume: %+v", scoped)
			}
			assertShippedCostCLI(t, stack, lane, scoped)
			for _, theme := range []string{"light", "dark"} {
				renderShippedCost(t, stack, lane, theme,
					"Egress spend", "Volume-only mode", "No CIDR→zone rules configured", "Accumulation opened")
			}
		}
	})

	t.Run("sovereign-pricing", func(t *testing.T) {
		stack := shipped.Start(t, shipped.Options{Name: "cost-priced", TenantBand: 4, Env: map[string]string{
			"PROBECTL_DEPLOYMENT_PROFILE": "single",
			"PROBECTL_COST_ENABLED":       "true", "PROBECTL_COST_PRICED": "true",
			"PROBECTL_COST_ZONES":    "10.190.30.0/24=us-east-1a,10.190.1.0/24=us-east-1b",
			"PROBECTL_COST_SERVICES": "10.190.30.0/24=checkout:payments",
			"PROBECTL_COST_BUDGETS":  "team:payments=0.02,service:checkout=0.03",
		}})
		lane := nativeLane{name: "red", octet: 190, id: tenancy.DefaultTenantID.String()}
		lane.cookie = stack.SignIn(t, lane.id, "ada@acme.example")
		lane.apiToken = stack.APIToken(t, lane.cookie, "metrics.read")
		lane.enrollCollector(t, stack)
		cold := readShippedCost(t, stack, &lane)
		if !cold.Priced || !cold.ZonesMapped || cold.TotalBytes != 0 || !cold.DataSince.IsZero() {
			t.Fatalf("a priced cold tenant claimed observation coverage: %+v", cold)
		}
		const firstRaw, secondRaw = 1 << 28, 1 << 27
		firstAt := writeShippedCostObservation(t, &lane, 0, firstRaw)
		waitForShippedCost(t, stack, &lane, firstRaw*10)
		waitForShippedCostIncidents(t, stack, &lane, firstAt, time.Time{})
		secondAt := writeShippedCostObservation(t, &lane, 1, secondRaw)
		scoped := waitForShippedCost(t, stack, &lane, (firstRaw+secondRaw)*10)
		// 3.75 observed GiB across AZs at the embedded $0.01/GiB rate.
		exactUSD := func(usd float64) bool { return math.Abs(usd-0.0375) < 1e-9 }
		if !exactUSD(scoped.TotalUSD) || !exactUSD(scoped.ByService["checkout"].USD) ||
			!exactUSD(scoped.ByTeam["payments"].USD) || scoped.ByClass[cost.ClassInterAZ].Bytes != scoped.TotalBytes ||
			scoped.PricingSource == "" || scoped.PricingAsOf == "" || scoped.DataSince.Before(firstAt) ||
			len(scoped.ChattyPairs) != 1 || !scoped.ChattyPairs[0].Chatty || len(scoped.Budgets) != 2 {
			t.Fatalf("expected priced cross-AZ showback and two budget statuses: %+v", scoped)
		}
		for _, budget := range scoped.Budgets {
			if !budget.Exceeded || !exactUSD(budget.SpentUSD) {
				t.Fatalf("a configured budget omitted attributed spend: %+v", budget)
			}
		}
		// The service crosses on the second observation. Its published signal
		// proves the consumer has processed both budgets through that record.
		waitForShippedCostIncidents(t, stack, &lane, firstAt, secondAt)
		assertShippedCostCLI(t, stack, &lane, scoped)
		for _, theme := range []string{"light", "dark"} {
			renderShippedCost(t, stack, &lane, theme, "checkout", "payments", "chatty", "exceeded", "Accumulation opened")
		}
	})
}

func writeShippedCostObservation(t *testing.T, lane *nativeLane, sequence int, amount uint64) time.Time {
	t.Helper()
	conn, err := net.Dial("udp", lane.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ordinary := trafficVector{transport: 6, flags: 16, port: 42001, destinations: 1}
	at := time.Now().UTC().Truncate(time.Millisecond)
	frame := controlledTrafficIPFIX(t, lane.octet, 0, 0, sequence, at, ordinary, amount, 100)
	if n, err := conn.Write(frame); err != nil || n != len(frame) {
		t.Fatal("write synthetic cost observation to the owned IPFIX listener", err)
	}
	return at
}

func readShippedCost(t *testing.T, stack *shipped.Stack, lane *nativeLane) cost.Summary {
	t.Helper()
	var response shippedCostResponse
	lane.do(t, stack, http.MethodGet, "/v1/cost/summary", nil, &response, http.StatusOK)
	if !response.Running {
		t.Fatal("the shipped cost consumer is disabled")
	}
	return response.Summary
}

func waitForStoredShippedCostObservation(t *testing.T, stack *shipped.Stack, lane *nativeLane, at time.Time, want uint64) {
	t.Helper()
	plan := nativeGoldenPlan(lane.octet, at, []string{"src_addr"})
	plan.DataSeries, plan.From, plan.To = "raw", at.Add(-time.Second), at.Add(time.Second)
	// A newly provisioned tenant can wait for a 30-second lane refresh.
	// Start the derived-view deadline after observing the original on its lane.
	shipped.Await(t, lane.name+" exact sampled IPFIX record stored in its tenant", 45*time.Second, func() bool {
		result := lane.query(t, stack, plan)
		return result.Totals["flows:total"] == "1" && result.Totals["bytes:total"] == strconv.FormatUint(want, 10)
	})
}

func waitForShippedCost(t *testing.T, stack *shipped.Stack, lane *nativeLane, want uint64) cost.Summary {
	t.Helper()
	var last uint64
	for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); time.Sleep(150 * time.Millisecond) {
		summary := readShippedCost(t, stack, lane)
		last = summary.TotalBytes
		if summary.TotalBytes == want {
			return summary
		}
		if summary.TotalBytes > want {
			t.Fatalf("%s cost double-counted the observation: got %d bytes, want %d", lane.name, summary.TotalBytes, want)
		}
	}
	t.Fatalf("%s cost consumer recorded %d sampled bytes, want %d", lane.name, last, want)
	return cost.Summary{}
}

func waitForShippedCostIncidents(t *testing.T, stack *shipped.Stack, lane *nativeLane, teamAt, serviceAt time.Time) {
	t.Helper()
	wanted := map[string]time.Time{"team:payments": teamAt, "service:checkout": serviceAt}
	wantCount := 1
	if !serviceAt.IsZero() {
		wantCount++
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(150 * time.Millisecond) {
		var page struct {
			Items []incident.Incident `json:"items"`
		}
		lane.do(t, stack, http.MethodGet, "/v1/incidents", nil, &page, http.StatusOK)
		seen := map[string]bool{}
		for _, row := range page.Items {
			at, budget := wanted[row.Target]
			if !budget {
				continue
			}
			if row.TenantID != lane.id {
				t.Fatal("cost incident escaped its authenticated scope")
			}
			var full incident.Incident
			lane.do(t, stack, http.MethodGet, fmt.Sprintf("/v1/incidents/%s", row.ID), nil, &full, http.StatusOK)
			for _, signal := range full.Signals {
				if signal.Kind != "cost.budget_exceeded" {
					continue
				}
				if at.IsZero() || seen[row.Target] || !signal.OccurredAt.Equal(at) || signal.Attributes["cost.month"] != at.Format("2006-01") {
					t.Fatalf("cost budget fired at the wrong observation or more than once for %s", row.Target)
				}
				seen[row.Target] = true
			}
		}
		if len(seen) == wantCount {
			return
		}
	}
	t.Fatal("the shipped cost breach did not publish a scoped incident")
}

func assertShippedCostCLI(t *testing.T, stack *shipped.Stack, lane *nativeLane, want cost.Summary) {
	t.Helper()
	var cli shippedCostResponse
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &cli, "cost", "summary")
	if !cli.Running || !reflect.DeepEqual(cli.Summary, want) {
		t.Fatalf("the CLI lost the tenant's scoped cost summary: %+v", cli)
	}
}

func renderShippedCost(t *testing.T, stack *shipped.Stack, lane *nativeLane, theme string, text ...string) {
	t.Helper()
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: stack.BaseURL + "/ui/cost", Theme: theme, Accessibility: true,
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
		TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
		Expect: text,
	})
}
