// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/author"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestAuthoringDiscoveryRealStack uses two enrolled flow collectors and the
// shipped control plane, CLI and Targets page. Fixture datagrams only go to
// the loopback collectors. No canary agent is started and no target is probed.
func TestAuthoringDiscoveryRealStack(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "authoring", TenantBand: 4})
	operator := stack.OnboardOperator(t, "root@msp-authoring.example")
	run := "authoring-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	type authoringLane struct {
		nativeLane
		theme, observed, cliTarget, uiTarget string
		env                                  map[string]string
		proposal                             author.Proposal
		persisted                            []store.Test
		browser                              testsupport.RenderSpec
	}
	lanes := [2]authoringLane{
		{nativeLane: nativeLane{name: "red", octet: 188}, theme: "light"},
		{nativeLane: nativeLane{name: "blue", octet: 189}, theme: "dark"},
	}
	for i := range lanes {
		lane := &lanes[i]
		lane.provision(t, stack, operator, run)
		lane.observed = fmt.Sprintf("10.%d.1.1", lane.octet)
		lane.cliTarget = "https://cli-" + lane.name + ".example/status"
		lane.uiTarget = "https://ui-" + lane.name + ".example/status"
		lane.env = map[string]string{"PROBECTL_API_TOKEN": stack.APIToken(t, lane.cookie, "test.read", "test.write", "flow.read")}
		sendAuthoringObservations(t, stack, &lane.nativeLane)
	}
	const panel = "[data-targets-authoring]"
	for i := range lanes {
		lane, peer := &lanes[i], &lanes[1-i]
		lane.browser = testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/targets", Theme: lane.theme,
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
			Expect: []string{"Author with AI", lane.observed},
			Absent: []string{peer.observed, peer.cliTarget, peer.uiTarget},
			Steps: []testsupport.RenderStep{
				{Fill: panel + " form input", Value: "Check " + lane.uiTarget},
				{Click: "Propose a test", Within: panel, ExpectWithin: panel, Expect: []string{lane.uiTarget, "Proposed by heuristic"}},
			},
		}
	}

	type discoveryResponse struct {
		Proposals []author.DiscoveryProposal `json:"proposals"`
	}
	for i := range lanes {
		lane := &lanes[i]
		t.Run(lane.name+"-propose", func(t *testing.T) {
			var discoveries discoveryResponse
			stack.MustCLI(t, lane.env, &discoveries, "ai", "discover")
			if len(discoveries.Proposals) != 1 {
				t.Fatalf("discovery must return exactly one owned candidate, got %+v", discoveries.Proposals)
			}
			observation := discoveries.Proposals[0]
			if observation.Source != "flow" || observation.Spec.Target != lane.observed ||
				observation.Spec.Type != "icmp" || observation.Score != 2 {
				t.Fatalf("discovery lost the owned flow evidence: %+v", observation)
			}
			noFlow := map[string]string{"PROBECTL_API_TOKEN": stack.APIToken(t, lane.cookie, "test.write")}
			discoveries = discoveryResponse{}
			stack.MustCLI(t, noFlow, &discoveries, "ai", "discover")
			if len(discoveries.Proposals) != 0 {
				t.Fatalf("test-write scope disclosed flow evidence: %+v", discoveries.Proposals)
			}
			stack.MustCLI(t, lane.env, &lane.proposal, "ai", "author", "--body-file",
				stack.SecretFile(t, map[string]string{"prompt": "Check " + lane.cliTarget}))
			spec := lane.proposal.Spec
			if lane.proposal.Source != "heuristic" || spec.Target != lane.cliTarget || spec.Type != "http" ||
				spec.IntervalSeconds != testspec.DefaultIntervalSeconds || spec.TimeoutSeconds != testspec.DefaultTimeoutSeconds || !spec.Enabled {
				t.Fatalf("CLI did not receive the schema-validated proposal: %+v", lane.proposal)
			}
			testsupport.RenderUI(t, lane.browser)
			var before []store.Test
			stack.MustCLI(t, lane.env, &before, "test", "list")
			if len(before) != 0 {
				t.Fatalf("CLI or browser proposal persisted tests: %+v", before)
			}
		})
	}
	if t.Failed() {
		return
	}
	for i := range lanes {
		lane := &lanes[i]
		t.Run(lane.name+"-confirm", func(t *testing.T) {
			spec := lane.proposal.Spec
			var created store.Test
			stack.MustCLI(t, lane.env, &created, "test", "create", "--name", spec.Name, "--type", spec.Type, "--target", spec.Target,
				"--interval", strconv.Itoa(spec.IntervalSeconds), "--timeout", strconv.Itoa(spec.TimeoutSeconds))
			if created.ID == "" || created.Name != spec.Name || created.Type != spec.Type || created.Target != spec.Target ||
				created.IntervalSeconds != spec.IntervalSeconds || created.TimeoutSeconds != spec.TimeoutSeconds || !created.Enabled {
				t.Fatalf("CLI confirmation lost the reviewed config: %+v", created)
			}
			const suggestions = `[aria-label="Suggested targets"]`
			browser := lane.browser
			browser.Expect = append(browser.Expect, lane.cliTarget)
			browser.Accessibility = true
			browser.Steps = append(browser.Steps,
				testsupport.RenderStep{Click: "Create test", Within: panel, Gone: true, ExpectWithin: "[data-targets-inventory]", Expect: []string{lane.uiTarget}},
				testsupport.RenderStep{Click: "Allow private or loopback targets for " + lane.observed, Role: "checkbox", Within: suggestions},
				testsupport.RenderStep{Click: "Add", Within: suggestions, Gone: true, ExpectWithin: panel, Expect: []string{"No suggestions yet"}},
			)
			testsupport.RenderUI(t, browser)
			var listed struct {
				Items []store.Test `json:"items"`
			}
			lane.do(t, stack, http.MethodGet, "/v1/tests", nil, &listed, http.StatusOK)
			lane.persisted = listed.Items
			expected := map[string]string{lane.cliTarget: "http", lane.uiTarget: "http", lane.observed: "icmp"}
			for _, row := range listed.Items {
				wantConsent := row.Target == lane.observed
				if row.ID == "" || row.TenantID != lane.id || row.Type != expected[row.Target] || !row.Enabled ||
					(row.Params["allow_private_targets"] == "true") != wantConsent {
					t.Fatalf("unexpected confirmed test: %+v", row)
				}
				delete(expected, row.Target)
			}
			if len(expected) != 0 {
				t.Fatalf("reviewed tests missing from the tenant inventory: %+v", expected)
			}
			var after discoveryResponse
			stack.MustCLI(t, lane.env, &after, "ai", "discover")
			if len(after.Proposals) != 0 {
				t.Fatalf("discovery continued to suggest the confirmed target: %+v", after.Proposals)
			}
		})
	}
	if t.Failed() {
		return
	}
	for i := range lanes {
		lane, peer := &lanes[i], &lanes[1-i]
		for _, row := range peer.persisted {
			lane.do(t, stack, http.MethodGet, "/v1/tests/"+row.ID, nil, nil, http.StatusNotFound)
		}
	}
}

func sendAuthoringObservations(t *testing.T, stack *shipped.Stack, lane *nativeLane) {
	t.Helper()
	conn, err := net.Dial("udp", lane.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	at := time.Now().UTC()
	ordinary := trafficVector{transport: 6, flags: 16, port: 42001, destinations: 1}
	for i := range 2 {
		stamp := at.Add(time.Duration(i-4) * time.Second)
		frame := controlledTrafficIPFIX(t, lane.octet, 0, 0, i, stamp, ordinary, 1000, 10)
		if n, err := conn.Write(frame); err != nil || n != len(frame) {
			t.Fatal("write synthetic flow observation to the loopback collector", err)
		}
	}
	plan := nativeGoldenPlan(lane.octet, at, []string{"dst_addr"})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		got := lane.query(t, stack, plan)
		if got.Totals["flows:total"] == "2" && len(got.Rows) == 1 &&
			got.Rows[0].Group["dst_addr"] == fmt.Sprintf("10.%d.1.1", lane.octet) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s observations did not become queryable in scoped ClickHouse", lane.name)
}
