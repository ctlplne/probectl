// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package endpoint_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type shippedEndpointLane struct {
	id, slug, cookie, agent, target string
}

type shippedEndpointFleet struct {
	Running bool            `json:"collector_running"`
	Items   []endpoint.View `json:"items"`
}

func TestLinuxEndpointsReachOnlyTheirOwnShippedFleet(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the shipped endpoint receipt runs on Linux")
	}
	stack := shipped.Start(t, shipped.Options{Name: "endpointlinux", TenantBand: 3})
	operator := stack.OnboardOperator(t, "root@msp-endpoint-receipt.example")
	// Go's Linux trust loader accepts the fixture CA for endpoint processes.
	// Browser and control-plane trust continue to use their ordinary fixtures.
	t.Setenv("SSL_CERT_FILE", stack.CAFile)
	t.Setenv("PROBECTL_ENDPOINT_METRICS_TLS_CERT_FILE", stack.ServerCert)
	t.Setenv("PROBECTL_ENDPOINT_METRICS_TLS_KEY_FILE", stack.ServerKey)
	t.Setenv("PROBECTL_ENDPOINT_COLLECT_SSID", "false")
	t.Setenv("PROBECTL_ENDPOINT_COLLECT_BSSID", "false")
	t.Setenv("PROBECTL_ENDPOINT_COLLECT_GATEWAY_IP", "false")
	t.Setenv("PROBECTL_ENDPOINT_COLLECT_PUBLIC_HOPS", "false")
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [2]shippedEndpointLane{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		lane.slug = fmt.Sprintf("endpoint-%s-%d", stamp, i)
		lane.target = stack.BaseURL + "/readyz?origin=" + lane.slug
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"hybrid"}`, lane.slug, lane.slug))
		lane.id = tenant.ID
		lane.cookie = stack.SignIn(t, lane.id, email, lane.slug)
		lane.agent = uuid.NewString()
		stack.EnrollAgent(t, lane.id, lane.agent, lane.slug)
		brokers, err := json.Marshal(testsupport.KafkaBrokers())
		if err != nil {
			t.Fatal(err)
		}
		stack.StartCollector(t, "probectl-endpoint", lane.slug, "PROBECTL_ENDPOINT", fmt.Sprintf(`apiVersion: probectl.io/endpoint/v1
tenant_id: %q
agent_id: %q
bus:
  mode: kafka
  brokers: %s
  namespace: %q
interval: 2s
max_hops: 3
probes: 1
session_timeout: 5s
targets: [%q]
`, lane.id, lane.agent, brokers, "t-"+lane.slug, lane.target))
	}
	for _, lane := range lanes {
		shipped.Await(t, lane.slug+" successful HTTPS session in the endpoint fleet", 75*time.Second, func() bool {
			got := readShippedEndpointFleet(t, stack, lane.cookie)
			for _, view := range got.Items {
				if view.AgentID == lane.agent {
					for _, session := range view.Sessions {
						if session.Success && session.Target == lane.target && session.Metrics["status"] == http.StatusOK {
							return true
						}
					}
				}
			}
			return false
		})
	}
	for _, lane := range lanes {
		stack.Stop(t, lane.slug)
	}
	stack.RestartControl(t, "control-restarted-endpoints", nil)
	for i, lane := range lanes {
		sibling := lanes[1-i]
		got := readShippedEndpointFleet(t, stack, lane.cookie)
		checkShippedEndpointFleet(t, lane, got)
		token := stack.APIToken(t, lane.cookie, "agent.read")
		var output json.RawMessage
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &output, "endpoint", "list")
		if !bytes.Contains(output, []byte(lane.agent)) || bytes.Contains(output, []byte(sibling.agent)) {
			t.Fatal("the endpoint CLI output did not retain its exact tenant's fleet")
		}
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/endpoints", CAFile: stack.CAFile, TrustCertFiles: stack.TrustCerts(),
			Theme:   []string{"light", "dark"}[i],
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			Expect:  []string{"Endpoints", lane.agent}, Absent: []string{sibling.agent},
		})
	}
}

func readShippedEndpointFleet(t *testing.T, stack *shipped.Stack, cookie string) shippedEndpointFleet {
	t.Helper()
	code, body := stack.Do(t, cookie, http.MethodGet, "/v1/endpoints", nil)
	var out shippedEndpointFleet
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil || !out.Running {
		t.Fatalf("the active endpoint collector could not be read: status %d", code)
	}
	return out
}

func checkShippedEndpointFleet(t *testing.T, lane shippedEndpointLane, got shippedEndpointFleet) {
	t.Helper()
	if len(got.Items) != 1 || got.Items[0].AgentID != lane.agent || got.Items[0].Attribution == nil {
		t.Fatalf("expected the owned endpoint and its attribution after restart: %+v", got)
	}
	view := got.Items[0]
	if len(view.Sessions) != 1 || view.Sessions[0].Target != lane.target || !view.Sessions[0].Success ||
		view.Sessions[0].Type != endpoint.TypeSession || view.Sessions[0].Metrics["status"] != http.StatusOK {
		t.Fatalf("expected the exact TLS target after restart: %+v", view.Sessions)
	}
	if view.WiFi != nil {
		for key, value := range view.WiFi.Attributes {
			if value != "" && strings.Contains(key, "ssid") {
				t.Fatal("the disabled endpoint network identifiers reached the API")
			}
		}
	}
}
