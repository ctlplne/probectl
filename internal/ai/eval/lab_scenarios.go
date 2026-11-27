// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package eval

import (
	"time"

	"github.com/ctlplne/probectl/internal/ai"
)

// labScenarios normalizes scoped QA observations into independent RCA cases.
// The source tests establish the observed event or symptom. Their case data
// carries no tenant identities, credentials, route payloads, or customer names.
func labScenarios() []Scenario {
	changeAt := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	coldFaultAt := time.Date(2026, 10, 24, 14, 19, 37, 900_000_000, time.UTC)
	return []Scenario{
		{
			// The paired incident impact API fixture retains an original
			// 100-byte sampled flow with sampling factor three.
			Name: "lab-fx09-tagged-prefix-impact", Planes: []string{"flow", "entities"},
			Text:    "What traffic volume did the packet records attribute to the affected customer prefix?",
			Subject: map[string]string{"prefix": "203.0.113.0/24"},
			Metrics: []ai.Row{row("flow", "warning", "Affected traffic estimate 300 bytes", "The sampled flow contained 100 bytes at sampling factor three.")},
			Entities: []ai.Row{row("entities", "info", "Customer tag on affected prefix",
				"The current tenant assigned the customer tag to the observed prefix.")},
			ExpectLabels:   []string{"affected traffic estimate", "300 bytes"},
			RelevantTitles: []string{"Affected traffic estimate 300 bytes", "Customer tag on affected prefix"},
		},
		{
			// The routed path health fixture records the 100→230 original
			// Net-SNMP input error readings on the hop's owning interface.
			Name: "lab-fx10-routed-hop-error-climb", Planes: []string{"path", "device"},
			Text: "What changed at the affected hop along the routed path?",
			Entities: []ai.Row{
				row("network", "critical", "Ingress errors climbed from 100 to 230", "Two original interface counter polls show an increase of at least 130 errors."),
				row("path", "warning", "Trace traversed the polled interface", "The routed ICMP trace resolves the hop to the selected interface."),
			},
			ExpectLabels:   []string{"ingress errors climbed", "100", "230"},
			RelevantTitles: []string{"Ingress errors climbed from 100 to 230", "Trace traversed the polled interface"},
		},
		{
			// FX-11 observes the remaining path after an authenticated
			// session shutdown. Counter measurements are a separate witness.
			Name: "lab-fx11-surviving-link-load", Planes: []string{"bgp", "flow", "device"},
			Text: "Which BGP change explains the packet load on the surviving link?",
			Events: []ai.Row{row("bgp", "critical", "Primary BGP session shutdown displaced the selected route",
				"Both views had complete post-policy data before the controlled shutdown. The surviving route appeared afterward.")},
			Metrics:        []ai.Row{row("flow", "warning", "Traffic moved to the surviving link", "Measured directional counter load rose on the alternate interface after failover.")},
			ExpectLabels:   []string{"primary BGP session shutdown"},
			RelevantTitles: []string{"Primary BGP session shutdown displaced the selected route", "Traffic moved to the surviving link"},
		},
		{
			// The FRR change-effects proof records withdrawal and announcement
			// separately, preserving which observation came before recovery.
			Name: "lab-fx12-withdrawal-and-recovery", Planes: []string{"bgp", "change", "path"},
			Text: "Which route change preceded the path degradation?",
			Events: []ai.Row{
				timedRow("bgp", "critical", "Owned FRR route withdrawn", "The before/after timeline captured the selected route withdrawal.", changeAt, nil),
				timedRow("bgp", "info", "Selected route announced again", "A later announcement is retained as a separate change.", changeAt.Add(30*time.Second), nil),
			},
			Entities:       []ai.Row{row("path", "warning", "Original before and after path observations", "Actual path observations bracketed the recorded route change.")},
			ExpectLabels:   []string{"route withdrawn"},
			RelevantTitles: []string{"Owned FRR route withdrawn", "Selected route announced again", "Original before and after path observations"},
		},
		{
			Name: "lab-fx13-local-network", Planes: []string{"path", "device", "topology"},
			Text:    "Does the link event place the failure on our own network?",
			Subject: map[string]string{"node": "interface:lab-ingress"},
			Entities: []ai.Row{
				row("network", "critical", "Owned ingress interface lost carrier", "The original interface state records administrative up and operational down after the peer link was lowered."),
				row("path", "warning", "Selected interface is an owned backbone link", "The current tenant's role declaration identifies the interface that supplied the original link state."),
			},
			Topology:       []ai.Row{row("topology", "info", "Path boundary is inside the local network", "The affected interface is upstream of the carrier handoff.")},
			ExpectLabels:   []string{"owned ingress interface"},
			RelevantTitles: []string{"Owned ingress interface lost carrier", "Selected interface is an owned backbone link", "Path boundary is inside the local network"},
		},
		{
			Name: "lab-fx13-owned-carrier-handoff", Planes: []string{"path", "bgp", "device"},
			Text: "Which carrier handoff shows the fault on the affected route?",
			Events: []ai.Row{
				row("bgp", "critical", "Carrier BGP hold timer expired on the owned handoff", "The local router's original BMP notification reports a hold timer expiry for AS64496."),
			},
			Entities: []ai.Row{
				row("path", "warning", "Independent probes lost replies across the carrier handoff", "Two configured vantages transmitted their complete probes without receiving replies."),
				row("network", "info", "The owned carrier and backbone interfaces stayed up", "The observed interfaces retained administrative and operational state during the outage."),
			},
			ExpectLabels:   []string{"hold timer expired"},
			RelevantTitles: []string{"Carrier BGP hold timer expired on the owned handoff", "Independent probes lost replies across the carrier handoff", "The owned carrier and backbone interfaces stayed up"},
		},
		{
			Name: "lab-fx13-wider-internet", Planes: []string{"path", "network", "bgp"},
			Text: "Where does the path failure sit relative to our owned handoffs?",
			Entities: []ai.Row{
				row("path", "critical", "No-route errors came from beyond the owned handoff", "Two independent probes received matching no-route errors from the same external router."),
				row("network", "info", "The owned handoff and its BGP neighbor remained up", "The scoped link observations and physical Peer Up frame show healthy local coverage."),
			},
			Events: []ai.Row{
				row("bgp", "warning", "The selected responder route has a distinct external origin", "The stock FRR view places the responder in a prefix originated by AS64497 through carrier AS64496."),
			},
			ExpectLabels:   []string{"beyond the owned handoff"},
			RelevantTitles: []string{"No-route errors came from beyond the owned handoff", "The owned handoff and its BGP neighbor remained up", "The selected responder route has a distinct external origin"},
		},
		{
			// The routed verdict uses a modeled published range and original
			// verified same-origin responses from two probe namespaces.
			Name: "lab-fx13-remote-service-error", Planes: []string{"network", "metrics"},
			Text:           "Which provider range was corroborated by the remote HTTPS failures?",
			Entities:       []ai.Row{row("network", "critical", "Remote service returned HTTPS 503 from the AWS S3 range", "Independent probes verified the configured origin. Their socket peers matched the same fresh published range.")},
			Metrics:        []ai.Row{row("metrics", "warning", "Independent owned HTTPS probes failed", "Both vantages recorded 503 responses in the same window.")},
			ExpectLabels:   []string{"aws", "s3", "503"},
			RelevantTitles: []string{"Remote service returned HTTPS 503 from the AWS S3 range", "Independent owned HTTPS probes failed"},
		},
		{
			Name: "lab-fx13-thin-verdict", Planes: []string{"topology"},
			Text:    "Does the path topology support attributing the reported incident to a carrier?",
			Subject: map[string]string{"node": "interface:lab-handoff"},
			Topology: []ai.Row{row("topology", "info", "Configured carrier interface",
				"The handoff is known, but current fault observations are unavailable.")},
			ExpectInsufficient: true,
			RelevantTitles:     []string{"Configured carrier interface"},
		},
		{
			// The carrier fixture preserves per-source provenance. A known
			// control-plane trace does not supply missing agent-origin traces.
			Name: "lab-fx14-incomplete-vantage-coverage", Planes: []string{"topology"},
			Text:    "Where does the path topology place the first loss in the customer-side traces?",
			Subject: map[string]string{"node": "service:carrier-lab"},
			Topology: []ai.Row{row("topology", "info", "Only the control-plane origin is represented",
				"The carrier attachment labels its trace origin and does not claim independent agent-origin observations.")},
			ExpectInsufficient: true,
			RelevantTitles:     []string{"Only the control-plane origin is represented"},
		},
		{
			// G4(a) cold-stack lab incident. The routing signal opened the
			// incident and the failed service test joined it about 21 s later.
			Name: "qa-g4a-cold-stack-hijack-outage", Planes: []string{"bgp", "network", "metrics"},
			Text: "Why did the lab service become unreachable when the monitored BGP route changed?",
			Events: []ai.Row{timedRow("bgp", "critical", "Monitored prefix announced by unexpected AS65021",
				"The scoped isolated replay produced the wrong origin; the expected origin was AS64500.", coldFaultAt, nil)},
			Entities: []ai.Row{timedRow("network", "critical", "Service down signal joined the routing incident",
				"The affected service was in the same monitored prefix.", coldFaultAt.Add(21*time.Second), nil)},
			Metrics:        []ai.Row{row("metrics", "warning", "Service probe success fell to zero", "The service check failed in the incident window.")},
			ExpectLabels:   []string{"unexpected AS65021"},
			RelevantTitles: []string{"Monitored prefix announced by unexpected AS65021", "Service down signal joined the routing incident", "Service probe success fell to zero"},
		},
		{
			// Shipped two-tenant F13 lab, second incident. The separate
			// no-transit route leak did not coincide with a local service outage.
			Name: "qa-f13-route-leak-with-service-up", Planes: []string{"bgp", "metrics"},
			Text:           "What route anomaly was observed for the owned prefix without a service timeout?",
			Subject:        map[string]string{"prefix": "198.51.100.0/24"},
			Events:         []ai.Row{row("bgp", "critical", "Route leak through no-transit AS64666", "The scoped analyzer identified the disallowed transit AS on this prefix.")},
			Metrics:        []ai.Row{row("metrics", "info", "Local service stayed reachable", "The probe remained healthy during the separate routing incident.")},
			ExpectLabels:   []string{"route leak", "AS64666"},
			RelevantTitles: []string{"Route leak through no-transit AS64666", "Local service stayed reachable"},
		},
	}
}
