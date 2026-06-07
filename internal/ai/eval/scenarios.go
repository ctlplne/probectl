package eval

import "github.com/imfeelingtheagi/probectl/internal/ai"

// row builds a planted evidence row.
func row(plane, severity, title, summary string) ai.Row {
	return ai.Row{"plane": plane, "severity": severity, "title": title, "summary": summary}
}

// distractor is an irrelevant-but-present signal (the noise every real
// incident has); citing it costs precision.
func distractor() ai.Row {
	return row("entities", "info", "Scheduled maintenance window notice", "routine notice, unrelated to the question")
}

// Scenarios is the U-049 eval set: >=20 labeled cases across planes. Most are
// solvable by a sound cause-vs-symptom ranking; a few are deliberately hard
// (mis-ranking traps marked HARD) so the score discriminates — a perfect 1.0
// would mean the set is too easy to catch regressions.
func Scenarios() []Scenario {
	return []Scenario{
		{
			Name: "deploy-caused-latency", Planes: []string{"change", "metrics"},
			Text:    "Why is checkout slow since the last deploy?",
			Subject: map[string]string{"target": "checkout"},
			Events:  []ai.Row{row("change", "critical", "Deploy checkout v2.31", "rollout of checkout v2.31 to production")},
			Metrics: []ai.Row{row("metrics", "warning", "p99 latency 2.4s on checkout", "latency regression after 14:02")},
			Entities: []ai.Row{
				row("incident", "high", "Checkout latency incident", "correlated latency degradation"),
				distractor(),
			},
			ExpectLabels:   []string{"Deploy checkout v2.31"},
			RelevantTitles: []string{"Deploy checkout v2.31", "p99 latency 2.4s on checkout", "Checkout latency incident"},
		},
		{
			Name: "bgp-prefix-hijack", Planes: []string{"bgp", "metrics"},
			Text:           "Did a bgp hijack make 203.0.113.0/24 unreachable?",
			Subject:        map[string]string{"prefix": "203.0.113.0/24"},
			Events:         []ai.Row{row("bgp", "critical", "Origin change for 203.0.113.0/24", "unexpected origin AS64511 announced the prefix")},
			Metrics:        []ai.Row{row("metrics", "warning", "Reachability loss to 203.0.113.0/24", "probe success rate fell to 8%")},
			ExpectLabels:   []string{"Origin change for 203.0.113.0/24"},
			RelevantTitles: []string{"Origin change for 203.0.113.0/24", "Reachability loss to 203.0.113.0/24"},
		},
		{
			Name: "bgp-route-withdrawal", Planes: []string{"bgp", "entities"},
			Text:   "Why did routes to 198.51.100.0/24 get withdrawn?",
			Events: []ai.Row{row("bgp", "critical", "Route withdrawn for 198.51.100.0/24", "upstream AS64500 withdrew the prefix")},
			Entities: []ai.Row{
				row("incident", "high", "Prefix unreachable incident", "reachability incident for 198.51.100.0/24"),
				distractor(),
			},
			ExpectLabels:   []string{"Route withdrawn for 198.51.100.0/24"},
			RelevantTitles: []string{"Route withdrawn for 198.51.100.0/24", "Prefix unreachable incident"},
		},
		{
			Name: "expired-tls-cert", Planes: []string{"threat", "metrics"},
			Text:           "Why are tls errors spiking for api.example.com?",
			Subject:        map[string]string{"target": "api.example.com"},
			Events:         []ai.Row{row("threat", "critical", "TLS certificate expired for api.example.com", "leaf certificate expired at 09:00 UTC")},
			Metrics:        []ai.Row{row("metrics", "warning", "HTTPS error rate 41%", "handshake failures dominate errors")},
			ExpectLabels:   []string{"TLS certificate expired"},
			RelevantTitles: []string{"TLS certificate expired for api.example.com", "HTTPS error rate 41%"},
		},
		{
			Name: "config-push-broke-dns", Planes: []string{"change", "metrics"},
			Text:           "DNS lookups time out after the resolver config push — why?",
			Events:         []ai.Row{row("change", "critical", "Config push to resolver fleet", "ACL update applied to all resolvers")},
			Metrics:        []ai.Row{row("metrics", "critical", "DNS timeout rate 87%", "SERVFAIL/timeouts across regions")},
			ExpectLabels:   []string{"Config push to resolver fleet"},
			RelevantTitles: []string{"Config push to resolver fleet", "DNS timeout rate 87%"},
		},
		{
			Name: "transit-path-loss", Planes: []string{"path", "metrics"},
			Text: "Where is the packet loss to eu-west coming from?",
			Entities: []ai.Row{
				row("path", "critical", "Packet loss on transit hop ae-3.tier1.net", "12% loss introduced at hop 7"),
				distractor(),
			},
			Metrics:        []ai.Row{row("metrics", "warning", "Jitter 38ms on eu-west probes", "jitter elevated since 11:20")},
			ExpectLabels:   []string{"Packet loss on transit hop ae-3.tier1.net"},
			RelevantTitles: []string{"Packet loss on transit hop ae-3.tier1.net", "Jitter 38ms on eu-west probes"},
		},
		{
			Name: "device-interface-down", Planes: []string{"network", "metrics"},
			Text:           "Why is the branch site down?",
			Entities:       []ai.Row{row("network", "critical", "Interface Gi0/0/1 down on edge-rtr-2", "link down trap + ifOperStatus=down")},
			Metrics:        []ai.Row{row("metrics", "critical", "Branch site unreachable", "all probes failing since 08:14")},
			ExpectLabels:   []string{"Interface Gi0/0/1 down on edge-rtr-2"},
			RelevantTitles: []string{"Interface Gi0/0/1 down on edge-rtr-2", "Branch site unreachable"},
		},
		{
			Name: "rollout-l7-error-spike", Planes: []string{"change", "ebpf/l7"},
			Text:           "What is causing the payments-svc HTTP 5xx spike? Any recent rollout?",
			Subject:        map[string]string{"target": "payments-svc"},
			Events:         []ai.Row{row("change", "warning", "Rollout of payments-svc 9.2", "canary promoted to 100%")},
			Metrics:        []ai.Row{row("metrics", "warning", "L7 error rate 9.8% on payments-svc", "5xx concentrated on /charge")},
			ExpectLabels:   []string{"Rollout of payments-svc 9.2"},
			RelevantTitles: []string{"Rollout of payments-svc 9.2", "L7 error rate 9.8% on payments-svc"},
		},
		{
			Name: "release-slo-burn", Planes: []string{"change", "slo"},
			Text:           "Why is the web-frontend SLO burning down so fast?",
			Events:         []ai.Row{row("change", "critical", "Release web-frontend 4.0", "major release shipped at 10:00")},
			Metrics:        []ai.Row{row("metrics", "critical", "SLO burn rate 14x on web-frontend", "error budget exhausted in 6h at this rate")},
			ExpectLabels:   []string{"Release web-frontend 4.0"},
			RelevantTitles: []string{"Release web-frontend 4.0", "SLO burn rate 14x on web-frontend"},
		},
		{
			Name: "syn-flood-anomaly", Planes: []string{"threat", "metrics"},
			Text:           "Is this a security anomaly? Inbound traffic doubled in minutes.",
			Events:         []ai.Row{row("threat", "critical", "Traffic anomaly: inbound SYN flood", "SYN rate 40x baseline from 1.2k sources")},
			Metrics:        []ai.Row{row("metrics", "warning", "Connection table saturation on edge LB", "conntrack 96% full")},
			ExpectLabels:   []string{"SYN flood"},
			RelevantTitles: []string{"Traffic anomaly: inbound SYN flood", "Connection table saturation on edge LB"},
		},
		{
			Name: "peer-session-flap", Planes: []string{"bgp", "metrics"},
			Text:           "Latency to the peering fabric keeps oscillating — is a bgp peer flapping?",
			Events:         []ai.Row{row("bgp", "warning", "Peer AS64500 session flap", "session reset 6 times in 30m")},
			Metrics:        []ai.Row{row("metrics", "warning", "Latency oscillation on IX path", "rtt alternating 12ms/80ms")},
			ExpectLabels:   []string{"Peer AS64500 session flap"},
			RelevantTitles: []string{"Peer AS64500 session flap", "Latency oscillation on IX path"},
		},
		{
			Name: "cdn-origin-unreachable", Planes: []string{"path", "topology"},
			Text:    "Users behind fra-1 see errors; is the path to origin broken?",
			Subject: map[string]string{"target": "origin-cluster"},
			Entities: []ai.Row{
				row("path", "critical", "Origin unreachable via POP fra-1", "traceroute dies after the POP egress"),
			},
			Topology:       []ai.Row{{"node": "service:origin-cluster", "kind": "service", "label": "origin-cluster", "plane": "topology", "title": "origin-cluster dependency"}},
			ExpectLabels:   []string{"Origin unreachable via POP fra-1"},
			RelevantTitles: []string{"Origin unreachable via POP fra-1", "origin-cluster dependency"},
		},
		{
			Name: "db-failover-change", Planes: []string{"change", "metrics"},
			Text:           "Queries started timing out at 03:12 — was there a config change or failover?",
			Events:         []ai.Row{row("change", "critical", "Failover of pg-primary to replica-2", "automatic failover triggered by health check")},
			Metrics:        []ai.Row{row("metrics", "critical", "Query timeout rate 22%", "connection pool exhaustion follows failover")},
			ExpectLabels:   []string{"Failover of pg-primary to replica-2"},
			RelevantTitles: []string{"Failover of pg-primary to replica-2", "Query timeout rate 22%"},
		},
		{
			Name: "mtls-ca-rotation-breakage", Planes: []string{"change", "threat"},
			Text: "Service-to-service tls handshakes fail after the cert rotation — root cause?",
			Events: []ai.Row{
				row("change", "critical", "Rotated mTLS CA bundle", "new CA bundle pushed fleet-wide"),
				row("threat", "warning", "TLS handshake failure burst", "alerts across 14 services"),
			},
			ExpectLabels:   []string{"Rotated mTLS CA bundle"},
			RelevantTitles: []string{"Rotated mTLS CA bundle", "TLS handshake failure burst"},
		},
		{
			Name: "route-leak-upstream", Planes: []string{"bgp", "metrics"},
			Text:           "Traffic to apac suddenly routes through AS64511 with high loss — a route leak?",
			Events:         []ai.Row{row("bgp", "critical", "Route leak via AS64511", "more-specifics leaked to transit, path detour")},
			Metrics:        []ai.Row{row("metrics", "warning", "Loss 18% on apac paths", "loss began with the path change")},
			ExpectLabels:   []string{"Route leak via AS64511"},
			RelevantTitles: []string{"Route leak via AS64511", "Loss 18% on apac paths"},
		},
		{
			Name: "firewall-rule-block", Planes: []string{"change", "metrics"},
			Text:           "Internal 10.x targets became unreachable after a config push — which change?",
			Events:         []ai.Row{row("change", "critical", "Firewall policy update DENY 10.0.0.0/8", "deny rule shadowing internal routes")},
			Metrics:        []ai.Row{row("metrics", "critical", "Probe failures to internal ranges", "100% failure to 10.0.0.0/8 targets")},
			ExpectLabels:   []string{"Firewall policy update DENY 10.0.0.0/8"},
			RelevantTitles: []string{"Firewall policy update DENY 10.0.0.0/8", "Probe failures to internal ranges"},
		},
		{
			Name: "dns-divergence-threat", Planes: []string{"threat", "metrics"},
			Text:           "Some regions resolve api.example.com to an unknown IP — dns security issue?",
			Events:         []ai.Row{row("threat", "critical", "DNS responses diverge from authoritative", "resolver answers differ from authoritative records in 3 regions")},
			Metrics:        []ai.Row{row("metrics", "warning", "NXDOMAIN rate elevated", "lookup failures clustered in affected regions")},
			ExpectLabels:   []string{"DNS responses diverge from authoritative"},
			RelevantTitles: []string{"DNS responses diverge from authoritative", "NXDOMAIN rate elevated"},
		},
		{
			Name: "kernel-upgrade-flow-gap", Planes: []string{"change", "ebpf"},
			Text:           "Flow telemetry from the fleet dropped to zero after the node upgrades — why?",
			Events:         []ai.Row{row("change", "warning", "Node kernel upgrade to 6.8", "staged kernel upgrade across the fleet")},
			Metrics:        []ai.Row{row("metrics", "critical", "eBPF flow events gap", "agents report attach failures after reboot")},
			ExpectLabels:   []string{"Node kernel upgrade to 6.8"},
			RelevantTitles: []string{"Node kernel upgrade to 6.8", "eBPF flow events gap"},
		},
		{
			Name: "autoscaler-cost-spike", Planes: []string{"change", "cost"},
			Text:           "Egress cost doubled overnight — did a config change cause it?",
			Events:         []ai.Row{row("change", "warning", "Autoscaler policy change", "min replicas raised 3 -> 12 in all regions")},
			Metrics:        []ai.Row{row("metrics", "warning", "Egress cost rate 2.1x baseline", "cost spike tracks replica count")},
			ExpectLabels:   []string{"Autoscaler policy change"},
			RelevantTitles: []string{"Autoscaler policy change", "Egress cost rate 2.1x baseline"},
		},
		{
			Name: "ix-maintenance-reroute", Planes: []string{"bgp", "path"},
			Text: "Why did the IX path change and latency rise during the night?",
			Events: []ai.Row{
				row("bgp", "warning", "IX maintenance: paths shifted to backup transit", "planned maintenance drained the IX port"),
			},
			Metrics:        []ai.Row{row("metrics", "warning", "Latency +22ms via backup transit", "rtt rose when the path moved")},
			ExpectLabels:   []string{"IX maintenance"},
			RelevantTitles: []string{"IX maintenance: paths shifted to backup transit", "Latency +22ms via backup transit"},
		},
		{
			// HARD: cause-plane trap — an unrelated info-severity change event
			// outranks the true BGP cause for any plane-weight-only ranking.
			Name: "hard-bgp-cause-with-change-noise", Planes: []string{"bgp", "change"},
			Text: "Prefix 192.0.2.0/24 went unreachable — was it the routing or the unrelated deploy?",
			Events: []ai.Row{
				row("bgp", "critical", "RPKI-invalid announcement for 192.0.2.0/24", "invalid origin dropped by peers"),
				row("change", "info", "Unrelated dev-cluster deploy", "dev environment deploy, no prod impact"),
			},
			Metrics:        []ai.Row{row("metrics", "critical", "Reachability 0% for 192.0.2.0/24", "all vantage points fail")},
			ExpectLabels:   []string{"RPKI-invalid announcement"},
			RelevantTitles: []string{"RPKI-invalid announcement for 192.0.2.0/24", "Reachability 0% for 192.0.2.0/24"},
		},
		{
			// HARD: two same-plane candidates; only severity+summary disambiguate.
			Name: "hard-two-changes-one-cause", Planes: []string{"change", "metrics"},
			Text: "Checkout errors after this morning's deploys — which change broke it?",
			Events: []ai.Row{
				row("change", "critical", "Deploy checkout v3.0 (schema migration)", "migration locked the orders table"),
				row("change", "info", "Deploy docs-site v1.2", "static site refresh"),
			},
			Metrics:        []ai.Row{row("metrics", "critical", "Checkout error rate 31%", "DB lock wait timeouts")},
			ExpectLabels:   []string{"Deploy checkout v3.0"},
			RelevantTitles: []string{"Deploy checkout v3.0 (schema migration)", "Checkout error rate 31%"},
		},
		{
			// Symptom-only: no cause is present; best honest answer names the
			// dominant symptom rather than inventing a cause.
			Name: "symptom-only-latency", Planes: []string{"metrics"},
			Text:           "Why is everything slow in us-east?",
			Metrics:        []ai.Row{row("metrics", "warning", "Regional latency elevated in us-east", "p95 up 60% across services")},
			ExpectLabels:   []string{"Regional latency elevated in us-east"},
			RelevantTitles: []string{"Regional latency elevated in us-east"},
		},
		{
			// Negative control: nothing planted — the only correct answer is
			// "insufficient evidence" (honesty over fabrication).
			Name: "negative-control-no-signals", Planes: []string{"none"},
			Text:               "Why is service ghost-svc degraded?",
			ExpectInsufficient: true,
		},
	}
}
