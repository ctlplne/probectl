// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { BadgeTone } from '../components/Badge'

export interface DemoMetric {
  label: string
  value: string
  detail: string
  tone: BadgeTone
}

export interface DemoTableRow {
  id: string
  cells: string[]
  tone?: BadgeTone
}

export interface DemoTableModel {
  title: string
  description: string
  columns: string[]
  rows: DemoTableRow[]
}

export type DemoVizKind = 'incident-clock' | 'path-graph' | 'time-series'

/** Declares which sample visualization the page mounts; the heavy component
 * and its static props live in the lazily-loaded DemoViz chunk. */
export interface DemoVizSpec {
  kind: DemoVizKind
  title: string
  description: string
}

export interface DemoPageModel {
  path: string
  kicker: string
  title: string
  description: string
  metrics: DemoMetric[]
  viz?: DemoVizSpec
  primary: DemoTableModel
  secondary: DemoTableModel
}

const metric = (
  label: string,
  value: string,
  detail: string,
  tone: BadgeTone = 'neutral',
): DemoMetric => ({ label, value, detail, tone })

const row = (id: string, cells: string[], tone?: BadgeTone): DemoTableRow => ({ id, cells, tone })

const table = (
  title: string,
  description: string,
  columns: string[],
  rows: DemoTableRow[],
): DemoTableModel => ({ title, description, columns, rows })

export const DEMO_PAGES: Record<string, DemoPageModel> = {
  '/onboarding': {
    path: '/onboarding',
    kicker: 'Guided setup',
    title: 'Get started',
    description:
      'A sample deployment progressing from connected producers to its first correlated finding.',
    metrics: [
      metric('Setup progress', '82%', '9 of 11 milestones', 'info'),
      metric('Signals connected', '5 / 5', 'All core planes represented', 'success'),
      metric('Reporting agents', '12', 'Across three sample regions', 'success'),
      metric('First insight', 'Ready', 'Cross-plane evidence available', 'accent'),
    ],
    primary: table(
      'Signal readiness',
      'Illustrative producers and their most recent sample ingest.',
      ['Signal', 'Producer', 'Last ingest', 'State'],
      [
        row('synthetic', ['Synthetic', '3 canaries', '1 min ago', 'Ready'], 'success'),
        row('flow', ['Flow', '2 exporters', '2 min ago', 'Ready'], 'success'),
        row('bgp', ['BGP', 'RIS + edge-r1', '4 min ago', 'Ready'], 'success'),
        row('ebpf', ['eBPF', '7 hosts', '1 min ago', 'Ready'], 'success'),
      ],
    ),
    secondary: table(
      'Guided milestones',
      'A safe sample walkthrough; actions are intentionally non-operational.',
      ['Milestone', 'Outcome', 'Owner', 'State'],
      [
        row(
          'tenant',
          ['Create tenant boundary', 'Default Tenant', 'Platform', 'Complete'],
          'success',
        ),
        row(
          'collector',
          ['Register collectors', '5 signal types', 'Network', 'Complete'],
          'success',
        ),
        row('slo', ['Define checkout SLO', '99.95% target', 'SRE', 'In review'], 'warning'),
      ],
    ),
  },
  '/targets': {
    path: '/targets',
    kicker: 'Active monitoring',
    title: 'Targets & active tests',
    description:
      'Synthetic checks show reachability, latency, and DNS behavior from sample canaries.',
    metrics: [
      metric('Healthy tests', '23 / 24', 'One degraded check', 'success'),
      metric('Availability', '99.95%', 'Rolling sample window', 'success'),
      metric('HTTP p95', '42 ms', 'Checkout endpoint', 'info'),
      metric('Scheduled runs', '6', 'Due in the next minute', 'accent'),
    ],
    primary: table(
      'Active tests',
      'Representative synthetic checks across three sample regions.',
      ['Test', 'Type', 'Region', 'Result'],
      [
        row('checkout', ['checkout-http', 'HTTPS', 'us-east', 'Healthy · 38 ms'], 'success'),
        row('edge-dns', ['edge-dns', 'DNS', 'eu-west', 'Degraded · 118 ms'], 'warning'),
        row('payments', ['payments-tcp', 'TCP', 'us-west', 'Healthy · 24 ms'], 'success'),
        row('portal', ['portal-journey', 'Browser', 'us-east', 'Healthy · 1.2 s'], 'success'),
      ],
    ),
    secondary: table(
      'Recent runs',
      'Sample results are illustrative and cannot create alerts.',
      ['Time', 'Target', 'Observation', 'State'],
      [
        row('run-1', ['09:44 UTC', 'checkout.example', 'TLS + HTTP 200', 'Passed'], 'success'),
        row('run-2', ['09:43 UTC', 'resolver.example', 'Slow recursion', 'Investigate'], 'warning'),
        row('run-3', ['09:42 UTC', 'payments.example', 'Handshake 24 ms', 'Passed'], 'success'),
      ],
    ),
  },
  '/path': {
    path: '/path',
    kicker: 'Route intelligence',
    title: 'Path analysis',
    description:
      'Sample hop-by-hop evidence connects a latency change to routing and interface behavior.',
    metrics: [
      metric('Observed paths', '18', 'Across sample targets', 'info'),
      metric('Route changes', '2', 'Within the sample window', 'warning'),
      metric('Peak loss', '3.8%', 'At transit hop 6', 'danger'),
      metric('ECMP branches', '3', 'For checkout traffic', 'accent'),
    ],
    viz: {
      kind: 'path-graph',
      title: 'Hop-by-hop path evidence',
      description:
        'ECMP branches, MPLS context, and the lossy transit hop — the same sample evidence the tables cite, drawn as the network saw it.',
    },
    primary: table(
      'Checkout path',
      'Illustrative path from canary-us-east to checkout.',
      ['Hop', 'Node', 'RTT', 'Observation'],
      [
        row('hop-1', ['1', 'canary-us-east', '1 ms', 'Origin'], 'success'),
        row('hop-3', ['3', 'edge-r1', '8 ms', 'Stable'], 'success'),
        row('hop-6', ['6', 'transit-as64510', '67 ms', '3.8% loss'], 'danger'),
        row('hop-9', ['9', 'checkout', '91 ms', 'Destination'], 'warning'),
      ],
    ),
    secondary: table(
      'Path changes',
      'Round comparison highlights only changed sample evidence.',
      ['Round', 'AS path', 'Delta', 'Assessment'],
      [
        row('round-current', ['Current', '64500 → 64510 → 64520', '+49 ms', 'Changed'], 'warning'),
        row(
          'round-previous',
          ['Previous', '64500 → 64511 → 64520', 'Baseline', 'Stable'],
          'success',
        ),
        row('round-alt', ['ECMP branch', '64500 → 64512 → 64520', '+7 ms', 'Healthy'], 'success'),
      ],
    ),
  },
  '/planes': {
    path: '/planes',
    kicker: 'Unified telemetry',
    title: 'Planes',
    description:
      'A sample cross-plane inventory shows what each producer contributes to the same incident clock.',
    metrics: [
      metric('Planes ready', '5 / 5', 'Synthetic, BGP, flow, device, eBPF', 'success'),
      metric('Correlated signals', '9', 'One incident window', 'accent'),
      metric('Sample regions', '3', 'US East, US West, EU West', 'info'),
      metric('Late producers', '1', 'Device poller is 4 min behind', 'warning'),
    ],
    primary: table(
      'Plane status',
      'Sample producer coverage and ingest freshness.',
      ['Plane', 'Coverage', 'Last ingest', 'State'],
      [
        row('synthetic', ['Synthetic', '24 tests', '1 min ago', 'Ready'], 'success'),
        row('bgp', ['BGP', '18 paths', '2 min ago', 'Ready'], 'success'),
        row('flow', ['Flow', '113 edges', '1 min ago', 'Ready'], 'success'),
        row('device', ['Device', '14 nodes', '4 min ago', 'Delayed'], 'warning'),
        row('ebpf', ['eBPF', '7 hosts', '1 min ago', 'Ready'], 'success'),
      ],
    ),
    secondary: table(
      'Cross-plane evidence',
      'Signals aligned to the sample checkout incident.',
      ['Time', 'Plane', 'Evidence', 'Confidence'],
      [
        row('evidence-1', ['09:37 UTC', 'BGP', 'AS path changed', 'High'], 'success'),
        row('evidence-2', ['09:38 UTC', 'Flow', 'Transit volume shifted 41%', 'High'], 'success'),
        row('evidence-3', ['09:39 UTC', 'Synthetic', 'p95 rose to 91 ms', 'High'], 'success'),
      ],
    ),
  },
  // DPR-145: the tour's Planes item used to be the whole story, and every
  // /planes/<plane> route fell back to it — four navigation destinations
  // rendering one page. A tour of a five-plane product that cannot show a plane
  // is the wrong shape, and on a hosted demo it reads as four broken links.
  // Addresses throughout are RFC 5737 documentation space (DPR-146).
  '/planes/synthetic': {
    path: '/planes/synthetic',
    kicker: 'Active measurement',
    title: 'Synthetic plane',
    description:
      'Sample checks running from three regions, with the p95 that moved before any alert fired.',
    metrics: [
      metric('Checks', '24', 'HTTP, DNS, ICMP, and path', 'info'),
      metric('Healthy', '23 / 24', 'One degraded DNS check', 'success'),
      metric('Worst p95', '91 ms', 'Checkout, US East', 'warning'),
      metric('Agents reporting', '6', 'Across three sample regions', 'accent'),
    ],
    primary: table(
      'Checks in the sample window',
      'Illustrative results by check and region.',
      ['Check', 'Type', 'Region', 'p95', 'State'],
      [
        row('chk-1', ['checkout', 'HTTP', 'US East', '91 ms', 'Degraded'], 'warning'),
        row('chk-2', ['checkout', 'HTTP', 'EU West', '38 ms', 'Healthy'], 'success'),
        row('chk-3', ['payments', 'HTTP', 'US East', '42 ms', 'Healthy'], 'success'),
        row('chk-4', ['auth-dns', 'DNS', 'US West', '—', 'Degraded'], 'warning'),
        row('chk-5', ['edge-gw', 'ICMP', 'US East', '4 ms', 'Healthy'], 'success'),
      ],
    ),
    secondary: table(
      'What the plane contributed',
      'Sample signals this plane raised into the shared incident clock.',
      ['Time', 'Signal', 'Detail'],
      [
        row('syn-1', ['09:37 UTC', 'p95 step', 'checkout US East 44 ms to 91 ms'], 'warning'),
        row('syn-2', ['09:41 UTC', 'DNS timeout', 'auth-dns, one of three resolvers'], 'warning'),
        row('syn-3', ['09:44 UTC', 'Recovery', 'checkout p95 back under target'], 'success'),
      ],
    ),
  },
  '/planes/bgp': {
    path: '/planes/bgp',
    kicker: 'Routing',
    title: 'BGP plane',
    description:
      'Sample routing events for the monitored prefixes, with RPKI state alongside each change.',
    metrics: [
      metric('Monitored prefixes', '12', 'Across three sample origins', 'info'),
      metric('Paths seen', '18', 'From the sample collectors', 'accent'),
      metric('Origin changes', '1', 'Within the sample window', 'warning'),
      metric('RPKI invalid', '0', 'No invalid announcement observed', 'success'),
    ],
    primary: table(
      'Routing events',
      'Illustrative announcements and withdrawals.',
      ['Time', 'Prefix', 'Origin', 'RPKI', 'Event'],
      [
        row('bgp-1', ['09:37 UTC', '203.0.113.0/24', 'AS64501', 'Valid', 'Origin changed'], 'warning'),
        row('bgp-2', ['09:38 UTC', '198.51.100.0/24', 'AS64500', 'Valid', 'Path lengthened'], 'info'),
        row('bgp-3', ['09:39 UTC', '192.0.2.0/24', 'AS64500', 'Valid', 'Announced'], 'success'),
      ],
    ),
    secondary: table(
      'Collector coverage',
      'Which sample collectors saw the change, and when.',
      ['Collector', 'Peers', 'First seen', 'State'],
      [
        row('col-1', ['rrc00', '42', '09:37 UTC', 'Ready'], 'success'),
        row('col-2', ['route-views2', '38', '09:37 UTC', 'Ready'], 'success'),
        row('col-3', ['local BMP', '2', '09:38 UTC', 'Ready'], 'success'),
      ],
    ),
  },
  '/planes/flow': {
    path: '/planes/flow',
    kicker: 'Traffic',
    title: 'Flow plane',
    description:
      'Sample NetFlow, IPFIX, and sFlow records folded into service edges and cost classes.',
    metrics: [
      metric('Exporters', '3', 'NetFlow v5, IPFIX, sFlow v5', 'info'),
      metric('Service edges', '113', 'Tenant-scoped sample edges', 'accent'),
      metric('Decode errors', '0', 'Every record parsed', 'success'),
      metric('Inter-region share', '41%', 'Shifted during the window', 'warning'),
    ],
    primary: table(
      'Top talkers in the sample window',
      'Illustrative conversations by volume.',
      ['Source', 'Destination', 'Port', 'Class', 'Share'],
      [
        row('flow-1', ['198.51.100.21', '203.0.113.20', '443', 'inter_region', '18%'], 'warning'),
        row('flow-2', ['198.51.100.22', '198.51.100.40', '5432', 'intra_az', '14%'], 'success'),
        row('flow-3', ['198.51.100.23', '192.0.2.9', '443', 'internet_egress', '11%'], 'info'),
        row('flow-4', ['203.0.113.1', '198.51.100.21', '9092', 'inter_az', '9%'], 'success'),
      ],
    ),
    secondary: table(
      'Ingest quality',
      'What each sample exporter sent, and what arrived.',
      ['Exporter', 'Dialect', 'Records', 'Decode errors', 'Template misses'],
      [
        row('exp-1', ['edge-r1', 'netflow5', '155', '0', 'n/a'], 'success'),
        row('exp-2', ['edge-r2', 'ipfix', '60', '0', '0'], 'success'),
        row('exp-3', ['tor-sw3', 'sflow5', '84', '0', 'n/a'], 'success'),
      ],
    ),
  },
  '/planes/device': {
    path: '/planes/device',
    kicker: 'Device telemetry',
    title: 'Device plane',
    description:
      'Sample interface counters, neighbours, and configuration changes from the polled fleet.',
    metrics: [
      metric('Devices', '14', 'Routers, switches, firewalls', 'info'),
      metric('Interfaces', '186', 'Sample polled interfaces', 'accent'),
      metric('Poll lag', '4 min', 'One poller behind the others', 'warning'),
      metric('Config changes', '2', 'Within the sample window', 'warning'),
    ],
    primary: table(
      'Interfaces worth looking at',
      'Illustrative counters from the sample fleet.',
      ['Device', 'Interface', 'Utilisation', 'Errors', 'State'],
      [
        row('dev-1', ['edge-r1', 'ethernet-1/1', '78%', '0', 'Up'], 'warning'),
        row('dev-2', ['edge-r1', 'ethernet-1/2', '31%', '0', 'Up'], 'success'),
        row('dev-3', ['tor-sw3', 'ethernet-1/9', '12%', '14', 'Up'], 'warning'),
        row('dev-4', ['core-r2', 'ethernet-2/1', '44%', '0', 'Up'], 'success'),
      ],
    ),
    secondary: table(
      'Changes and neighbours',
      'Sample configuration changes and discovered adjacencies.',
      ['Time', 'Device', 'Change', 'Neighbour'],
      [
        row('devc-1', ['09:31 UTC', 'edge-r1', 'BGP policy updated', 'core-r2'], 'warning'),
        row('devc-2', ['09:33 UTC', 'tor-sw3', 'MTU changed on ethernet-1/9', 'edge-r1'], 'warning'),
        row('devc-3', ['09:35 UTC', 'core-r2', 'No change', 'edge-r1, tor-sw3'], 'success'),
      ],
    ),
  },
  '/planes/ebpf': {
    path: '/planes/ebpf',
    kicker: 'Host and service map',
    title: 'eBPF plane',
    description:
      'Sample host-level connections and a service map built without touching the application.',
    metrics: [
      metric('Hosts', '7', 'Reporting in the sample window', 'info'),
      metric('Service edges', '38', 'Observed, not configured', 'accent'),
      metric('L7 capture', 'Off', 'Consent and scope not granted', 'neutral'),
      metric('Dropped records', '0', 'Ring buffers kept up', 'success'),
    ],
    primary: table(
      'Observed service map',
      'Illustrative process-to-process connections.',
      ['From', 'To', 'Port', 'Connections', 'State'],
      [
        row('ebpf-1', ['checkout', 'payments', '8443', '1,204', 'Healthy'], 'success'),
        row('ebpf-2', ['checkout', 'session-cache', '6379', '3,880', 'Healthy'], 'success'),
        row('ebpf-3', ['payments', 'ledger-db', '5432', '642', 'Slow'], 'warning'),
        row('ebpf-4', ['auth', 'auth-dns', '53', '918', 'Degraded'], 'warning'),
      ],
    ),
    secondary: table(
      'Per-host coverage',
      'What each sample host contributed, and what it could not see.',
      ['Host', 'Flows', 'Edges', 'Encrypted L7'],
      [
        row('ebpf-h1', ['node-a', '1,042', '14', 'Not captured — no consent'], 'neutral'),
        row('ebpf-h2', ['node-b', '988', '12', 'Not captured — no consent'], 'neutral'),
        row('ebpf-h3', ['node-c', '1,131', '12', 'Not captured — no consent'], 'neutral'),
      ],
    ),
  },
  '/topology': {
    path: '/topology',
    kicker: 'Change-aware graph',
    title: 'Topology & what-if',
    description:
      'Sample service, network, and host dependencies with an observe-only blast-radius preview.',
    metrics: [
      metric('Entities', '46', 'Services, devices, hosts, and ASNs', 'info'),
      metric('Dependencies', '113', 'Tenant-scoped sample edges', 'accent'),
      metric('Recent changes', '4', 'Within the sample window', 'warning'),
      metric('At-risk services', '3', 'If edge-r1 becomes unavailable', 'danger'),
    ],
    primary: table(
      'Service dependencies',
      'Illustrative dependency edges ordered by current risk.',
      ['Source', 'Dependency', 'Traffic', 'Health'],
      [
        row('checkout-db', ['checkout', 'orders-db', '82 Mbps', 'Healthy'], 'success'),
        row('checkout-edge', ['checkout', 'edge-r1', '41 Mbps', 'Degraded'], 'warning'),
        row('payments-auth', ['payments', 'identity', '18 Mbps', 'Healthy'], 'success'),
        row('portal-cdn', ['portal', 'cdn-edge', '64 Mbps', 'Healthy'], 'success'),
      ],
    ),
    secondary: table(
      'Observe-only simulation',
      'No network action is performed; this is sample impact reasoning only.',
      ['Selected entity', 'Potential impact', 'Evidence', 'Assessment'],
      [
        row(
          'edge-r1',
          ['edge-r1', '3 services / 2 regions', 'Flow + path + BGP', 'Elevated'],
          'warning',
        ),
        row('orders-db', ['orders-db', 'Checkout writes', 'eBPF + flow', 'Contained'], 'info'),
        row('cdn-edge', ['cdn-edge', 'Portal static assets', 'Synthetic + flow', 'Low'], 'success'),
      ],
    ),
  },
  '/incidents': {
    path: '/incidents',
    kicker: 'Correlated operations',
    title: 'Incidents',
    description:
      'Sample incidents combine related evidence instead of opening one ticket per signal.',
    metrics: [
      metric('Open incidents', '2', 'One requires investigation', 'warning'),
      metric('Critical', '0', 'No sample Sev-1 incidents', 'success'),
      metric('Mean time to acknowledge', '4 min', 'Sample 7-day trend', 'info'),
      metric('Planes correlated', '4', 'In the checkout incident', 'accent'),
    ],
    viz: {
      kind: 'incident-clock',
      title: 'Cross-plane incident clock',
      description:
        'One absolute timeline: the sample routing change, the traffic shift, and the latency regression in causal order.',
    },
    primary: table(
      'Open incidents',
      'Illustrative tenant-scoped incident queue.',
      ['Incident', 'Started', 'Evidence', 'State'],
      [
        row(
          'inc-checkout',
          ['Checkout latency regression', '09:37 UTC', 'BGP + flow + synthetic', 'Investigating'],
          'warning',
        ),
        row(
          'inc-dns',
          ['EU resolver degradation', '09:12 UTC', 'DNS + device', 'Monitoring'],
          'info',
        ),
        row(
          'inc-closed',
          ['Payments handshake errors', 'Yesterday', 'TLS + eBPF', 'Resolved'],
          'success',
        ),
      ],
    ),
    secondary: table(
      'Checkout incident timeline',
      'Sample evidence shares one clock and remains non-actionable.',
      ['Time', 'Event', 'Source', 'Confidence'],
      [
        row('timeline-1', ['09:37', 'AS path changed', 'BGP', 'High'], 'success'),
        row('timeline-2', ['09:38', 'Transit traffic shifted', 'Flow', 'High'], 'success'),
        row('timeline-3', ['09:39', 'Latency SLO began burning', 'Synthetic', 'High'], 'success'),
      ],
    ),
  },
  '/outages': {
    path: '/outages',
    kicker: 'External context',
    title: 'Internet outages',
    description:
      'Cached public outage signals are compared with sample tenant evidence and degrade gracefully.',
    metrics: [
      metric('External signals', '3', 'Cached read-only sources', 'info'),
      metric('Tenant impact', '1', 'EU resolver traffic', 'warning'),
      metric('Corroborated', '2', 'Supported by two or more sources', 'success'),
      metric('Top confidence', '88%', 'Sample assessment only', 'accent'),
    ],
    primary: table(
      'Outage signals',
      'Illustrative events from cached open-data feeds.',
      ['Region / ASN', 'Signal', 'Tenant overlap', 'Assessment'],
      [
        row(
          'out-eu',
          ['EU West · AS64530', 'Reachability drop', 'Resolver traffic', 'Likely impact'],
          'warning',
        ),
        row(
          'out-us',
          ['US Central · AS64540', 'Route instability', 'No overlap', 'External only'],
          'info',
        ),
        row(
          'out-ap',
          ['AP Southeast', 'Latency increase', 'No sample assets', 'Watching'],
          'neutral',
        ),
      ],
    ),
    secondary: table(
      'Source health',
      'External sources remain read-only and never block core operation.',
      ['Source', 'Freshness', 'Coverage', 'State'],
      [
        row('ioda', ['IODA', '5 min', 'Global reachability', 'Available'], 'success'),
        row('ris', ['RIPE RIS', '2 min', 'BGP routes', 'Available'], 'success'),
        row('radar', ['Cloudflare Radar', '18 min', 'Traffic anomalies', 'Cached'], 'warning'),
      ],
    ),
  },
  '/alerts': {
    path: '/alerts',
    kicker: 'Human-gated response',
    title: 'Alerts',
    description:
      'Sample firing conditions remain signals: operators acknowledge, silence, or investigate them.',
    metrics: [
      metric('Firing', '4', 'Across three sample rules', 'danger'),
      metric('Acknowledged', '2', 'Owned by Network SRE', 'info'),
      metric('Silenced', '1', 'Maintenance window', 'neutral'),
      metric('Enabled rules', '37', 'Tenant-scoped definitions', 'success'),
    ],
    primary: table(
      'Active alerts',
      'Illustrative alerts ordered by severity and start time.',
      ['Alert', 'Severity', 'Since', 'State'],
      [
        row('alert-loss', ['Transit packet loss', 'High', '8 min', 'Firing'], 'danger'),
        row('alert-dns', ['DNS p95 above 100 ms', 'Medium', '33 min', 'Acknowledged'], 'warning'),
        row('alert-cert', ['Certificate expires in 21 days', 'Low', '2 h', 'Open'], 'info'),
      ],
    ),
    secondary: table(
      'Rule evaluation',
      'Sample rule windows and the evidence that satisfied them.',
      ['Rule', 'Window', 'Evidence', 'Result'],
      [
        row('rule-loss', ['path.loss.high', '5 min', '3 of 4 samples', 'Triggered'], 'danger'),
        row('rule-slo', ['slo.checkout.burn', '30 min', '3.2× burn', 'Triggered'], 'warning'),
        row('rule-agent', ['agent.stale', '15 min', 'All reporting', 'Clear'], 'success'),
      ],
    ),
  },
  '/endpoints': {
    path: '/endpoints',
    kicker: 'Digital experience',
    title: 'Endpoints',
    description:
      'Sample endpoint experience separates Wi-Fi, gateway, ISP, and application symptoms.',
    metrics: [
      metric('Reporting endpoints', '86', 'Across seven sample sites', 'success'),
      metric('Degraded', '5', 'Mostly EU West Wi-Fi', 'warning'),
      metric('Gateway p95', '18 ms', 'Fleet-wide sample', 'info'),
      metric('Remote regions', '7', 'Home and branch cohorts', 'accent'),
    ],
    primary: table(
      'Experience exceptions',
      'Illustrative endpoint cohorts with the weakest current experience.',
      ['Cohort', 'Endpoints', 'Symptom', 'Assessment'],
      [
        row('berlin', ['Berlin branch', '4', 'Wi-Fi retransmits 11%', 'Local network'], 'warning'),
        row('remote-eu', ['Remote · EU West', '1', 'ISP latency 142 ms', 'Last mile'], 'danger'),
        row('boston', ['Boston office', '18', 'No anomaly', 'Healthy'], 'success'),
      ],
    ),
    secondary: table(
      'Endpoint journey',
      'Sample latency is decomposed so the operator knows where to investigate.',
      ['Stage', 'p50', 'p95', 'State'],
      [
        row('wifi', ['Wi-Fi', '8 ms', '64 ms', 'Degraded'], 'warning'),
        row('gateway', ['Gateway', '5 ms', '18 ms', 'Healthy'], 'success'),
        row('internet', ['Internet', '22 ms', '71 ms', 'Healthy'], 'success'),
        row('application', ['Application', '31 ms', '91 ms', 'Elevated'], 'warning'),
      ],
    ),
  },
  '/ask': {
    path: '/ask',
    kicker: 'Cited analysis',
    title: 'Ask (AI)',
    description:
      'A sample answer explains checkout latency using tenant-first, authorization-scoped evidence.',
    metrics: [
      metric('Citations', '8', 'Every claim links to evidence', 'success'),
      metric('Planes used', '4', 'BGP, flow, path, synthetic', 'accent'),
      metric('Answer confidence', 'High', 'Multiple signals agree', 'success'),
      metric('Tenant scope', '1', 'Default Tenant only', 'info'),
    ],
    primary: table(
      'Sample answer: why is checkout slow?',
      'The answer is illustrative; no model or live telemetry is queried in demo mode.',
      ['Finding', 'Evidence', 'Observed', 'Confidence'],
      [
        row(
          'answer-route',
          ['Transit route changed', 'BGP event #204', '09:37 UTC', 'High'],
          'success',
        ),
        row(
          'answer-flow',
          ['41% of traffic shifted', 'Flow edge #881', '09:38 UTC', 'High'],
          'success',
        ),
        row(
          'answer-latency',
          ['p95 increased by 49 ms', 'Synthetic round #771', '09:39 UTC', 'High'],
          'success',
        ),
      ],
    ),
    secondary: table(
      'Suggested follow-ups',
      'Safe sample prompts for continuing the investigation.',
      ['Question', 'Scope', 'Expected evidence', 'Availability'],
      [
        row(
          'prompt-compare',
          ['Compare the previous path', 'Checkout only', 'Immutable path rounds', 'Ready'],
          'success',
        ),
        row(
          'prompt-impact',
          [
            'Which services share edge-r1?',
            'Topology selection',
            'Flow + dependency graph',
            'Ready',
          ],
          'success',
        ),
        row(
          'prompt-slo',
          ['Show SLO burn by region', '15-minute window', 'Synthetic + SLO', 'Ready'],
          'success',
        ),
      ],
    ),
  },
  '/explore': {
    path: '/explore',
    kicker: 'Semantic query',
    title: 'Explorer',
    description:
      'Sample saved questions expose exact tenant-scoped queries and reproducible result sets.',
    metrics: [
      metric('Saved questions', '6', 'Operator-curated examples', 'info'),
      metric('Active window', '15 min', 'Fixed sample clock', 'accent'),
      metric('Result rows', '28', 'Across current query', 'success'),
      metric('Last run', '09:45 UTC', 'Illustrative timestamp', 'neutral'),
    ],
    primary: table(
      'Saved questions',
      'Illustrative query templates for common cross-plane investigations.',
      ['Question', 'Planes', 'Window', 'Result'],
      [
        row(
          'query-talkers',
          ['Top service talkers', 'Flow + eBPF', '15 min', '12 rows'],
          'success',
        ),
        row(
          'query-route',
          ['Routes changed before latency', 'BGP + synthetic', '1 h', '4 rows'],
          'success',
        ),
        row(
          'query-certs',
          ['Expiring certificates on active paths', 'TLS + topology', '30 d', '3 rows'],
          'warning',
        ),
      ],
    ),
    secondary: table(
      'Top service talkers',
      'Sample results from the selected canonical query.',
      ['Source', 'Destination', 'Rate', 'Change'],
      [
        row('talker-1', ['checkout', 'orders-db', '82 Mbps', '+12%'], 'warning'),
        row('talker-2', ['portal', 'cdn-edge', '64 Mbps', '−3%'], 'success'),
        row('talker-3', ['payments', 'identity', '18 Mbps', '+1%'], 'success'),
      ],
    ),
  },
  '/dashboards': {
    path: '/dashboards',
    kicker: 'Operator overview',
    title: 'Dashboards',
    description:
      'A populated sample operations dashboard summarizes health, risk, cost, and current work.',
    metrics: [
      metric('Service availability', '99.94%', '−0.01% from sample target', 'warning'),
      metric('Healthy tests', '23 / 24', 'One degraded DNS check', 'success'),
      metric('Open incidents', '2', 'No critical incidents', 'warning'),
      metric('SLOs at risk', '1 / 12', 'Checkout is burning 3.2×', 'danger'),
    ],
    viz: {
      kind: 'time-series',
      title: 'Latency during the sample window',
      description:
        'Checkout p95 steps at 09:37 while payments stays flat — the incident is visible before any alert fires.',
    },
    primary: table(
      'Service health',
      'Illustrative operator rollup across the sample service graph.',
      ['Service', 'Availability', 'p95 latency', 'Health'],
      [
        row('checkout', ['checkout', '99.88%', '91 ms', 'Degraded'], 'warning'),
        row('payments', ['payments', '99.99%', '44 ms', 'Healthy'], 'success'),
        row('portal', ['portal', '99.97%', '1.2 s', 'Healthy'], 'success'),
        row('identity', ['identity', '100.00%', '31 ms', 'Healthy'], 'success'),
      ],
    ),
    secondary: table(
      'Current operator queue',
      'Sample work ordered by urgency; no actions are available in demo mode.',
      ['Item', 'Owner', 'Age', 'State'],
      [
        row(
          'queue-incident',
          ['Checkout latency incident', 'Network SRE', '8 min', 'Investigating'],
          'warning',
        ),
        row('queue-dns', ['EU DNS degradation', 'Platform', '33 min', 'Acknowledged'], 'info'),
        row('queue-cert', ['API certificate renewal', 'Security', '2 h', 'Planned'], 'neutral'),
      ],
    ),
  },
  '/security': {
    path: '/security',
    kicker: 'Posture and signals',
    title: 'Security',
    description:
      'Sample TLS posture and confidence-scored detections remain observable signals, never inline blocking.',
    metrics: [
      metric('Open findings', '7', 'One high-confidence signal', 'warning'),
      metric('High confidence', '1', 'Known scanner contact', 'danger'),
      metric('Certificates expiring', '3', 'Within 30 sample days', 'warning'),
      metric('Suppressed', '2', 'Documented sample exceptions', 'neutral'),
    ],
    primary: table(
      'Threat signals',
      'Illustrative detections enriched by cached read-only intelligence.',
      ['Signal', 'Asset', 'Confidence', 'State'],
      [
        row('scanner', ['Known scanner contact', 'edge-r1', '92%', 'Open'], 'danger'),
        row(
          'beacon',
          ['Periodic outbound pattern', 'worker-07', '71%', 'Investigating'],
          'warning',
        ),
        row('tls', ['Legacy TLS negotiation', 'portal', '64%', 'Accepted risk'], 'neutral'),
      ],
    ),
    secondary: table(
      'Certificate posture',
      'Sample certificate inventory; private keys are never represented.',
      ['Endpoint', 'Issuer', 'Expires', 'Posture'],
      [
        row('cert-api', ['api.example', 'Example Internal CA', '21 days', 'Renew soon'], 'warning'),
        row(
          'cert-checkout',
          ['checkout.example', 'Example Internal CA', '114 days', 'Healthy'],
          'success',
        ),
        row(
          'cert-portal',
          ['portal.example', 'Example Public CA', '67 days', 'Healthy'],
          'success',
        ),
      ],
    ),
  },
  '/compliance': {
    path: '/compliance',
    kicker: 'Evidence-backed controls',
    title: 'Compliance',
    description:
      'Sample controls link posture findings to bounded evidence and authorization-safe next steps.',
    metrics: [
      metric('Controls assessed', '42', 'Across three sample frameworks', 'info'),
      metric('Passing', '38', '90% sample coverage', 'success'),
      metric('Gaps', '4', 'Two require evidence updates', 'warning'),
      metric('Stale evidence', '1', 'Older than 30 sample days', 'danger'),
    ],
    primary: table(
      'Control status',
      'Illustrative control mappings and current evidence.',
      ['Control', 'Requirement', 'Evidence', 'Status'],
      [
        row(
          'ctl-tls',
          ['NET-01', 'TLS on every listener', 'Listener inventory', 'Passing'],
          'success',
        ),
        row(
          'ctl-tenant',
          ['TEN-04', 'Tenant-scoped storage', 'RLS verification', 'Passing'],
          'success',
        ),
        row(
          'ctl-retention',
          ['DAT-07', 'Retention review', 'Policy snapshot', 'Needs review'],
          'warning',
        ),
      ],
    ),
    secondary: table(
      'Framework coverage',
      'Sample crosswalk; probectl supplies evidence rather than certification.',
      ['Framework', 'Mapped controls', 'Passing', 'Coverage'],
      [
        row('nist', ['NIST CSF', '18', '17', '94%'], 'success'),
        row('iso', ['ISO 27001', '14', '12', '86%'], 'warning'),
        row('soc2', ['SOC 2', '10', '9', '90%'], 'success'),
      ],
    ),
  },
  '/audit': {
    path: '/audit',
    kicker: 'Tamper-evident history',
    title: 'Audit',
    description: 'Sample configuration and data-access events remain tenant-scoped and immutable.',
    metrics: [
      metric('Events', '128', 'Within the fixed sample day', 'info'),
      metric('Config changes', '7', 'All attributed to actors', 'accent'),
      metric('Denied actions', '3', 'Fail-closed authorization', 'warning'),
      metric('Break-glass events', '0', 'Separate provider stream', 'success'),
    ],
    primary: table(
      'Recent audit events',
      'Illustrative tenant audit records with actor and result.',
      ['Time', 'Actor', 'Action', 'Result'],
      [
        row(
          'audit-1',
          ['09:43 UTC', 'operator@example', 'alert.acknowledge', 'Allowed'],
          'success',
        ),
        row('audit-2', ['09:31 UTC', 'viewer@example', 'dashboard.create', 'Denied'], 'warning'),
        row('audit-3', ['09:18 UTC', 'admin@example', 'agent.token.create', 'Allowed'], 'success'),
      ],
    ),
    secondary: table(
      'Integrity checkpoints',
      'Sample verification status for the append-only chain.',
      ['Checkpoint', 'Events', 'Verified at', 'Integrity'],
      [
        row('checkpoint-945', ['09:45', '42', '09:45 UTC', 'Verified'], 'success'),
        row('checkpoint-930', ['09:30', '39', '09:30 UTC', 'Verified'], 'success'),
        row('checkpoint-915', ['09:15', '47', '09:15 UTC', 'Verified'], 'success'),
      ],
    ),
  },
  '/cost': {
    path: '/cost',
    kicker: 'Network economics',
    title: 'Cost',
    description:
      'Sample flow attribution turns network usage into tenant-local showback and budget signals.',
    metrics: [
      metric('Projected spend', '$42.6k', 'Current sample month', 'info'),
      metric('Budget used', '71%', 'On track for month end', 'success'),
      metric('Cross-zone egress', '$8.4k', '20% of projected spend', 'warning'),
      metric('Savings identified', '$3.1k', 'Observe-only opportunities', 'accent'),
    ],
    primary: table(
      'Cost by service',
      'Illustrative attribution from flow and cloud pricing context.',
      ['Service', 'Projected', 'Budget', 'State'],
      [
        row('cost-checkout', ['checkout', '$14.2k', '76%', 'Watch'], 'warning'),
        row('cost-portal', ['portal', '$10.8k', '68%', 'On track'], 'success'),
        row('cost-payments', ['payments', '$9.6k', '64%', 'On track'], 'success'),
        row('cost-shared', ['shared platform', '$8.0k', '79%', 'Watch'], 'warning'),
      ],
    ),
    secondary: table(
      'Optimization opportunities',
      'Sample recommendations are informational and never modify infrastructure.',
      ['Opportunity', 'Evidence', 'Estimate', 'Confidence'],
      [
        row(
          'opt-zone',
          ['Keep checkout traffic in-zone', '41 Mbps cross-zone', '$1.8k/mo', 'High'],
          'success',
        ),
        row(
          'opt-chatty',
          ['Reduce portal cache misses', '64 Mbps repeated fetches', '$900/mo', 'Medium'],
          'info',
        ),
        row(
          'opt-idle',
          ['Review idle exporters', '2 low-volume sources', '$400/mo', 'Medium'],
          'info',
        ),
      ],
    ),
  },
  '/slos': {
    path: '/slos',
    kicker: 'Reliability objectives',
    title: 'SLOs',
    description:
      'Sample error budgets connect synthetic outcomes to objectives and burn-rate alerts.',
    metrics: [
      metric('Objectives', '12', 'Across four sample services', 'info'),
      metric('At risk', '1', 'Checkout availability', 'danger'),
      metric('Fast burn', '3.2×', 'Last 30 sample minutes', 'warning'),
      metric('Budget remaining', '72%', 'Fleet-wide weighted average', 'success'),
    ],
    primary: table(
      'Service objectives',
      'Illustrative attainment and error-budget posture.',
      ['Objective', 'Target', 'Attainment', 'State'],
      [
        row('slo-checkout', ['Checkout availability', '99.95%', '99.88%', 'At risk'], 'danger'),
        row('slo-payments', ['Payments latency', 'p95 < 80 ms', '44 ms', 'Healthy'], 'success'),
        row('slo-portal', ['Portal journey', '99.90%', '99.97%', 'Healthy'], 'success'),
      ],
    ),
    secondary: table(
      'Burn-rate windows',
      'Sample multi-window evidence avoids reacting to a single noisy point.',
      ['Window', 'Checkout burn', 'Budget consumed', 'Assessment'],
      [
        row('burn-5m', ['5 minutes', '4.8×', '2.1%', 'Fast burn'], 'danger'),
        row('burn-30m', ['30 minutes', '3.2×', '6.4%', 'Elevated'], 'warning'),
        row('burn-6h', ['6 hours', '0.8×', '11.0%', 'Within budget'], 'success'),
      ],
    ),
  },
  '/admin': {
    path: '/admin',
    kicker: 'Tenant operations',
    title: 'Admin & settings',
    description:
      'A read-only sample inventory of tenant configuration, integrations, and platform health.',
    metrics: [
      metric('Registered agents', '12', 'All tenant-bound identities', 'success'),
      metric('Integrations', '5', 'Three signal producers', 'info'),
      metric('Retention', '30 days', 'Sample tenant policy', 'neutral'),
      metric('Edition', 'Core', 'Commercial features hidden', 'accent'),
    ],
    primary: table(
      'Platform components',
      'Illustrative component inventory; demo mode exposes no configuration actions.',
      ['Component', 'Version', 'Coverage', 'State'],
      [
        row('admin-control', ['Control plane', '0.4.0', 'Default Tenant', 'Healthy'], 'success'),
        row('admin-agent', ['Canary agents', '0.4.0', '3 regions', 'Healthy'], 'success'),
        row('admin-ebpf', ['eBPF agents', '0.4.0', '7 hosts', 'Healthy'], 'success'),
        row('admin-device', ['Device collector', '0.4.0', '14 devices', 'Delayed'], 'warning'),
      ],
    ),
    secondary: table(
      'Tenant settings',
      'Sample effective values, never editable from the product tour.',
      ['Setting', 'Effective value', 'Source', 'Status'],
      [
        row(
          'setting-isolation',
          ['Isolation model', 'Pooled + forced RLS', 'Deployment', 'Enforced'],
          'success',
        ),
        row('setting-retention', ['Retention', '30 days', 'Tenant policy', 'Active'], 'success'),
        row(
          'setting-sso',
          ['Identity provider', 'Local demo Dex', 'Demo overlay', 'Demo only'],
          'warning',
        ),
      ],
    ),
  },
  '/docs/api': {
    path: '/docs/api',
    kicker: 'Versioned contract',
    title: 'API docs',
    description:
      'A sample OpenAPI catalogue shows the shape of the HTTPS-only, tenant-scoped v1 API.',
    metrics: [
      metric('Operations', '145', 'Documented v1 surface', 'info'),
      metric('Schemas', '53', 'Generated typed models', 'accent'),
      metric('API version', 'v1', 'OpenAPI 3.1 contract', 'success'),
      metric('Authentication', 'OIDC', 'Secure session cookie', 'success'),
    ],
    primary: table(
      'Featured operations',
      'Illustrative read operations; the interactive client is disabled in demo mode.',
      ['Method', 'Path', 'Purpose', 'Scope'],
      [
        row(
          'api-incidents',
          ['GET', '/v1/incidents', 'List correlated incidents', 'tenant + RBAC'],
          'success',
        ),
        row(
          'api-topology',
          ['GET', '/v1/topology', 'Read service graph', 'tenant + RBAC'],
          'success',
        ),
        row(
          'api-slos',
          ['GET', '/v1/slos', 'List reliability objectives', 'tenant + RBAC'],
          'success',
        ),
        row(
          'api-audit',
          ['GET', '/v1/audit', 'Read authorized audit records', 'tenant + audit.read'],
          'info',
        ),
      ],
    ),
    secondary: table(
      'Contract guarantees',
      'Sample summary of the API boundary demonstrated by this tour.',
      ['Guarantee', 'Mechanism', 'Failure behavior', 'Status'],
      [
        row(
          'api-tenancy',
          ['Tenant isolation', 'Storage/query scope', 'Return nothing', 'Required'],
          'success',
        ),
        row(
          'api-transport',
          ['TLS 1.2+', 'HTTPS listener', 'Refuse connection', 'Required'],
          'success',
        ),
        row('api-auth', ['Authentication', 'OIDC session', '401 / 403', 'Required'], 'success'),
      ],
    ),
  },
}

export const DEMO_PAGE_PATHS = Object.keys(DEMO_PAGES)

export function demoPageForPath(pathname: string): DemoPageModel {
  // DPR-145: a per-plane route gets its own sample surface. Falling back to the
  // plane index made four navigation destinations render one page, which on a
  // hosted tour reads as four broken links. An unknown plane still falls back,
  // so a future plane is a missing page rather than a crash.
  return DEMO_PAGES[pathname] ?? DEMO_PAGES['/dashboards']
}
