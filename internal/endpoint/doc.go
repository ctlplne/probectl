// Package endpoint is probectl's endpoint / Digital-Experience-Monitoring (DEM)
// agent core (S37, F16/F46): it captures last-mile experience from a user's
// device — WiFi link health, the local gateway, the ISP/last-mile path, and
// browser-session timings — and ATTRIBUTES a slowdown to the closest impaired
// layer (local WiFi, the LAN/gateway, the ISP, or the wider network) so an
// operator can answer the hybrid-work question "is it us, or the user's
// WiFi/ISP?".
//
// Design (mirrors the eBPF agent, S20). The schema, privacy minimization, the
// attribution engine, the result mapping, and the bus emitter are pure Go and
// fully tested here; only the thin metric COLLECTORS that shell out to OS tools
// (airport/nmcli/netsh for WiFi, traceroute/tracert for the path) are
// build-tagged per OS, and their OUTPUT PARSERS are portable and fixture-tested
// on every platform. A device with no Wi-Fi or a metric the OS does not expose
// degrades gracefully (CLAUDE.md §7 guardrail 10) rather than reporting a false
// zero.
//
// Privacy (the agent runs on an end-user's machine). Only measurements
// (signal/RTT/loss/timings — not PII) are collected by default; identifying
// fields (the BSSID/AP-MAC, public last-mile hop IPs) are gated OFF, and the
// agent DISCLOSES exactly what it collects at startup. Nothing phones home
// (CLAUDE.md §7 guardrail 2); results flow only to the operator's own bus,
// tenant-tagged, exactly like every other agent's results.
package endpoint
