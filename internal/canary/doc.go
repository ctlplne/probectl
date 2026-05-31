// Package canary defines the Canary plugin interface — the load-bearing
// extension point for every netctl measurement type — together with the
// Result/Spec/Config shapes and a Registry of compiled-in plugin factories
// (S5). A no-op plugin is included to exercise the agent runtime.
//
// The real probes (icmp/tcp/udp/http/dns, ...) are added from S7 by registering
// their factories. A probe failure is a Result with Success=false, never a
// returned error or a panic (CLAUDE.md §6).
package canary
