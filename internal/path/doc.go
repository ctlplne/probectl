// Package path is probectl's ECMP/MPLS-aware path-discovery engine (S10).
//
// It runs Paris-style traceroutes — each trace uses a constant flow identifier
// (a forced ICMP checksum, or a fixed TCP 5-tuple) so load-balancing routers
// keep that trace's path stable across TTLs, while different flow identifiers
// explore different ECMP branches. It detects MPLS label stacks (RFC 4884/4950)
// on Time Exceeded responses, and merges the per-flow traces into one multi-path
// Path — hops with per-node RTT/loss and MPLS, plus the links between them — for
// the path visualization (S11) and ClickHouse storage.
package path
