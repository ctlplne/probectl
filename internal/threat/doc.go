// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package threat is probectl's security/threat subsystem. S27 implements TLS/cert
// observability: it analyzes TLS posture from ALREADY-CAPTURED data — the HTTP
// synthetic canary (S13) and eBPF L7 (S21) — so it never re-handshakes (S27
// watch-out).
//
// It parses the certificate chain (expiry, issuer, subject/SAN, key type/size),
// reads the captured TLS version + cipher, optionally correlates against
// Certificate Transparency logs for issuance anomalies, flags deprecated
// protocols / weak ciphers / expired-or-expiring / self-signed / weak-key /
// untrusted-chain, builds a trustctl renewal handoff, and emits threat-plane
// incident signals (feeding the unified timeline + alerting, S16/S17).
//
// Threat detections here are SIGNALS, not an IPS (docs/guardrails.md G7-9):
// confidence-scored, surfaced, and exportable — probectl does not block traffic.
// Malicious-cert / JA3 threat-intel correlation is deferred (S28/S42).
package threat
