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
// Threat detections here are SIGNALS, not an IPS (CLAUDE.md §7 guardrail 9):
// confidence-scored, surfaced, and exportable — probectl does not block traffic.
// Malicious-cert / JA3 threat-intel correlation is deferred (S28/S42).
package threat
