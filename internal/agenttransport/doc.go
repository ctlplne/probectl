// Package agenttransport is the control-plane side of the agent <-> control-plane
// gRPC transport (S4). Every connection is mTLS (S3 crypto.ServerMTLSConfig);
// non-mTLS clients are rejected at the TLS layer. The caller's tenant and agent
// id are derived from the verified client certificate's SPIFFE identity
// (spiffe://probectl/tenant/<t>/agent/<a>), never trusted from the request body, so
// an agent is bound to exactly one tenant and everything it does is
// tenant-attributable at the source (F50).
//
// It implements Register, Attest, Heartbeat, and StreamResults (agent->server).
// StreamConfig is an EXPLICIT DENY kept for wire compatibility (U-044/ARCH-003):
// config push is deliberately not a shipped capability — agents load config
// from local YAML/env only, and there is no remote control channel (see
// docs/adr/config-push.md). Registration persists to the agents registry via
// internal/store.
package agenttransport
